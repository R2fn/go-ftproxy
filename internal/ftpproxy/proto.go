package ftpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// FTP control-channel helpers: line reading, full-response framing and
// parsing/rewriting of the data-address commands (IPv4 only).

const crlf = "\r\n"

var (
	re227 = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)
	re229 = regexp.MustCompile(`\((\d*)\|(\d*)\|(\d*)\|(\d+)\|`)
)

// readControlLine reads one CRLF-terminated line, returns it without the
// trailing CR/LF.
func readControlLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), err
}

// readResponse reads one complete (possibly multi-line) server response.
// RFC 959 framing: the first line starts with the 3-digit code; if the code
// is followed by '-' the response continues until a line that repeats the
// code followed by a space (or is exactly the code). Continuation lines are
// arbitrary text - vsftpd's FEAT lists commands as " EPRT" style lines.
func readResponse(br *bufio.Reader) (code string, lines []string, err error) {
	first, rerr := readControlLine(br)
	if first == "" {
		return "", nil, rerr
	}
	if len(first) < 3 || first[0] < '0' || first[0] > '9' || first[1] < '0' || first[1] > '9' || first[2] < '0' || first[2] > '9' {
		return "", nil, fmt.Errorf("malformed server response: %q", first)
	}
	code = first[:3]
	lines = []string{first}
	if len(first) == 3 || first[3] != '-' {
		return code, lines, nil
	}
	for {
		line, lerr := readControlLine(br)
		if line == "" {
			return "", nil, lerr
		}
		lines = append(lines, line)
		if line[:3] == code && (len(line) == 3 || line[3] == ' ') {
			return code, lines, nil
		}
		if lerr != nil {
			return "", nil, lerr
		}
	}
}

// writeResponse writes response lines back with CRLF framing.
func writeResponse(w io.Writer, lines []string) error {
	for _, l := range lines {
		if _, err := w.Write([]byte(l + crlf)); err != nil {
			return err
		}
	}
	return nil
}

// parsePORT parses "h1,h2,h3,h4,p1,p2" into an IPv4 endpoint.
func parsePORT(arg string) (ip string, port int, err error) {
	parts := strings.Split(strings.TrimSpace(arg), ",")
	if len(parts) != 6 {
		return "", 0, fmt.Errorf("PORT needs 6 comma-separated values, got %d", len(parts))
	}
	nums := make([]int, 6)
	for i, p := range parts {
		n, cerr := strconv.Atoi(strings.TrimSpace(p))
		if cerr != nil || n < 0 || n > 255 {
			return "", 0, fmt.Errorf("invalid PORT octet %q", p)
		}
		nums[i] = n
	}
	port = nums[4]*256 + nums[5]
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid PORT port %d", port)
	}
	ip = fmt.Sprintf("%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3])
	return ip, port, nil
}

// formatPORT renders the argument of a PORT command.
func formatPORT(ip string, port int) string {
	p1, p2 := port/256, port%256
	return fmt.Sprintf("%s,%d,%d", strings.ReplaceAll(ip, ".", ","), p1, p2)
}

// parseEPRT parses "|1|<ipv4>|<port>|" (IPv4 transport only).
func parseEPRT(arg string) (ip string, port int, err error) {
	parts := strings.Split(strings.TrimSpace(arg), "|")
	if len(parts) != 5 {
		return "", 0, fmt.Errorf("EPRT must look like |1|addr|port|, got %q", arg)
	}
	if parts[1] != "1" {
		return "", 0, fmt.Errorf("EPRT network %q is not IPv4", parts[1])
	}
	port, err = strconv.Atoi(parts[3])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid EPRT port %q", parts[3])
	}
	return parts[2], port, nil
}

// formatEPRT renders the argument of an EPRT command.
func formatEPRT(ip string, port int) string {
	return fmt.Sprintf("|1|%s|%d|", ip, port)
}

// parseEPRTFamily returns the EPRT network without validating it.
func eprtIsIPv4(arg string) bool {
	parts := strings.Split(strings.TrimSpace(arg), "|")
	return len(parts) == 5 && parts[1] == "1"
}

// rewrite227 replaces the address in a 227 response body with ip:port.
func rewrite227(lines []string, ip string, port int) []string {
	body := strings.ReplaceAll(ip, ".", ",") + fmt.Sprintf(",%d,%d", port/256, port%256)
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = re227.ReplaceAllString(l, "("+body+")")
	}
	return out
}

// rewrite229 replaces the port in a 229 (EPSV) response with port.
func rewrite229(lines []string, port int) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		m := re229.FindStringSubmatchIndex(l)
		if m == nil {
			out[i] = l
			continue
		}
		// the port is capture group 4: indices m[8]:m[9]
		out[i] = l[:m[8]] + strconv.Itoa(port) + l[m[9]:]
	}
	return out
}

// parse227Addr extracts host and port from a 227 response line set.
func parse227Addr(lines []string) (ip string, port int, ok bool) {
	for _, l := range lines {
		m := re227.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		p1, _ := strconv.Atoi(m[5])
		p2, _ := strconv.Atoi(m[6])
		p := p1*256 + p2
		if p <= 0 || p > 65535 {
			continue
		}
		return fmt.Sprintf("%s.%s.%s.%s", m[1], m[2], m[3], m[4]), p, true
	}
	return "", 0, false
}

// parse229Port extracts the port from a 229 response line set.
func parse229Port(lines []string) (port int, ok bool) {
	for _, l := range lines {
		m := re229.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		p, err := strconv.Atoi(m[4])
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		return p, true
	}
	return 0, false
}

// hostPort joins for tcp dial strings.
func hostPort(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}
