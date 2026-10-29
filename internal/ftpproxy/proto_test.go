package ftpproxy

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseFormatPORT(t *testing.T) {
	ip, port, err := parsePORT("192,168,1,10,196,13")
	if err != nil {
		t.Fatalf("parsePORT: %v", err)
	}
	if ip != "192.168.1.10" || port != 50189 {
		t.Fatalf("got %s:%d", ip, port)
	}
	if got := formatPORT(ip, port); got != "192,168,1,10,196,13" {
		t.Fatalf("formatPORT = %q", got)
	}
	if _, _, err := parsePORT("1,2,3"); err == nil {
		t.Fatal("expected error for short PORT")
	}
	if _, _, err := parsePORT("1,2,3,4,0,0"); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestParseFormatEPRT(t *testing.T) {
	ip, port, err := parseEPRT("|1|10.0.0.5|52422|")
	if err != nil {
		t.Fatalf("parseEPRT: %v", err)
	}
	if ip != "10.0.0.5" || port != 52422 {
		t.Fatalf("got %s:%d", ip, port)
	}
	if _, _, err := parseEPRT("|2|::1|52422|"); err == nil {
		t.Fatal("IPv6 EPRT must be rejected")
	}
	if eprtIsIPv4("|2|::1|1|") {
		t.Fatal("eprtIsIPv4 must be false")
	}
	if !eprtIsIPv4("|1|1.2.3.4|1|") {
		t.Fatal("eprtIsIPv4 must be true")
	}
}

func TestParse227And229(t *testing.T) {
	lines := []string{"227 Entering Passive Mode (192,0,2,1,196,13)."}
	ip, port, ok := parse227Addr(lines)
	if !ok || ip != "192.0.2.1" || port != 50189 {
		t.Fatalf("parse227Addr = %s:%d ok=%v", ip, port, ok)
	}
	rew := rewrite227(lines, "10.1.1.1", 20000)
	ip, port, ok = parse227Addr(rew)
	if !ok || ip != "10.1.1.1" || port != 20000 {
		t.Fatalf("rewrite227 failed: %v -> %s:%d", rew, ip, port)
	}

	lines229 := []string{"229 Entering Extended Passive Mode (|||50189|)"}
	p, ok := parse229Port(lines229)
	if !ok || p != 50189 {
		t.Fatalf("parse229Port = %d ok=%v", p, ok)
	}
	rew229 := rewrite229(lines229, 31000)
	p, ok = parse229Port(rew229)
	if !ok || p != 31000 {
		t.Fatalf("rewrite229 failed: %v -> %d", rew229, p)
	}
	if rew229[0] != "229 Entering Extended Passive Mode (|||31000|)" {
		t.Fatalf("rewrite229 corrupted line: %q", rew229[0])
	}
}

func TestReadResponseFraming(t *testing.T) {
	// vsftpd-style FEAT: continuation lines are arbitrary text (" EPRT"),
	// the response ends only on a line repeating the code + space.
	in := "211-Extensions supported:\r\n EPRT\r\n IDLE\r\n MDTM\r\n SIZE\r\n211 End\r\n200 ok\r\n"
	br := bufio.NewReader(strings.NewReader(in))
	code, lines, err := readResponse(br)
	if err != nil {
		t.Fatalf("FEAT response: %v", err)
	}
	if code != "211" || len(lines) != 6 || lines[5] != "211 End" {
		t.Fatalf("bad framing: code=%s lines=%v", code, lines)
	}
	// Stream stays in sync: next response parses cleanly.
	code, lines, err = readResponse(br)
	if err != nil || code != "200" || len(lines) != 1 {
		t.Fatalf("next response: code=%s lines=%v err=%v", code, lines, err)
	}

	// Terminator line exactly equal to the code (no trailing space).
	br = bufio.NewReader(strings.NewReader("220-\r\n220\r\n"))
	code, lines, err = readResponse(br)
	if err != nil || code != "220" || len(lines) != 2 {
		t.Fatalf("bare terminator: code=%s lines=%v err=%v", code, lines, err)
	}

	// Single-line responses.
	br = bufio.NewReader(strings.NewReader("230 Login ok\r\n"))
	code, lines, err = readResponse(br)
	if err != nil || code != "230" || len(lines) != 1 {
		t.Fatalf("single line: code=%s lines=%v err=%v", code, lines, err)
	}

	// A garbage first line is still an error.
	br = bufio.NewReader(strings.NewReader("garbage\r\n"))
	if _, _, err = readResponse(br); err == nil {
		t.Fatal("garbage first line must error")
	}
}
