package ftpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// session ties one client control connection to one upstream control
// connection and manages the data-channel plans for it.
type session struct {
	p      *Proxy
	client net.Conn
	server net.Conn
	br     *bufio.Reader // client commands
	bs     *bufio.Reader // server responses
	log    *slog.Logger
	src    netip.Addr
	id     string

	wmu sync.Mutex // serializes writes to the client conn

	mu          sync.Mutex
	authed      bool
	pendingUser string
	lastCmd     string    // last client command forwarded upstream (for error context)
	active      *dataPlan // created by PORT/EPRT
	passive     *dataPlan // created on 227/229 interception
	dataDir     string    // direction label of the last transfer command
	xferCmd     string    // last transfer-initiating command (RETR/LIST/STOR ...)

	transferCount atomic.Int32
	closed        atomic.Bool
}

var sessionSeq atomic.Uint64

func newSession(p *Proxy, client, server net.Conn, src netip.Addr) *session {
	id := strconv.FormatUint(sessionSeq.Add(1), 10)
	return &session{
		p:      p,
		client: client,
		server: server,
		br:     bufio.NewReader(client),
		bs:     bufio.NewReader(server),
		log: p.log.With(
			"session", id,
			"src", src.String(),
			"dest", p.dst.Host+":"+strconv.Itoa(p.dst.Port),
		),
		src:     src,
		id:      id,
		authed:  p.authUsers == nil,
		dataDir: "",
	}
}

// run drives the session until either side closes or the idle timeout hits.
func (s *session) run() {
	defer s.close()

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		s.serverToClient()
	}()

	quit := s.clientToServer()
	if quit {
		// QUIT forwarded: give the server a moment to answer (221) and the
		// relay goroutine a chance to deliver it before teardown.
		select {
		case <-relayDone:
		case <-time.After(3 * time.Second):
		}
	}
	s.close()
	<-relayDone

	s.log.Debug("session ended")
}

// clientToServer reads client commands, applies proxy logic and forwards.
// Returns true when the session ended due to QUIT.
func (s *session) clientToServer() bool {
	idle := s.p.cfg.ControlIdle.Duration
	for {
		if s.closed.Load() {
			return false
		}
		s.client.SetReadDeadline(time.Now().Add(idle))
		line, err := readControlLine(s.br)
		if line == "" {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() && s.transferCount.Load() > 0 {
				// Control channel stays quiet during long data transfers;
				// do not consider the session idle while bytes are moving.
				continue
			}
			if err != nil && !errors.Is(err, net.ErrClosed) {
				s.log.Debug("client read", "err", err)
			}
			return false
		}
		if quit := s.handleCommand(line); quit {
			return true
		}
		if err != nil { // partial line with error
			return false
		}
	}
}

// handleCommand processes one client command; returns true when the session
// should end (QUIT).
func (s *session) handleCommand(line string) bool {
	verb, arg, _ := strings.Cut(line, " ")
	up := strings.ToUpper(verb)
	s.p.m.CommandsTotal.WithLabelValues(s.p.Name, strings.ToLower(up)).Inc()
	s.log.Debug("client cmd", "cmd", up, "arg", s.safeArg(up, arg))

	// Proxy-side authentication gate.
	if s.p.authUsers != nil && !s.authed {
		switch up {
		case "USER":
			s.mu.Lock()
			s.pendingUser = arg
			s.mu.Unlock()
			// Forward transparently; the upstream server's 331 reply is
			// relayed as usual. The password is verified by the proxy.
			s.forward(line)
			return false
		case "PASS":
			s.handlePass(arg)
			return false
		case "NOOP", "HELP", "FEAT":
			s.forward(line)
			return false
		case "QUIT":
			s.forward(line)
			return true
		default:
			s.writeClientLine("530 Not logged in at proxy.")
			s.log.Info("command before authentication denied", "cmd", up)
			return false
		}
	}

	switch up {
	case "USER", "PASS":
		// Transparent pass-through (no proxy auth configured, or authenticated).
	case "QUIT":
		s.forward(line)
		return true
	case "PORT":
		s.handlePort(arg)
		return false
	case "EPRT":
		s.handleEPRT(arg)
		return false
	case "PASV", "EPSV":
		if strings.EqualFold(strings.TrimSpace(arg), "ALL") {
			s.writeClientLine("502 EPSV ALL is not supported by this proxy.")
			s.log.Info("EPSV ALL rejected")
			return false
		}
		s.forward(line)
		return false
	case "RETR", "LIST", "NLST", "MLSD":
		s.setDir("download", line)
	case "STOR", "APPE", "STOU":
		s.setDir("upload", line)
	}
	s.forward(line)
	return false
}

func (s *session) handlePass(pass string) {
	s.mu.Lock()
	user := s.pendingUser
	s.pendingUser = ""
	s.mu.Unlock()
	if user == "" {
		s.writeClientLine("503 Send USER first.")
		return
	}
	want, ok := s.p.authUsers[user]
	if !ok || want != pass {
		s.p.m.AuthFailuresTotal.WithLabelValues(s.p.Name).Inc()
		s.p.m.ErrorsTotal.WithLabelValues(s.p.Name, "auth_denied").Inc()
		s.log.Info("proxy authentication failed", "user", user)
		s.writeClientLine("530 Proxy authentication failed.")
		return
	}
	s.mu.Lock()
	s.authed = true
	s.mu.Unlock()
	s.log.Info("proxy authentication ok", "user", user)
	// USER was already forwarded; relay the password upstream now.
	s.forward("PASS " + pass)
}

// handlePort processes a PORT command: remember the client data endpoint and
// tell the upstream server to connect to a locally allocated port instead.
func (s *session) handlePort(arg string) {
	ip, port, err := parsePORT(arg)
	if err != nil {
		s.log.Info("bad PORT", "err", err)
		s.writeClientLine("501 Invalid PORT argument.")
		return
	}
	plan, err := s.newActivePlan(ip, port)
	if err != nil {
		s.log.Info("cannot open active data listener", "err", err)
		s.writeClientLine("425 Cannot open data connection.")
		return
	}
	s.forward("PORT " + formatPORT(plan.advertise, plan.localPort))
}

// handleEPRT processes an EPRT command (IPv4 transport only).
func (s *session) handleEPRT(arg string) {
	if !eprtIsIPv4(arg) {
		s.writeClientLine("522 Network protocol not supported, use IPv4.")
		return
	}
	ip, port, err := parseEPRT(arg)
	if err != nil {
		s.log.Info("bad EPRT", "err", err)
		s.writeClientLine("501 Invalid EPRT argument.")
		return
	}
	plan, err := s.newActivePlan(ip, port)
	if err != nil {
		s.log.Info("cannot open active data listener", "err", err)
		s.writeClientLine("425 Cannot open data connection.")
		return
	}
	s.forward("EPRT " + formatEPRT(plan.advertise, plan.localPort))
}

// serverToClient relays upstream responses to the client, intercepting the
// passive data addresses in 227/229 replies.
func (s *session) serverToClient() {
	for {
		if s.closed.Load() {
			return
		}
		code, lines, err := readResponse(s.bs)
		if len(lines) > 0 {
			if s.log.Enabled(context.Background(), slog.LevelDebug) {
				s.log.Debug("server resp", "code", code, "text", strings.Join(lines, " | "))
			}
			// Negative completions (4xx transient, 5xx permanent) are
			// operational problems: surface them at info with the command
			// that caused them.
			if code != "" && (code[0] == '4' || code[0] == '5') {
				s.mu.Lock()
				cmd := s.lastCmd
				s.mu.Unlock()
				s.log.Info("server error response", "cmd", cmd, "code", code,
					"text", strings.Join(lines, " | "))
			}
			switch code {
			case "227":
				lines = s.interceptPassive(lines, false)
			case "229":
				lines = s.interceptPassive(lines, true)
			}
			s.writeClientLines(lines)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			// Framing/protocol failures kill the session: never leave this
			// visible only at debug, it looks like a silent disconnect.
			s.log.Info("upstream control read failed", "err", err)
			return
		}
	}
}

// interceptPassive allocates a local data listener and rewrites the passive
// address so client data connections land on the proxy. epsv selects 229
// (port only) versus 227 (address+port) handling.
func (s *session) interceptPassive(lines []string, epsv bool) []string {
	var upIP string
	var upPort int
	if epsv {
		p, ok := parse229Port(lines)
		if !ok {
			s.log.Info("cannot parse 229 EPSV response")
			return []string{"425 Cannot parse EPSV response."}
		}
		upIP, upPort = s.serverRemoteIP(), p
	} else {
		var ok bool
		upIP, upPort, ok = parse227Addr(lines)
		if !ok {
			s.log.Info("cannot parse 227 PASV response")
			return []string{"425 Cannot parse PASV response."}
		}
	}

	plan, err := s.newPassivePlan(upIP, upPort)
	if err != nil {
		s.log.Info("cannot open passive data listener", "err", err)
		return []string{"425 Cannot open data connection."}
	}
	if epsv {
		return rewrite229(lines, plan.localPort)
	}
	return rewrite227(lines, plan.advertise, plan.localPort)
}

// serverRemoteIP returns the IPv4 of the upstream control socket, used as the
// dial target for EPSV data channels (the server's own address family).
func (s *session) serverRemoteIP() string {
	if ta, ok := s.server.RemoteAddr().(*net.TCPAddr); ok && ta.IP.To4() != nil {
		return ta.IP.String()
	}
	return s.p.dst.Host
}

func (s *session) safeArg(verb, arg string) string {
	if !s.p.hidePasswords {
		return arg
	}
	switch verb {
	case "PASS", "ACCT":
		if arg == "" {
			return arg
		}
		return "*****"
	}
	return arg
}

func (s *session) setDir(d, cmd string) {
	s.mu.Lock()
	s.dataDir = d
	s.xferCmd = cmd
	s.mu.Unlock()
}

func (s *session) getDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataDir
}

func (s *session) getXferCmd() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.xferCmd
}

func (s *session) forward(line string) {
	verb, arg, _ := strings.Cut(line, " ")
	// lastCmd feeds info-level error records: secrets are stripped from it
	// unconditionally, regardless of log.hide_passwords.
	up := strings.ToUpper(verb)
	if (up == "PASS" || up == "ACCT") && arg != "" {
		arg = "*****"
	}
	s.mu.Lock()
	if arg == "" {
		s.lastCmd = verb
	} else {
		s.lastCmd = verb + " " + arg
	}
	s.mu.Unlock()
	if _, err := s.server.Write([]byte(line + crlf)); err != nil {
		s.log.Debug("forward to server failed", "err", err)
		s.close()
	}
}

func (s *session) writeClientLine(line string) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.client.Write([]byte(line + crlf))
}

func (s *session) writeClientLines(lines []string) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	writeResponse(s.client, lines)
}

// close tears down the session and everything hanging off it.
func (s *session) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.mu.Lock()
	if s.active != nil {
		s.active.shutdown()
		s.active = nil
	}
	if s.passive != nil {
		s.passive.shutdown()
		s.passive = nil
	}
	s.mu.Unlock()
	s.client.Close()
	s.server.Close()
}
