package ftpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/r2fn/go-ftproxy/internal/config"
	"github.com/r2fn/go-ftproxy/internal/dnsx"
	"github.com/r2fn/go-ftproxy/internal/metrics"
)

// ---------- fake upstream FTP server ----------

type fakeServer struct {
	t      *testing.T
	ln     net.Listener
	mu     sync.Mutex
	stored []byte
}

func newFakeServer(t *testing.T) *fakeServer {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{t: t, ln: ln}
	go fs.acceptLoop()
	return fs
}

func (f *fakeServer) addr() string { return f.ln.Addr().String() }

func (f *fakeServer) acceptLoop() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeServer) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { io.WriteString(c, s+crlf) }

	w("220 fake ftp ready")
	var (
		dataIP    string
		dataPort  int
		mode      string // passive/active per last control cmd
		passiveLn net.Listener
	)
	defer func() {
		if passiveLn != nil {
			passiveLn.Close()
		}
	}()

	acceptData := func() (net.Conn, error) {
		switch mode {
		case "passive":
			if passiveLn == nil {
				return nil, errors.New("no passive listener")
			}
			conn, err := passiveLn.Accept()
			passiveLn.Close()
			passiveLn = nil
			return conn, err
		case "active":
			return net.Dial("tcp4", hostPort(dataIP, dataPort))
		}
		return nil, errors.New("no data mode set")
	}

	for {
		line, err := readControlLine(r)
		if line == "" {
			f.t.Logf("fake: control closed err=%v", err)
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "USER":
			w("331 need password")
		case "PASS":
			if arg == "BADPASS" {
				w("530 Login denied")
				continue
			}
			w("230 logged in")
		case "SYST", "TYPE", "PWD":
			w("200 ok")
		case "PASV":
			passiveLn, err = net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				w("425 cannot listen")
				continue
			}
			ap := passiveLn.Addr().(*net.TCPAddr)
			mode = "passive"
			w(fmt.Sprintf("227 entering passive (%s,%d,%d)",
				strings.ReplaceAll(ap.IP.String(), ".", ","), ap.Port/256, ap.Port%256))
		case "PORT":
			dataIP, dataPort, err = parsePORT(arg)
			if err != nil {
				w("501 bad port")
				continue
			}
			mode = "active"
			w("200 ok")
		case "RETR":
			conn, err := acceptData()
			if err != nil {
				w("425 no data")
				continue
			}
			w("150 opening data")
			if arg == "huge" {
				// Stream far more than any socket buffer so a transfer
				// cannot finish instantly.
				payload := make([]byte, 64<<10)
				for i := range payload {
					payload[i] = byte(i)
				}
				for i := 0; i < 256; i++ { // 16 MiB
					if _, err := conn.Write(payload); err != nil {
						break
					}
				}
				conn.Close()
				w("226 transfer complete")
				continue
			}
			payload := []byte("0123456789ABCDEF")
			conn.Write(payload)
			conn.Close()
			w("226 transfer complete")
		case "STOR":
			conn, err := acceptData()
			if err != nil {
				w("425 no data")
				continue
			}
			w("125 data ok")
			got, _ := io.ReadAll(conn)
			conn.Close()
			f.mu.Lock()
			f.stored = got
			f.mu.Unlock()
			w(fmt.Sprintf("226 stored %d bytes", len(got)))
		case "FEAT":
			// vsftpd-style multi-line: continuation lines are arbitrary
			// text (" EPRT"), terminator repeats the code.
			w("211-Extensions supported:")
			w(" EPRT")
			w(" IDLE")
			w(" MDTM")
			w(" SIZE")
			w("211 End")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("502 not implemented")
		}
		_ = err
	}
}

// ---------- test helpers ----------

type client struct {
	c net.Conn
	r *bufio.Reader
	t *testing.T
}

func dialClient(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &client{c: c, r: bufio.NewReader(c), t: t}
}

func (cl *client) send(line string) {
	cl.t.Helper()
	if _, err := io.WriteString(cl.c, line+crlf); err != nil {
		cl.t.Fatal(err)
	}
}

// expect reads one response and asserts the 3-digit code.
func (cl *client) expect(want string) string {
	cl.t.Helper()
	code, lines, err := readResponse(cl.r)
	if err != nil {
		cl.t.Fatalf("read response want %s: %v", want, err)
	}
	if code != want {
		cl.t.Fatalf("got code %s (%v), want %s", code, lines, want)
	}
	return strings.Join(lines, "\n")
}

func discardLogger() *slog.Logger {
	lvl := slog.LevelWarn
	if os.Getenv("FTP_TEST_DEBUG") != "" {
		lvl = slog.LevelDebug
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}

func testCfg(listen, dest string) config.ProxyConfig {
	c := config.ProxyConfig{Name: "test", Listen: listen, Destination: dest}
	c.SetDefaults()
	return c
}

func startProxy(t *testing.T, cfg config.ProxyConfig) *Proxy {
	return startProxyLog(t, cfg, discardLogger(), config.LogConfig{})
}

func startProxyLog(t *testing.T, cfg config.ProxyConfig, log *slog.Logger, logCfg config.LogConfig) *Proxy {
	t.Helper()
	res := dnsx.New(config.DNSConfig{Timeout: config.Duration{Duration: 2 * time.Second}})
	m := metrics.New("test", "none")
	p, err := New(cfg, res, m, log, logCfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := p.Serve(ctx); err != nil {
			// ignore after cancel
		}
	}()
	t.Cleanup(func() {
		p.Shutdown()
		cancel()
	})
	return p
}

// ---------- tests ----------

// passive mode: client PASV -> server 227 is rewritten to proxy listener.
func TestProxyPassiveRetrStor(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxy(t, cfg)

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("USER bob")
	cl.expect("331")
	cl.send("PASS x")
	cl.expect("230")
	cl.send("TYPE I")
	cl.expect("200")

	resp := func() (string, int) {
		cl.send("PASV")
		body := cl.expect("227")
		ip, port, ok := parse227Addr([]string{body})
		if !ok {
			t.Fatalf("bad 227: %q", body)
		}
		// The advertised address must be the proxy (127.0.0.1 in tests),
		// and the port must NOT equal the server's own passive port.
		if ip != "127.0.0.1" {
			t.Fatalf("227 rewritten to %s, want 127.0.0.1", ip)
		}
		return ip, port
	}

	// RETR
	ip, port := resp()
	t.Logf("passive data endpoint: %s:%d", ip, port)
	data, err := net.Dial("tcp4", hostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client data conn local=%s remote=%s", data.LocalAddr(), data.RemoteAddr())
	data.SetReadDeadline(time.Now().Add(8 * time.Second))
	cl.send("RETR file")
	cl.expect("150")
	got, err := io.ReadAll(data)
	t.Logf("retr read: n=%d err=%v", len(got), err)
	data.Close()
	cl.expect("226")
	if string(got) != "0123456789ABCDEF" {
		t.Fatalf("retr data = %q", got)
	}

	// STOR
	ip, port = resp()
	data, err = net.Dial("tcp4", hostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1<<20) // 1 MiB, streamed
	rand.Read(payload)
	cl.send("STOR up")
	cl.expect("125")
	if _, err := data.Write(payload); err != nil {
		t.Fatal(err)
	}
	// half-close so the server sees EOF on the data socket
	data.(*net.TCPConn).CloseWrite()
	cl.expect("226")
	data.Close()

	fs.mu.Lock()
	stored := fs.stored
	fs.mu.Unlock()
	if len(stored) != len(payload) || string(stored) != string(payload) {
		t.Fatalf("stored %d bytes, want %d (match=%v)", len(stored), len(payload), string(stored) == string(payload))
	}

	cl.send("QUIT")
	cl.expect("221")
}

// active mode: client PORT -> proxy listens and advertises its own port.
func TestProxyActivePort(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxy(t, cfg)

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("USER bob")
	cl.expect("331")
	cl.send("PASS x")
	cl.expect("230")

	// Client listens for the active data connection.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ap := ln.Addr().(*net.TCPAddr)
	cl.send(fmt.Sprintf("PORT %s,%d,%d",
		strings.ReplaceAll(ap.IP.String(), ".", ","), ap.Port/256, ap.Port%256))
	cl.expect("200")

	cl.send("RETR file")
	// server dials proxy; proxy dials client listener
	data, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	cl.expect("150")
	got, _ := io.ReadAll(data)
	cl.expect("226")
	if string(got) != "0123456789ABCDEF" {
		t.Fatalf("active retr = %q", got)
	}

	cl.send("QUIT")
	cl.expect("221")
}

// proxy-side basic auth gate.
func TestProxyAuth(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	cfg.Auth = &config.AuthConfig{Users: []config.User{{Username: "ok", Password: "pw"}}}
	cfg.ACL = &config.ACLConfig{Default: "allow"}
	cfg.SetDefaults()
	p := startProxy(t, cfg)

	// wrong credentials are rejected before anything reaches the server
	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("USER ok")
	cl.expect("331")
	cl.send("PASS wrong")
	cl.expect("530")
	cl.send("RETR file")
	cl.expect("530")

	// correct credentials pass through (proxy checks, then forwards USER/PASS)
	cl2 := dialClient(t, p.Addr().String())
	cl2.expect("220")
	cl2.send("USER ok")
	cl2.expect("331")
	cl2.send("PASS pw")
	cl2.expect("230")
	cl2.send("PWD")
	cl2.expect("200")
	cl2.send("QUIT")
	cl2.expect("221")
}

// ACL deny closes the connection without the server greeting.
func TestProxyACLDeny(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	cfg.ACL = &config.ACLConfig{
		Default: "deny",
		Rules:   []config.ACLRule{{Action: "allow", Src: "10.0.0.0/8"}},
	}
	cfg.SetDefaults()
	p := startProxy(t, cfg)

	c, err := net.Dial("tcp4", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("expected immediate close, got n=%d err=%v", n, err)
	}
}

// source_address pins the local source IP on outgoing dials.
func TestProxySourceAddressPinned(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	cfg.SourceAddress = "127.0.0.1"
	cfg.SetDefaults()
	p := startProxy(t, cfg)

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("PASV")
	body := cl.expect("227")
	ip, port, ok := parse227Addr([]string{body})
	if !ok {
		t.Fatalf("bad 227: %q", body)
	}
	data, err := net.Dial("tcp4", hostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	cl.send("RETR file")
	cl.expect("150")
	got, _ := io.ReadAll(data)
	cl.expect("226")
	if string(got) != "0123456789ABCDEF" {
		t.Fatalf("retr with source_address = %q", got)
	}
}

// A source address not assigned to any interface must fail the upstream
// dial: the connection is closed before the greeting ever arrives.
func TestProxyBadSourceAddressFailsDial(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	cfg.SourceAddress = "192.0.2.1" // TEST-NET-1, unrouted, not local
	cfg.SetDefaults()
	p := startProxy(t, cfg)

	c, err := net.Dial("tcp4", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("expected immediate close on bad source_address, got n=%d err=%v", n, err)
	}
}

// PASS/ACCT secrets: masked when log.hide_passwords is set, never present
// at info level (command records are debug-only), plain at debug otherwise.
func TestProxyPasswordMasking(t *testing.T) {
	fs := newFakeServer(t)

	cases := []struct {
		name     string
		logCfg   config.LogConfig
		wantMask bool
	}{
		{"debug shows secrets by default", config.LogConfig{HidePasswords: false}, false},
		{"hide_passwords masks secrets", config.LogConfig{HidePasswords: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			cfg := testCfg("127.0.0.1:0", fs.addr())
			p := startProxyLog(t, cfg, log, tc.logCfg)

			cl := dialClient(t, p.Addr().String())
			cl.expect("220")
			cl.send("USER alice")
			cl.expect("331")
			cl.send("PASS s3cr3t-pw")
			cl.expect("230")

			logs := buf.String()
			if tc.wantMask {
				if strings.Contains(logs, "s3cr3t-pw") {
					t.Fatalf("secret leaked in logs: %s", logs)
				}
				if !strings.Contains(logs, `arg=*****`) {
					t.Fatalf("expected masked arg in logs: %s", logs)
				}
			} else {
				if !strings.Contains(logs, "s3cr3t-pw") {
					t.Fatalf("expected secret at debug level: %s", logs)
				}
			}
		})
	}

	// and at info level the command line is never emitted at all
	var buf bytes.Buffer
	infoLog := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxyLog(t, cfg, infoLog, config.LogConfig{})
	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("USER alice")
	cl.expect("331")
	cl.send("PASS s3cr3t-pw")
	cl.expect("230")
	if strings.Contains(buf.String(), "s3cr3t-pw") || strings.Contains(buf.String(), "client cmd") {
		t.Fatalf("no command records expected at info level: %s", buf.String())
	}
}

// Negative completions (4xx/5xx) from the server are logged at info level
// with the causing command, and the command record never carries a password.
func TestServerErrorLoggedAtInfo(t *testing.T) {
	fs := newFakeServer(t)
	var buf bytes.Buffer
	infoLog := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxyLog(t, cfg, infoLog, config.LogConfig{})

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("USER alice")
	cl.expect("331")
	cl.send("PASS BADPASS")
	cl.expect("530")
	cl.send("FOO bar") // fake server answers unknown verbs with 502
	cl.expect("502")
	cl.send("QUIT")
	cl.expect("221")

	logs := buf.String()
	for _, want := range []string{
		`msg="server error response"`,
		`code=530`,
		`cmd="PASS *****"`,
		`code=502`,
		`cmd="FOO bar"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("info log missing %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "BADPASS") {
		t.Errorf("password leaked into info log:\n%s", logs)
	}

	// positive completions stay silent at info
	for _, ok := range []string{"code=220", "code=230", "code=221"} {
		if strings.Contains(logs, ok) {
			t.Errorf("positive completion %q should not be logged at info:\n%s", ok, logs)
		}
	}
}

// The transfer-initiating command (RETR/LIST/...) is attached to data
// channel records so repeated transfers of different files are separable.
func TestTransferCommandLogged(t *testing.T) {
	fs := newFakeServer(t)
	var buf bytes.Buffer
	infoLog := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxyLog(t, cfg, infoLog, config.LogConfig{})

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("PASV")
	body := cl.expect("227")
	ip, port, ok := parse227Addr([]string{body})
	if !ok {
		t.Fatalf("bad 227: %q", body)
	}
	data, err := net.Dial("tcp4", hostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	cl.send("RETR bfo001f.xml")
	cl.expect("150")
	io.ReadAll(data)
	data.Close() // finish the data channel so the proxy logs the transfer
	cl.expect("226")

	deadline := time.Now().Add(2 * time.Second)
	var logs string
	for time.Now().Before(deadline) {
		logs = buf.String()
		if strings.Contains(logs, `msg="data transfer finished"`) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logs, `cmd="RETR bfo001f.xml"`) {
		t.Errorf("transfer command missing from info log:\n%s", logs)
	}
	if !strings.Contains(logs, `msg="data transfer finished"`) {
		t.Errorf("transfer record missing:\n%s", logs)
	}
}

// FEAT (sent by WinSCP right after login) gets a multi-line 211 from vsftpd
// with space-indented command lines. The proxy must relay it whole and keep
// the control stream in sync.
func TestProxyFeatMultiLineResponse(t *testing.T) {
	fs := newFakeServer(t)
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxyLog(t, cfg, discardLogger(), config.LogConfig{})

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("FEAT")
	code, lines, err := readResponse(cl.r)
	if err != nil {
		t.Fatalf("FEAT relay: %v", err)
	}
	if code != "211" || len(lines) != 6 {
		t.Fatalf("bad FEAT relay: code=%s lines=%v", code, lines)
	}
	if lines[1] != " EPRT" || lines[5] != "211 End" {
		t.Fatalf("FEAT body corrupted: %q", lines)
	}

	// Session must still be alive and in sync afterwards.
	cl.send("TYPE I")
	cl.expect("200")
	cl.send("QUIT")
	cl.expect("221")
}

// A transfer that dies mid-stream must be distinguishable from a clean one
// at info level: record says aborted, names the command, and tags which
// phase failed (read from origin vs write to client).
func TestTransferAbortLoggedAtInfo(t *testing.T) {
	fs := newFakeServer(t)
	var buf bytes.Buffer
	infoLog := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := testCfg("127.0.0.1:0", fs.addr())
	p := startProxyLog(t, cfg, infoLog, config.LogConfig{})

	cl := dialClient(t, p.Addr().String())
	cl.expect("220")
	cl.send("PASV")
	body := cl.expect("227")
	ip, port, ok := parse227Addr([]string{body})
	if !ok {
		t.Fatalf("bad 227: %q", body)
	}
	d, err := net.Dial("tcp4", hostPort(ip, port))
	if err != nil {
		t.Fatal(err)
	}
	data := d.(*net.TCPConn)
	cl.send("RETR huge")
	cl.expect("150")

	// Prime the pipe, then RST the data channel from the client side,
	// like a client that gives up on a multi-GB download.
	first := make([]byte, 4096)
	data.Read(first)
	data.SetLinger(0) // Close() sends RST, not FIN
	data.Close()

	deadline := time.Now().Add(10 * time.Second)
	var logs string
	for time.Now().Before(deadline) {
		logs = buf.String()
		if strings.Contains(logs, `msg="data transfer aborted"`) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs, `cmd="RETR huge"`) {
		t.Errorf("aborted record missing cmd:\n%s", logs)
	}
	if !strings.Contains(logs, `err="download write:`) {
		t.Errorf("aborted record missing failure phase:\n%s", logs)
	}
}

func TestSampleConfigValid(t *testing.T) {
	cfg, err := config.Load("../../config.yaml")
	if err != nil {
		t.Fatalf("sample config invalid: %v", err)
	}
	if len(cfg.Proxies) != 2 {
		t.Fatalf("want 2 proxies, got %d", len(cfg.Proxies))
	}
	if cfg.DNS.Resolver == "" {
		t.Fatal("sample should show a custom resolver")
	}
}
