// Package ftpproxy implements a transparent, IPv4-only FTP proxy:
// client-facing control listeners, upstream FTP servers, ACL by
// source/destination, optional proxy-side authentication and streaming
// relay of data connections without buffering file contents.
package ftpproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/r2fn/go-ftproxy/internal/acl"
	"github.com/r2fn/go-ftproxy/internal/config"
	"github.com/r2fn/go-ftproxy/internal/dnsx"
	"github.com/r2fn/go-ftproxy/internal/metrics"
)

// Proxy is one client-facing FTP listener bound to one destination server.
type Proxy struct {
	Name string
	cfg  config.ProxyConfig
	res  *dnsx.Resolver
	m    *metrics.Metrics
	log  *slog.Logger

	dst     *acl.Destination
	checker *acl.Checker

	ln       net.Listener
	dataBind net.IP // explicit data bind address or nil
	extIP    net.IP // advertised external address or nil
	srcIP    net.IP // source address pinned on outgoing dials, or nil
	pLo, pHi int    // passive port range (0 = any)

	authUsers     map[string]string // nil = no proxy auth
	hidePasswords bool              // mask PASS/ACCT args even at debug level

	mu       sync.Mutex
	sessions map[*session]struct{}
	closed   bool
}

// New validates the config, resolves the destination, compiles the ACL and
// binds the client-facing IPv4 listener. logCfg controls secret masking in
// per-session logs (PASS/ACCT arguments).
func New(cfg config.ProxyConfig, res *dnsx.Resolver, m *metrics.Metrics, baseLog *slog.Logger, logCfg config.LogConfig) (*Proxy, error) {
	host, port := splitDest(cfg.Destination)

	p := &Proxy{
		Name:          cfg.Name,
		cfg:           cfg,
		res:           res,
		m:             m,
		log:           baseLog.With("listener", cfg.Name),
		dst:           &acl.Destination{Host: host, Port: port},
		hidePasswords: logCfg.HidePasswords,
	}
	if m != nil {
		m.InitListener(cfg.Name)
	}

	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		p.dst.IPs = []netip.Addr{ip}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ips, err := res.LookupIPv4(ctx, host)
		if err != nil {
			p.log.Warn("destination not resolved at startup, will retry per connection",
				"dest", cfg.Destination, "err", err)
		} else {
			p.dst.IPs = ips
		}
	}

	checker, aerr := acl.New(cfg.ACL, p.dst)
	if aerr != nil {
		return nil, fmt.Errorf("%s: acl: %w", cfg.Name, aerr)
	}
	p.checker = checker

	if cfg.DataBindAddress != "" {
		p.dataBind = net.ParseIP(cfg.DataBindAddress).To4()
	}
	if cfg.SourceAddress != "" {
		p.srcIP = net.ParseIP(cfg.SourceAddress).To4()
	}
	if cfg.ExternalIP != "" {
		p.extIP = net.ParseIP(cfg.ExternalIP).To4()
	}
	if cfg.PassivePorts != "" {
		if _, err := fmt.Sscanf(cfg.PassivePorts, "%d-%d", &p.pLo, &p.pHi); err != nil {
			return nil, fmt.Errorf("%s: passive_ports: %w", cfg.Name, err)
		}
	}
	if cfg.Auth != nil {
		p.authUsers = make(map[string]string, len(cfg.Auth.Users))
		for _, u := range cfg.Auth.Users {
			p.authUsers[u.Username] = u.Password
		}
	}

	ln, err := net.Listen("tcp4", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("%s: listen %s: %w", cfg.Name, cfg.Listen, err)
	}
	p.ln = ln
	p.sessions = make(map[*session]struct{})

	p.log.Info("listening",
		"listen", ln.Addr().String(),
		"dest", cfg.Destination,
		"auth", p.authUsers != nil,
		"acl_default", aclDefaultLabel(cfg.ACL),
		"acl_rules", aclRuleCount(cfg.ACL))
	return p, nil
}

func aclDefaultLabel(c *config.ACLConfig) string {
	if c == nil {
		return "allow(no-acl)"
	}
	return c.Default
}

func aclRuleCount(c *config.ACLConfig) int {
	if c == nil {
		return 0
	}
	return len(c.Rules)
}

// splitDest parses "host" or "host:port" (default port 21).
func splitDest(s string) (string, int) {
	if h, ps, err := net.SplitHostPort(s); err == nil {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 && n < 65536 {
			return h, n
		}
		return s, 21
	}
	return s, 21
}

// Addr returns the bound client-facing listener address (useful when the
// config uses port 0, and in tests).
func (p *Proxy) Addr() net.Addr { return p.ln.Addr() }

// Serve runs the accept loop until ctx is cancelled or the listener fails.
func (p *Proxy) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		p.ln.Close()
	}()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || p.isClosed() {
				return nil
			}
			return fmt.Errorf("%s: accept: %w", p.Name, err)
		}
		go p.handleClient(ctx, conn)
	}
}

func (p *Proxy) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// Shutdown stops the listener and closes all open sessions.
func (p *Proxy) Shutdown() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.ln.Close()
	conns := make([]*session, 0, len(p.sessions))
	for s := range p.sessions {
		conns = append(conns, s)
	}
	p.mu.Unlock()
	for _, s := range conns {
		s.close()
	}
	p.log.Info("listener shut down")
}

func (p *Proxy) handleClient(ctx context.Context, conn net.Conn) {
	tc, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || tc.IP.To4() == nil {
		// Listener is tcp4, defensive only.
		conn.Close()
		return
	}
	src, _ := netip.ParseAddr(tc.IP.String())

	if p.checker.Allow(src) == acl.Deny {
		p.log.Info("connection denied by ACL", "src", src.String())
		p.m.ACLDeniedTotal.WithLabelValues(p.Name).Inc()
		p.m.ErrorsTotal.WithLabelValues(p.Name, "acl_denied").Inc()
		conn.Close()
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout.Duration)
	defer cancel()

	server, err := p.dialUpstream(dialCtx)
	if err != nil {
		p.log.Info("upstream connect failed", "dest", p.cfg.Destination, "err", err)
		p.m.ErrorsTotal.WithLabelValues(p.Name, "upstream_dial").Inc()
		conn.Close()
		return
	}
	p.log.Debug("upstream connected", "src", tc.IP.String(),
		"via", p.UpstreamIPsString(), "server", server.RemoteAddr().String())

	s := newSession(p, conn, server, src)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		s.close()
		return
	}
	p.sessions[s] = struct{}{}
	p.mu.Unlock()

	p.m.SessionsTotal.WithLabelValues(p.Name).Inc()
	p.m.SessionsActive.WithLabelValues(p.Name).Inc()
	defer p.m.SessionsActive.WithLabelValues(p.Name).Dec()

	s.run()

	p.mu.Lock()
	delete(p.sessions, s)
	p.mu.Unlock()
}

// dialUpstream resolves (through the configured resolver) and connects to
// the destination FTP server over IPv4.
func (p *Proxy) dialUpstream(ctx context.Context) (net.Conn, error) {
	if len(p.dst.IPs) == 0 {
		ips, err := p.res.LookupIPv4(ctx, p.dst.Host)
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.dst.IPs = ips
		p.mu.Unlock()
	}
	var lastErr error
	dialer := &net.Dialer{LocalAddr: localAddrOf(p.srcIP)}
	for _, ip := range p.dst.IPs {
		d, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(p.dst.Port)))
		if err == nil {
			return d, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("dial %s: %w", p.dst.Host, lastErr)
}

// localAddrOf converts a plain IPv4 into a *net.TCPAddr with ephemeral port,
// or nil (OS picks the source address) when unset.
func localAddrOf(ip net.IP) *net.TCPAddr {
	if ip == nil {
		return nil
	}
	return &net.TCPAddr{IP: ip}
}

// UpstreamIPsString is used in session logs.
func (p *Proxy) UpstreamIPsString() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var sb strings.Builder
	for i, ip := range p.dst.IPs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(ip.String())
	}
	return sb.String()
}
