// Package config loads and validates the ftproxy YAML configuration.
package config

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a Go duration string
// ("5m", "30s") or from an integer number of seconds.
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements yaml.Unmarshaler for Duration.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil {
		if s == "" {
			d.Duration = 0
			return nil
		}
		// Plain integer YAML scalars are seconds ("90" -> 90s).
		if isInteger(s) {
			d.Duration = parseSeconds(s)
			return nil
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		d.Duration = v
		return nil
	}
	var secs int64
	if err := node.Decode(&secs); err == nil {
		d.Duration = time.Duration(secs) * time.Second
		return nil
	}
	return fmt.Errorf("invalid duration value %q", node.Value)
}

func isInteger(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && (r == '-' || r == '+') {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseSeconds(s string) time.Duration {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(n) * time.Second
}

// Config is the root configuration document.
type Config struct {
	Log     LogConfig     `yaml:"log"`
	Metrics MetricsConfig `yaml:"metrics"`
	DNS     DNSConfig     `yaml:"dns"`
	Proxies []ProxyConfig `yaml:"proxies"`
}

// LogConfig controls logging level, format and destination.
type LogConfig struct {
	// Level: debug | info | warn | error. Default: info.
	Level string `yaml:"level"`
	// Format: text | json. Default: text.
	Format string `yaml:"format"`
	// Output: stdout | stderr | path to a file. Default: stdout.
	Output string `yaml:"output"`
	// HidePasswords masks FTP secrets (PASS/ACCT arguments) in logs as
	// "***" on every level, including debug. Default: false — secrets are
	// visible only at debug level and absent from info and above.
	HidePasswords bool `yaml:"hide_passwords"`
}

// MetricsConfig controls the Prometheus HTTP endpoint.
type MetricsConfig struct {
	// Listen address for /metrics and /healthz, e.g. "127.0.0.1:9105".
	// Empty string disables the endpoint.
	Listen string `yaml:"listen"`
}

// DNSConfig configures name resolution of destination FTP servers.
// A dedicated resolver can be set so the proxy does not depend on the
// system resolver configuration.
type DNSConfig struct {
	// Resolver is an explicit DNS server, "10.0.0.53" or "10.0.0.53:5353".
	// When empty, the system resolver is used.
	Resolver string `yaml:"resolver"`
	// Timeout per DNS query. Default: 5s.
	Timeout Duration `yaml:"timeout"`
	// CacheTTL is how long resolved addresses are reused. Default: 60s.
	CacheTTL Duration `yaml:"cache_ttl"`
}

// AuthConfig enables proxy-side basic (username/password) authentication.
// When the section is present and has users, clients must authenticate
// against the proxy before any other FTP command is forwarded upstream.
type AuthConfig struct {
	Users []User `yaml:"users"`
}

// User is a single proxy credential.
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ACLConfig describes access rules checked per connection:
// source address versus configured destination of the listener.
type ACLConfig struct {
	// Default action when no rule matches: allow | deny. Default: deny.
	Default string    `yaml:"default"`
	Rules   []ACLRule `yaml:"rules"`
}

// ACLRule is a single ACL entry. Rules are evaluated in order,
// first match wins.
type ACLRule struct {
	// Action: allow | deny.
	Action string `yaml:"action"`
	// Src: IPv4 CIDR or plain IPv4; empty means any source.
	Src string `yaml:"src"`
	// Dest: IPv4 CIDR, plain IPv4 or "host[:port]" matched against the
	// listener destination; empty means the listener destination itself.
	Dest string `yaml:"dest"`
}

// ProxyConfig is one FTP listener (one port) with its own destination,
// authentication and ACL. Only IPv4 is supported.
type ProxyConfig struct {
	// Name used in logs and Prometheus label "listener".
	Name string `yaml:"name"`
	// Listen is the explicit address the client-facing FTP listener is
	// bound to, "192.168.1.10:21" or ":2121". Always IPv4.
	Listen string `yaml:"listen"`
	// Destination FTP server, "host" or "host:port" (default port 21).
	Destination string `yaml:"destination"`
	// DataBindAddress is the local IPv4 address data-channel listeners
	// are bound to. Default: the local address of the control connection.
	DataBindAddress string `yaml:"data_bind_address"`
	// SourceAddress is the local IPv4 bound as SOURCE on all outgoing
	// sockets of this listener: the upstream control connection, the
	// upstream data connection and the active-mode back-connection to the
	// client. Use it on multi-homed hosts to pin egress to a specific
	// interface/network. Default: OS routing table picks the address.
	SourceAddress string `yaml:"source_address"`
	// ExternalIP is the IPv4 advertised to clients in rewritten PASV/EPSV/
	// EPRT replies. Required when the proxy sits behind NAT; binding still
	// happens on DataBindAddress. Default: address of the control socket.
	ExternalIP string `yaml:"external_ip"`
	// PassivePorts restricts locally allocated data ports, e.g. "50000-50100".
	PassivePorts string `yaml:"passive_ports"`
	// ControlIdleTimeout closes an idle control connection. The timer is
	// suspended while a data transfer is in progress, so multi-terabyte
	// transfers are not interrupted.
	ControlIdle Duration `yaml:"control_idle_timeout"`
	// DataAcceptTimeout bounds how long the proxy waits for the client or
	// the upstream server to connect to the locally allocated data port.
	DataAcceptTimeout Duration `yaml:"data_accept_timeout"`
	// DialTimeout is the upstream control connect timeout.
	DialTimeout Duration `yaml:"upstream_connect_timeout"`

	Auth *AuthConfig `yaml:"auth"`
	// ACL: when the whole section is omitted, all sources are allowed.
	ACL *ACLConfig `yaml:"acl"`
}

// Default timeouts. Control idle is deliberately long: a TB-sized transfer
// keeps the control channel quiet for hours.
const (
	DefaultControlIdle  = 10 * time.Minute
	DefaultDataAcceptTo = 60 * time.Second
	DefaultDialTimeout  = 15 * time.Second
	DefaultDNSTimeout   = 5 * time.Second
	DefaultDNSCacheTTL  = 60 * time.Second
)

// Load reads, parses and validates the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("config %s: no proxies defined", path)
	}
	if cfg.DNS.Timeout.Duration == 0 {
		cfg.DNS.Timeout.Duration = DefaultDNSTimeout
	}
	if cfg.DNS.CacheTTL.Duration == 0 {
		cfg.DNS.CacheTTL.Duration = DefaultDNSCacheTTL
	}
	if cfg.DNS.Resolver != "" {
		if _, err := normalizeResolverAddr(cfg.DNS.Resolver); err != nil {
			return nil, fmt.Errorf("dns.resolver: %w", err)
		}
	}
	for i := range cfg.Proxies {
		cfg.Proxies[i].SetDefaults()
		if err := cfg.Proxies[i].Validate(fmt.Sprintf("proxies[%d]", i)); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

// normalizeResolverAddr accepts "ip" or "ip:port" and defaults port 53.
func normalizeResolverAddr(s string) (string, error) {
	if host, port, err := net.SplitHostPort(s); err == nil {
		if port == "" {
			return "", fmt.Errorf("empty port in %q", s)
		}
		if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
			return "", fmt.Errorf("IPv6 resolvers are not supported: %q", s)
		}
		return s, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP or ip:port", s)
	}
	if a.Is6() {
		return "", fmt.Errorf("IPv6 resolvers are not supported: %q", s)
	}
	return net.JoinHostPort(s, "53"), nil
}

// ResolverAddr returns the normalized custom resolver address, "" = system.
func (d *DNSConfig) ResolverAddr() string {
	if d.Resolver == "" {
		return ""
	}
	s, _ := normalizeResolverAddr(d.Resolver)
	return s
}

// SetDefaults fills in zero-valued fields with defaults.
func (p *ProxyConfig) SetDefaults() {
	if p.Name == "" {
		p.Name = p.Listen
	}
	if p.ControlIdle.Duration == 0 {
		p.ControlIdle.Duration = DefaultControlIdle
	}
	if p.DataAcceptTimeout.Duration == 0 {
		p.DataAcceptTimeout.Duration = DefaultDataAcceptTo
	}
	if p.DialTimeout.Duration == 0 {
		p.DialTimeout.Duration = DefaultDialTimeout
	}
	if p.ACL != nil && p.ACL.Default == "" {
		p.ACL.Default = "deny"
	}
}

func (p *ProxyConfig) Validate(ctx string) error {
	if p.Listen == "" {
		return fmt.Errorf("%s: listen is required", ctx)
	}
	if a, err := netip.ParseAddr(listenHost(p.Listen)); err == nil && a.Is6() {
		return fmt.Errorf("%s: only IPv4 is supported (listen host %q)", ctx, p.Listen)
	}
	if p.Destination == "" {
		return fmt.Errorf("%s: destination is required", ctx)
	}
	if p.DataBindAddress != "" {
		a, err := netip.ParseAddr(p.DataBindAddress)
		if err != nil || !a.Is4() {
			return fmt.Errorf("%s: data_bind_address must be a plain IPv4 address", ctx)
		}
	}
	if p.SourceAddress != "" {
		a, err := netip.ParseAddr(p.SourceAddress)
		if err != nil || !a.Is4() {
			return fmt.Errorf("%s: source_address must be a plain IPv4 address", ctx)
		}
	}
	if p.ExternalIP != "" {
		a, err := netip.ParseAddr(p.ExternalIP)
		if err != nil || !a.Is4() {
			return fmt.Errorf("%s: external_ip must be a plain IPv4 address", ctx)
		}
	}
	if p.PassivePorts != "" {
		var lo, hi int
		if _, err := fmt.Sscanf(p.PassivePorts, "%d-%d", &lo, &hi); err != nil || lo < 1 || hi > 65535 || lo > hi {
			return fmt.Errorf("%s: passive_ports must look like \"50000-50100\"", ctx)
		}
	}
	if p.Auth != nil {
		if len(p.Auth.Users) == 0 {
			return fmt.Errorf("%s: auth.users must contain at least one user", ctx)
		}
		seen := make(map[string]bool)
		for _, u := range p.Auth.Users {
			if u.Username == "" {
				return fmt.Errorf("%s: auth user with empty username", ctx)
			}
			if seen[u.Username] {
				return fmt.Errorf("%s: duplicate auth user %q", ctx, u.Username)
			}
			seen[u.Username] = true
		}
	}
	if p.ACL != nil {
		if p.ACL.Default != "allow" && p.ACL.Default != "deny" {
			return fmt.Errorf("%s: acl.default must be allow or deny", ctx)
		}
		for i, r := range p.ACL.Rules {
			a := strings.ToLower(r.Action)
			if a != "allow" && a != "deny" {
				return fmt.Errorf("%s.acl.rules[%d]: action must be allow or deny", ctx, i)
			}
		}
	}
	return nil
}

// listenHost extracts the host part of a listen address, "" when wildcard.
func listenHost(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	return host
}
