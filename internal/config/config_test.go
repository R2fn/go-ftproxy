package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAndDuration(t *testing.T) {
	p := write(t, `
proxies:
  - name: a
    listen: ":2121"
    destination: "ftp.example"
    control_idle_timeout: 90
    data_accept_timeout: 45s
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	pr := cfg.Proxies[0]
	if pr.ControlIdle.Duration != 90*time.Second {
		t.Fatalf("integer-seconds duration: %v", pr.ControlIdle.Duration)
	}
	if pr.DataAcceptTimeout.Duration != 45*time.Second {
		t.Fatalf("string duration: %v", pr.DataAcceptTimeout.Duration)
	}
	if pr.DialTimeout.Duration != DefaultDialTimeout {
		t.Fatalf("dial default: %v", pr.DialTimeout.Duration)
	}
	if cfg.DNS.Timeout.Duration != DefaultDNSTimeout || cfg.DNS.CacheTTL.Duration != DefaultDNSCacheTTL {
		t.Fatal("dns defaults not applied")
	}
	if pr.ACL != nil {
		t.Fatal("absent acl must stay nil (allow-all)")
	}
}

func TestStrictUnknownField(t *testing.T) {
	p := write(t, `
proxies:
  - name: a
    listen: ":21"
    destination: x
    typo_field: 1
`)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestMissingRequired(t *testing.T) {
	p := write(t, `
proxies:
  - name: a
    destination: x
`)
	if _, err := Load(p); err == nil {
		t.Fatal("listen is required")
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":21"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("destination is required")
	}
	p = write(t, "log:\n  level: info\n")
	if _, err := Load(p); err == nil {
		t.Fatal("at least one proxy required")
	}
}

func TestIPv4OnlyValidation(t *testing.T) {
	p := write(t, `
proxies:
  - name: a
    listen: "[::1]:2121"
    destination: x
`)
	if _, err := Load(p); err == nil {
		t.Fatal("IPv6 listen must be rejected")
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":2121"
    destination: x
    external_ip: "2001:db8::1"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("IPv6 external_ip must be rejected")
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":2121"
    destination: x
    data_bind_address: "203.0.113.5"
    external_ip: "203.0.113.9"
`)
	if _, err := Load(p); err != nil {
		t.Fatalf("valid IPv4 bind/external rejected: %v", err)
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":2121"
    destination: x
    source_address: "203.0.113.5"
`)
	if _, err := Load(p); err != nil {
		t.Fatalf("valid source_address rejected: %v", err)
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":2121"
    destination: x
    source_address: "2001:db8::5"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("IPv6 source_address must be rejected")
	}
}

func TestResolverNormalization(t *testing.T) {
	d := DNSConfig{Resolver: "10.0.0.53"}
	if got := d.ResolverAddr(); got != "10.0.0.53:53" {
		t.Fatalf("resolver addr = %q", got)
	}
	d = DNSConfig{Resolver: "10.0.0.53:5353"}
	if got := d.ResolverAddr(); got != "10.0.0.53:5353" {
		t.Fatalf("resolver addr = %q", got)
	}
	d = DNSConfig{Resolver: "[::1]:53"}
	if got := d.ResolverAddr(); got != "" {
		t.Fatalf("IPv6 resolver must be invalid, got %q", got)
	}
	p := write(t, `
dns:
  resolver: "2001:db8::53"
proxies:
  - name: a
    listen: ":21"
    destination: x
`)
	if _, err := Load(p); err == nil {
		t.Fatal("IPv6 resolver must be rejected")
	}
}

func TestAuthAndACLValidation(t *testing.T) {
	p := write(t, `
proxies:
  - name: a
    listen: ":21"
    destination: x
    auth:
      users: []
`)
	if _, err := Load(p); err == nil {
		t.Fatal("empty auth.users must be rejected")
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":21"
    destination: x
    auth:
      users:
        - username: u
          password: p
        - username: u
          password: q
`)
	if _, err := Load(p); err == nil {
		t.Fatal("duplicate users must be rejected")
	}
	p = write(t, `
proxies:
  - name: a
    listen: ":21"
    destination: x
    passive_ports: "99-1"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("inverted port range must be rejected")
	}
}
