package acl

import (
	"net/netip"
	"testing"

	"github.com/r2fn/go-ftproxy/internal/config"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNilConfigAllowsAll(t *testing.T) {
	c, err := New(nil, &Destination{Host: "ftp.example", Port: 21})
	if err != nil {
		t.Fatal(err)
	}
	if c.Allow(addr(t, "8.8.8.8")) != Allow {
		t.Fatal("nil ACL must allow everything")
	}
}

func TestFirstMatchWinsAndDefault(t *testing.T) {
	cfg := &config.ACLConfig{
		Default: "deny",
		Rules: []config.ACLRule{
			{Action: "deny", Src: "192.168.1.50"},
			{Action: "allow", Src: "192.168.1.0/24"},
		},
	}
	c, err := New(cfg, &Destination{Host: "ftp.example", Port: 21})
	if err != nil {
		t.Fatal(err)
	}
	if c.Allow(addr(t, "192.168.1.50")) != Deny {
		t.Fatal("explicit host deny must win (first match)")
	}
	if c.Allow(addr(t, "192.168.1.10")) != Allow {
		t.Fatal("subnet rule should allow")
	}
	if c.Allow(addr(t, "10.0.0.1")) != Deny {
		t.Fatal("no match -> default deny")
	}
}

func TestDestCIDRMatchesResolvedIPs(t *testing.T) {
	dst := &Destination{
		Host: "ftp.example",
		Port: 21,
		IPs:  []netip.Addr{addr(t, "203.0.113.7")},
	}
	cfg := &config.ACLConfig{
		Default: "deny",
		Rules: []config.ACLRule{
			{Action: "allow", Src: "10.0.0.0/8", Dest: "203.0.113.0/24"},
			{Action: "allow", Src: "10.0.0.0/8", Dest: "198.51.100.0/24"},
		},
	}
	c, err := New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	if c.Allow(addr(t, "10.1.1.1")) != Allow {
		t.Fatal("resolved IP in first dest CIDR -> allow")
	}

	dst.IPs = []netip.Addr{addr(t, "198.51.100.9")}
	if c.Allow(addr(t, "10.1.1.1")) != Allow {
		t.Fatal("second dest should match after re-resolve")
	}

	dst.IPs = []netip.Addr{addr(t, "192.0.2.1")}
	if c.Allow(addr(t, "10.1.1.1")) != Deny {
		t.Fatal("unlisted dest -> default deny")
	}
}

func TestDestHostPortMatch(t *testing.T) {
	dst := &Destination{Host: "Partner.Example", Port: 2121}
	cfg := &config.ACLConfig{
		Default: "deny",
		Rules: []config.ACLRule{
			{Action: "allow", Src: "", Dest: "partner.example:2121"},
		},
	}
	c, err := New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	if c.Allow(addr(t, "1.2.3.4")) != Allow {
		t.Fatal("case-insensitive host + port must match")
	}
}

func TestIPv6SrcAlwaysDenied(t *testing.T) {
	cfg := &config.ACLConfig{Default: "allow"}
	c, err := New(cfg, &Destination{Host: "x", Port: 21})
	if err != nil {
		t.Fatal(err)
	}
	if c.Allow(addr(t, "2001:db8::1")) != Deny {
		t.Fatal("IPv6 sources must be denied (IPv4-only proxy)")
	}
}

func TestIPv6CIDRRejectedAtCompile(t *testing.T) {
	cfg := &config.ACLConfig{
		Default: "deny",
		Rules:   []config.ACLRule{{Action: "allow", Src: "2001:db8::/32"}},
	}
	if _, err := New(cfg, &Destination{Host: "x", Port: 21}); err == nil {
		t.Fatal("IPv6 src CIDR must be rejected by config validation")
	}
}
