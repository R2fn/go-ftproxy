package dnsx

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/r2fn/go-ftproxy/internal/config"
)

// serveFakeUDP answers DNS queries on pc until the socket is closed.
func serveFakeUDP(pc net.PacketConn, handler func(query []byte) []byte) {
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return // socket closed
		}
		resp := handler(buf[:n])
		if resp == nil {
			continue
		}
		_, _ = pc.WriteTo(resp, from)
	}
}

// TestCustomResolver points the resolver at an in-process UDP DNS server.
func TestCustomResolver(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	handler := func(p []byte) []byte {
		r := new(dns.Msg)
		if err := r.Unpack(p); err != nil {
			return nil
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA && r.Question[0].Name == "ftp.example." {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
				A:   net.ParseIP("203.0.113.7").To4(),
			}}
		}
		b, err := m.Pack()
		if err != nil {
			return nil
		}
		return b
	}
	go serveFakeUDP(pc, handler)

	res := New(config.DNSConfig{
		Resolver: pc.LocalAddr().String(),
		Timeout:  config.Duration{Duration: 3 * time.Second},
		CacheTTL: config.Duration{Duration: time.Minute},
	})

	got, err := res.LookupIPv4(context.Background(), "ftp.example")
	if err != nil {
		t.Fatalf("lookup via custom resolver: %v", err)
	}
	want := netip.MustParseAddr("203.0.113.7")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want [%s]", got, want)
	}

	// second call must be served from cache
	res.mu.Lock()
	entry, ok := res.cache["ftp.example"]
	res.mu.Unlock()
	if !ok || len(entry.addrs) != 1 || entry.addrs[0] != want {
		t.Fatal("expected cached entry for ftp.example")
	}

	// literal IPv4 passthrough
	got, err = res.LookupIPv4(context.Background(), "198.51.100.4")
	if err != nil || len(got) != 1 || got[0].String() != "198.51.100.4" {
		t.Fatalf("literal passthrough: %v %v", got, err)
	}

	// IPv6 literal rejected
	if _, err := res.LookupIPv4(context.Background(), "2001:db8::1"); err == nil {
		t.Fatal("IPv6 literal must be rejected")
	}
}

// TestResolverGoneStaleFallback verifies an expired cache entry is served
// when the resolver becomes unreachable.
func TestResolverGoneStaleFallback(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := func(p []byte) []byte {
		r := new(dns.Msg)
		if err := r.Unpack(p); err != nil {
			return nil
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.ParseIP("192.0.2.9").To4(),
		}}
		b, err := m.Pack()
		if err != nil {
			return nil
		}
		return b
	}
	go serveFakeUDP(pc, handler)

	res := New(config.DNSConfig{
		Resolver: pc.LocalAddr().String(),
		Timeout:  config.Duration{Duration: 300 * time.Millisecond},
		CacheTTL: config.Duration{Duration: 1 * time.Millisecond},
	})
	if _, err := res.LookupIPv4(context.Background(), "a.example"); err != nil {
		t.Fatal(err)
	}
	pc.Close() // resolver gone

	// after TTL expiry the stale entry is returned as fallback
	time.Sleep(5 * time.Millisecond)
	got, err := res.LookupIPv4(context.Background(), "a.example")
	if err != nil {
		t.Fatalf("stale fallback expected, got err: %v", err)
	}
	if len(got) != 1 || got[0].String() != "192.0.2.9" {
		t.Fatalf("stale entry wrong: %v", got)
	}
}
