// Package dnsx resolves FTP server host names, optionally via a dedicated
// DNS resolver instead of the system one. IPv4 (A records) only.
package dnsx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/r2fn/go-ftproxy/internal/config"
)

// Resolver resolves host names to IPv4 addresses, with a small TTL cache.
type Resolver struct {
	server  string // custom resolver "ip:port", "" = system resolver
	timeout time.Duration
	ttl     time.Duration

	mu      sync.Mutex
	cache   map[string]entry
	dnsClnt *dns.Client
	sys     *net.Resolver
}

type entry struct {
	addrs   []netip.Addr
	expires time.Time
}

// New builds a resolver from configuration.
func New(cfg config.DNSConfig) *Resolver {
	r := &Resolver{
		server:  cfg.ResolverAddr(),
		timeout: cfg.Timeout.Duration,
		ttl:     cfg.CacheTTL.Duration,
		cache:   make(map[string]entry),
		sys:     &net.Resolver{PreferGo: false},
	}
	if r.server != "" {
		r.dnsClnt = &dns.Client{
			Net:     "udp4",
			Timeout: r.timeout,
		}
	}
	return r
}

// LookupIPv4 returns IPv4 addresses for host. Host literals pass through.
// Results are cached for the configured TTL; expired entries are refetched,
// and on refetch failure an expired entry is served as a fallback.
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			return []netip.Addr{a}, nil
		}
		return nil, fmt.Errorf("%s: IPv6 destinations are not supported", host)
	}
	key := host

	r.mu.Lock()
	e, ok := r.cache[key]
	if ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.addrs, nil
	}
	r.mu.Unlock()

	addrs, err := r.lookup(ctx, host)
	if err != nil {
		if ok && len(e.addrs) > 0 { // stale fallback
			return e.addrs, nil
		}
		return nil, err
	}

	r.mu.Lock()
	r.cache[key] = entry{addrs: addrs, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return addrs, nil
}

func (r *Resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if r.server == "" {
		return r.lookupSystem(ctx, host)
	}
	return r.lookupUpstream(ctx, host)
}

func (r *Resolver) lookupSystem(ctx context.Context, host string) ([]netip.Addr, error) {
	c, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	ips, err := r.sys.LookupNetIP(c, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("system resolver lookup %s: %w", host, err)
	}
	return ips, nil
}

func (r *Resolver) lookupUpstream(ctx context.Context, host string) ([]netip.Addr, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := r.dnsClnt.ExchangeContext(ctx, m, r.server)
	if err != nil {
		return nil, fmt.Errorf("dns lookup %s via %s: %w", host, r.server, err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, fmt.Errorf("dns: %s: NXDOMAIN (server %s)", host, r.server)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns: %s: rcode %s (server %s)", host, dns.RcodeToString[resp.Rcode], r.server)
	}
	var out []netip.Addr
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			addr, err := netip.ParseAddr(a.A.String())
			if err == nil && addr.Is4() {
				out = append(out, addr)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dns: %s: no A records (server %s)", host, r.server)
	}
	return out, nil
}
