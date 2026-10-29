// Package acl implements per-connection source/destination access control.
// Only IPv4 is supported.
//
// Rules are evaluated in order, first match wins. When no rule matches the
// configured default action is applied. A nil ACL config means allow-all
// (an explicit choice in the config file), otherwise the safe default is deny.
package acl

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/r2fn/go-ftproxy/internal/config"
)

// Action is the allow/deny verdict.
type Action int

const (
	Deny Action = iota
	Allow
)

// Destination describes the FTP server this listener forwards to.
type Destination struct {
	Host string       // host name as configured
	Port int          // resolved port
	IPs  []netip.Addr // IPv4 addresses the host resolves to (may be empty until first lookup)
}

type destMatchKind int

const (
	destAny destMatchKind = iota
	destNet
	destHost
)

// Rule is a compiled ACL rule.
type Rule struct {
	Action Action

	srcAny bool
	srcNet netip.Prefix

	destKind destMatchKind
	destNet  netip.Prefix // kind destNet
	destHost string       // kind destHost, lower-cased
	destPort int          // kind destHost, 0 = any port
}

// Checker evaluates rules for one listener destination. The destination is
// held by reference so freshly resolved IPs are visible to CIDR rules.
type Checker struct {
	rules []Rule
	def   Action
	dst   *Destination
}

// New compiles the ACL config for a given listener destination.
func New(cfg *config.ACLConfig, dst *Destination) (*Checker, error) {
	if cfg == nil {
		return &Checker{def: Allow, dst: dst}, nil
	}
	c := &Checker{dst: dst}
	c.def = Deny
	if cfg.Default == "allow" {
		c.def = Allow
	}
	for i, r := range cfg.Rules {
		rule := Rule{}
		rule.Action = Deny
		if strings.EqualFold(r.Action, "allow") {
			rule.Action = Allow
		}
		if r.Src == "" {
			rule.srcAny = true
		} else {
			p, err := parseIPv4Prefix(r.Src)
			if err != nil {
				return nil, fmt.Errorf("acl.rules[%d].src: %w", i, err)
			}
			rule.srcNet = p
		}
		if r.Dest == "" {
			rule.destKind = destAny
			c.rules = append(c.rules, rule)
			continue
		}
		if p, err := parseIPv4Prefix(r.Dest); err == nil {
			rule.destKind = destNet
			rule.destNet = p
		} else {
			host := r.Dest
			port := 0
			if j := strings.LastIndex(r.Dest, ":"); j >= 0 {
				if n, err := strconv.Atoi(r.Dest[j+1:]); err == nil {
					host, port = r.Dest[:j], n
				}
			}
			rule.destKind = destHost
			rule.destHost = strings.ToLower(host)
			rule.destPort = port
		}
		c.rules = append(c.rules, rule)
	}
	return c, nil
}

func parseIPv4Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err == nil {
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("not IPv4: %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an IPv4 CIDR or address: %q", s)
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("not IPv4: %q", s)
	}
	return netip.PrefixFrom(a, 32), nil
}

// Allow returns the verdict for an IPv4 source address.
func (c *Checker) Allow(src netip.Addr) Action {
	if c == nil {
		return Allow
	}
	if !src.Is4() {
		return Deny
	}
	for _, r := range c.rules {
		if !r.srcAny && !r.srcNet.Contains(src) {
			continue
		}
		if !c.matchDest(&r) {
			continue
		}
		return r.Action
	}
	return c.def
}

func (c *Checker) matchDest(r *Rule) bool {
	switch r.destKind {
	case destAny:
		return true
	case destNet:
		for _, ip := range c.dst.IPs {
			if r.destNet.Contains(ip) {
				return true
			}
		}
		return false
	case destHost:
		if r.destPort != 0 && r.destPort != c.dst.Port {
			return false
		}
		return r.destHost == strings.ToLower(c.dst.Host)
	}
	return false
}
