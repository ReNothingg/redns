package certs

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestGuardWaitsForDNS(t *testing.T) {
	g := newIssueGuard("203.0.113.10", "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	answer := []netip.Addr{}
	var lookupErr error = errors.New("no such host")
	g.lookup = func(context.Context, string) ([]netip.Addr, error) { return answer, lookupErr }

	if err := g.check("dns.example.com"); err == nil {
		t.Fatal("must refuse while the name does not resolve")
	}
	lookupErr, answer = nil, []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	now = now.Add(20 * time.Second)
	if err := g.check("dns.example.com"); err == nil {
		t.Fatal("must refuse while the name points elsewhere")
	}
	answer = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	if err := g.check("dns.example.com"); !errors.Is(err, errBackoff) {
		t.Fatalf("must back off between DNS checks, got %v", err)
	}
	now = now.Add(20 * time.Second)
	if err := g.check("dns.example.com"); err != nil {
		t.Fatalf("must allow once DNS points here: %v", err)
	}
}

func TestGuardBacksOffAfterFailures(t *testing.T) {
	g := newIssueGuard("203.0.113.10", "")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	g.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	g.failed("dns.example.com", errors.New("acme: 403"))
	if err := g.check("dns.example.com"); !errors.Is(err, errBackoff) {
		t.Fatal("must back off after a failure")
	}
	now = now.Add(61 * time.Second)
	if err := g.check("dns.example.com"); err != nil {
		t.Fatal("first backoff is one minute")
	}
	g.failed("dns.example.com", errors.New("acme: 403"))
	now = now.Add(61 * time.Second)
	if err := g.check("dns.example.com"); !errors.Is(err, errBackoff) {
		t.Fatal("second backoff is two minutes")
	}
	g.markReady("dns.example.com")
	if !g.isReady("dns.example.com") {
		t.Fatal("ready")
	}
}
