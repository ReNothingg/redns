package certs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

var errBackoff = errors.New("waiting before the next certificate attempt")

type issueGuard struct {
	want   map[netip.Addr]bool
	lookup func(ctx context.Context, name string) ([]netip.Addr, error)
	now    func() time.Time

	mu      sync.Mutex
	ready   map[string]bool
	retryAt map[string]time.Time
	fails   map[string]int
	lastErr map[string]error
}

func newIssueGuard(ipv4, ipv6 string) *issueGuard {
	g := &issueGuard{
		want:    map[netip.Addr]bool{},
		lookup:  publicLookup,
		now:     time.Now,
		ready:   map[string]bool{},
		retryAt: map[string]time.Time{},
		fails:   map[string]int{},
		lastErr: map[string]error{},
	}
	for _, s := range []string{ipv4, ipv6} {
		if a, err := netip.ParseAddr(s); err == nil {
			g.want[a.Unmap()] = true
		}
	}
	return g
}

func publicLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	var errs []error
	for _, server := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		}}
		addrs, err := r.LookupNetIP(ctx, "ip", name)
		if err == nil {
			return addrs, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (g *issueGuard) isReady(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ready[name]
}

func (g *issueGuard) markReady(name string) {
	g.mu.Lock()
	g.ready[name] = true
	delete(g.fails, name)
	delete(g.retryAt, name)
	g.mu.Unlock()
}

func (g *issueGuard) check(name string) error {
	g.mu.Lock()
	retry, last := g.retryAt[name], g.lastErr[name]
	g.mu.Unlock()
	if g.now().Before(retry) {
		if last != nil {
			return fmt.Errorf("%w: %v", errBackoff, last)
		}
		return errBackoff
	}
	if len(g.want) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := g.lookup(ctx, name)
	for _, a := range addrs {
		if g.want[a.Unmap()] {
			return nil
		}
	}
	if err == nil {
		err = fmt.Errorf("public DNS for %s returns %v, not this server", name, addrs)
	} else {
		err = fmt.Errorf("public DNS for %s does not resolve yet: %v", name, err)
	}

	g.mu.Lock()
	g.retryAt[name] = g.now().Add(15 * time.Second)
	g.lastErr[name] = err
	g.mu.Unlock()
	return err
}

func (g *issueGuard) failed(name string, err error) {
	steps := []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute}
	g.mu.Lock()
	n := g.fails[name]
	g.fails[name] = n + 1
	g.retryAt[name] = g.now().Add(steps[min(n, len(steps)-1)])
	g.lastErr[name] = err
	g.mu.Unlock()
}
