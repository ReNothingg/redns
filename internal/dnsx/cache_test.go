package dnsx

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/renothingg/redns/internal/stats"
)

type fakeUpstream struct {
	calls atomic.Int32
	ip    atomic.Value
	delay time.Duration
}

func (f *fakeUpstream) String() string { return "fake" }

func (f *fakeUpstream) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(f.ip.Load().(string)),
	}}
	return m, nil
}

func testResolver(f *fakeUpstream, optimistic time.Duration) (*Resolver, *Cache, *time.Time) {
	now := time.Now()
	c := NewCache(1000, 0, time.Hour, 24*time.Hour)
	c.now = func() time.Time { return now }
	up := &Upstream{primary: []exchanger{f}, timeout: time.Second}
	r := &Resolver{opt: Options{ServeStale: true, Optimistic: optimistic}, cache: c, up: up, stats: stats.New(0)}
	return r, c, &now
}

func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

func firstA(t *testing.T, m *dns.Msg) (string, uint32) {
	t.Helper()
	if len(m.Answer) == 0 {
		t.Fatal("empty answer")
	}
	a := m.Answer[0].(*dns.A)
	return a.A.String(), a.Hdr.Ttl
}

func TestOptimisticServesExpiredAndRefreshes(t *testing.T) {
	f := &fakeUpstream{}
	f.ip.Store("192.0.2.1")
	r, c, now := testResolver(f, time.Hour)
	ctx := context.Background()
	req := query("example.com.")
	q := req.Question[0]

	m, act := r.forward(ctx, req, q, "example.com", Client{})
	if act != "forward" {
		t.Fatalf("first action = %s", act)
	}
	if ip, _ := firstA(t, m); ip != "192.0.2.1" {
		t.Fatalf("ip = %s", ip)
	}

	f.ip.Store("192.0.2.2")
	f.delay = 200 * time.Millisecond
	*now = now.Add(2 * time.Minute)
	c.now = func() time.Time { return *now }

	start := time.Now()
	m, act = r.forward(ctx, req, q, "example.com", Client{})
	if act != "optimistic" {
		t.Fatalf("expired action = %s", act)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("optimistic answer waited for upstream")
	}
	ip, ttl := firstA(t, m)
	if ip != "192.0.2.1" || ttl != optimisticTTL {
		t.Fatalf("stale answer = %s ttl %d", ip, ttl)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		m, act = r.forward(ctx, req, q, "example.com", Client{})
		if act == "cache" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background refresh did not land, action = %s", act)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ip, _ := firstA(t, m); ip != "192.0.2.2" {
		t.Fatalf("refreshed ip = %s", ip)
	}
	if n := f.calls.Load(); n != 2 {
		t.Fatalf("upstream calls = %d, want 2", n)
	}
}

func TestOptimisticWindow(t *testing.T) {
	f := &fakeUpstream{}
	f.ip.Store("192.0.2.1")
	r, c, now := testResolver(f, time.Hour)
	ctx := context.Background()
	req := query("example.com.")
	q := req.Question[0]
	r.forward(ctx, req, q, "example.com", Client{})

	*now = now.Add(3 * time.Hour)
	c.now = func() time.Time { return *now }
	if _, act := r.forward(ctx, req, q, "example.com", Client{}); act != "forward" {
		t.Fatalf("action past window = %s", act)
	}
}

func TestCacheSaveLoad(t *testing.T) {
	c := NewCache(1000, 0, time.Hour, 24*time.Hour)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.7"),
	}}
	k := cacheKey{name: "example.com", qtype: dns.TypeA, do: true, ecs: netip.MustParsePrefix("203.0.113.0/24")}
	c.Set(k, m)
	clock := c.now
	c.now = func() time.Time { return clock().Add(-48 * time.Hour) }
	c.Set(cacheKey{name: "old.example", qtype: dns.TypeA}, m)
	c.now = clock

	path := filepath.Join(t.TempDir(), "cache.gob")
	n, err := c.Save(path)
	if err != nil || n != 1 {
		t.Fatalf("save: n=%d err=%v", n, err)
	}

	c2 := NewCache(1000, 0, time.Hour, 24*time.Hour)
	n, err = c2.Load(path)
	if err != nil || n != 1 {
		t.Fatalf("load: n=%d err=%v", n, err)
	}
	e, fresh := c2.Get(k)
	if !fresh {
		t.Fatal("restored entry is not fresh")
	}
	if ip, _ := firstA(t, e.msg); ip != "192.0.2.7" {
		t.Fatalf("restored ip = %s", ip)
	}

	if n, err := NewCache(10, 0, 0, 0).Load(filepath.Join(t.TempDir(), "missing")); n != 0 || err != nil {
		t.Fatalf("missing file: n=%d err=%v", n, err)
	}
}
