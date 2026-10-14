package dnsx

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/lists"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
)

const testToken = "testtoken0123456"

type fakeUpstream struct {
	addr    string
	queries atomic.Int32
	down    atomic.Bool
	mu      sync.Mutex
	lastECS *dns.EDNS0_SUBNET
	srv     *dns.Server
}

func startUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{addr: pc.LocalAddr().String()}
	f.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if f.down.Load() {
			return
		}
		f.queries.Add(1)
		if o := req.IsEdns0(); o != nil {
			for _, opt := range o.Option {
				if s, ok := opt.(*dns.EDNS0_SUBNET); ok {
					f.mu.Lock()
					f.lastECS = s
					f.mu.Unlock()
				}
			}
		}
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.1")})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")})
		case dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{"hello"}})
		}
		_ = w.WriteMsg(m)
	})}
	go f.srv.ActivateAndServe()
	t.Cleanup(func() { f.srv.Shutdown() })
	return f
}

type hintRecorder struct {
	mu    sync.Mutex
	names []string
}

func (h *hintRecorder) Hint(_ netip.Addr, name string) {
	h.mu.Lock()
	h.names = append(h.names, name)
	h.mu.Unlock()
}

func newTestResolver(t *testing.T, mode string) (*Resolver, *fakeUpstream, *access.Access, *hintRecorder) {
	t.Helper()
	up := startUpstream(t)
	u, err := NewUpstream([]string{up.addr}, nil, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	proxy := lists.NewRules()
	proxy.Add(lists.Rule{Kind: lists.Suffix, Value: "chatgpt.com"}, "")
	proxy.Add(lists.Rule{Kind: lists.Suffix, Value: "claude.ai"}, "")
	exclude := lists.NewRules()
	exclude.Add(lists.Rule{Kind: lists.Exact, Value: "excluded.chatgpt.com"}, "")
	block := lists.NewRules()
	block.Add(lists.Rule{Kind: lists.Suffix, Value: "ads.example"}, "")
	block.Add(lists.Rule{Kind: lists.Suffix, Value: "claude.ai"}, "")
	allow := lists.NewRules()
	allow.Add(lists.Rule{Kind: lists.Exact, Value: "ok.ads.example"}, "")
	p := &Policy{
		Host: "dns.example.com", Proxy: proxy, Exclude: exclude, Block: block, Allow: allow,
		Hosts:    map[string][]netip.Addr{"pinned.example": {netip.MustParseAddr("198.51.100.5")}},
		Canaries: true,
	}
	acc := access.New("dns.example.com", config.Access{
		Mode: mode, Tokens: []config.Token{{Name: "t", Token: testToken}}, AuthTTL: time.Hour,
	}, state.Data{})
	h := &hintRecorder{}
	r := NewResolver(Options{
		IPv4: netip.MustParseAddr("203.0.113.10"), AnswerTTL: 300, ECS: true, ServeStale: true,
	}, p, NewCache(1000, 0, time.Hour, time.Hour), u, acc, stats.New(100), h)
	return r, up, acc, h
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(1232, false)
	return m
}

var client = Client{IP: netip.MustParseAddr("93.184.1.2"), Proto: "doh"}

func firstA(t *testing.T, m *dns.Msg) string {
	t.Helper()
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A.String()
		case *dns.AAAA:
			return v.AAAA.String()
		}
	}
	return ""
}

func TestProxyAnswers(t *testing.T) {
	r, up, _, h := newTestResolver(t, "public")
	ctx := context.Background()

	m := r.Resolve(ctx, query("API.ChatGPT.com", dns.TypeA), client)
	if got := firstA(t, m); got != "203.0.113.10" {
		t.Fatalf("A = %q, want proxy IP", got)
	}
	if len(h.names) != 1 || h.names[0] != "api.chatgpt.com" {
		t.Fatalf("hints = %v", h.names)
	}
	m = r.Resolve(ctx, query("chatgpt.com", dns.TypeAAAA), client)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Fatalf("AAAA without IPv6 must be NODATA with SOA: %v", m)
	}
	m = r.Resolve(ctx, query("chatgpt.com", dns.TypeHTTPS), client)
	if len(m.Answer) != 0 {
		t.Fatalf("HTTPS for proxied name must be empty: %v", m)
	}
	if up.queries.Load() != 0 {
		t.Fatalf("proxied A/AAAA/HTTPS must not hit upstream, got %d", up.queries.Load())
	}
	m = r.Resolve(ctx, query("chatgpt.com", dns.TypeTXT), client)
	if len(m.Answer) != 1 || up.queries.Load() != 1 {
		t.Fatalf("TXT for proxied name must be forwarded: %v", m)
	}

	m = r.Resolve(ctx, query("excluded.chatgpt.com", dns.TypeA), client)
	if got := firstA(t, m); got != "192.0.2.1" {
		t.Fatalf("excluded name = %q, want upstream answer", got)
	}

	m = r.Resolve(ctx, query("claude.ai", dns.TypeA), client)
	if got := firstA(t, m); got != "203.0.113.10" {
		t.Fatalf("claude.ai = %q, want proxy IP", got)
	}
}

func TestBlockSelfHostsCanary(t *testing.T) {
	r, _, _, _ := newTestResolver(t, "public")
	ctx := context.Background()
	if got := firstA(t, r.Resolve(ctx, query("x.ads.example", dns.TypeA), client)); got != "0.0.0.0" {
		t.Fatalf("blocked A = %q", got)
	}
	if got := firstA(t, r.Resolve(ctx, query("x.ads.example", dns.TypeAAAA), client)); got != "::" {
		t.Fatalf("blocked AAAA = %q", got)
	}
	if got := firstA(t, r.Resolve(ctx, query("ok.ads.example", dns.TypeA), client)); got != "192.0.2.1" {
		t.Fatalf("allow-listed = %q", got)
	}
	if got := firstA(t, r.Resolve(ctx, query("dns.example.com", dns.TypeA), client)); got != "203.0.113.10" {
		t.Fatalf("self = %q", got)
	}
	if got := firstA(t, r.Resolve(ctx, query(testToken+".dns.example.com", dns.TypeA), client)); got != "203.0.113.10" {
		t.Fatalf("token self = %q", got)
	}
	if got := firstA(t, r.Resolve(ctx, query("pinned.example", dns.TypeA), client)); got != "198.51.100.5" {
		t.Fatalf("hosts = %q", got)
	}
	if m := r.Resolve(ctx, query("use-application-dns.net", dns.TypeA), client); m.Rcode != dns.RcodeNameError {
		t.Fatalf("canary rcode = %d", m.Rcode)
	}
	if m := r.Resolve(ctx, query("example.org", dns.TypeANY), client); len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != dns.TypeHINFO {
		t.Fatalf("ANY = %v", m)
	}
}

func TestForwardCacheECS(t *testing.T) {
	r, up, _, _ := newTestResolver(t, "public")
	ctx := context.Background()
	q := query("example.org", dns.TypeA)
	q.Id = 4242
	m := r.Resolve(ctx, q, client)
	if m.Id != 4242 || firstA(t, m) != "192.0.2.1" {
		t.Fatalf("forward = %v", m)
	}
	up.mu.Lock()
	ecs := up.lastECS
	up.mu.Unlock()
	if ecs == nil || ecs.SourceNetmask != 24 || ecs.Address.String() != "93.184.1.0" {
		t.Fatalf("ECS = %+v", ecs)
	}
	r.Resolve(ctx, query("example.org", dns.TypeA), client)
	if n := up.queries.Load(); n != 1 {
		t.Fatalf("second query must be cached, upstream saw %d", n)
	}

	other := client
	other.IP = netip.MustParseAddr("93.184.9.9")
	r.Resolve(ctx, query("example.org", dns.TypeA), other)
	if n := up.queries.Load(); n != 2 {
		t.Fatalf("other subnet must miss cache, upstream saw %d", n)
	}
}

func TestServeStale(t *testing.T) {
	r, up, _, _ := newTestResolver(t, "public")
	ctx := context.Background()
	base := time.Now()
	r.cache.now = func() time.Time { return base }
	r.Resolve(ctx, query("stale.example", dns.TypeA), client)
	r.cache.now = func() time.Time { return base.Add(2 * time.Minute) }
	up.down.Store(true)
	m := r.Resolve(ctx, query("stale.example", dns.TypeA), client)
	if firstA(t, m) != "192.0.2.1" || m.Answer[0].Header().Ttl != 30 {
		t.Fatalf("stale answer = %v", m)
	}
	m = r.Resolve(ctx, query("never-seen.example", dns.TypeA), client)
	if m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("uncached + upstream down must SERVFAIL, got %d", m.Rcode)
	}
}

func TestPrivateMode(t *testing.T) {
	r, _, acc, _ := newTestResolver(t, "private")
	ctx := context.Background()
	stranger := Client{IP: netip.MustParseAddr("198.51.100.200"), Proto: "udp"}
	if m := r.Resolve(ctx, query("chatgpt.com", dns.TypeA), stranger); m != nil {
		t.Fatal("unauthorized plain DNS must be dropped")
	}
	stranger.Proto = "doh"
	if m := r.Resolve(ctx, query("chatgpt.com", dns.TypeA), stranger); m.Rcode != dns.RcodeRefused {
		t.Fatal("unauthorized DoH must be refused")
	}
	stranger.Token = testToken
	if m := r.Resolve(ctx, query("chatgpt.com", dns.TypeA), stranger); firstA(t, m) != "203.0.113.10" {
		t.Fatal("token DoH must be answered")
	}
	if !acc.Allowed(stranger.IP) {
		t.Fatal("token must authorize the client IP")
	}
	stranger.Proto, stranger.Token = "udp", ""
	if m := r.Resolve(ctx, query("chatgpt.com", dns.TypeA), stranger); m == nil {
		t.Fatal("authorized client must get plain DNS")
	}
}

func TestLookupNetIPBypassesPolicy(t *testing.T) {
	r, _, _, _ := newTestResolver(t, "public")
	addrs, err := r.LookupNetIP(context.Background(), "chatgpt.com", true)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"192.0.2.1": true, "2001:db8::1": true}
	if len(addrs) != 2 || !want[addrs[0].String()] || !want[addrs[1].String()] {
		t.Fatalf("addrs = %v", addrs)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2)
	now := time.Now()
	l.now = func() time.Time { return now }
	ip := netip.MustParseAddr("192.0.2.9")
	allowed := 0
	for i := 0; i < 20; i++ {
		if l.Allow(ip) {
			allowed++
		}
	}
	if allowed != 8 {
		t.Fatalf("allowed %d, want 8", allowed)
	}
	now = now.Add(time.Second)
	if !l.Allow(ip) {
		t.Fatal("bucket must refill")
	}
}

func TestSameQuestion(t *testing.T) {
	q := query("example.org", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	if !sameQuestion(q, r) {
		t.Fatal("matching reply rejected")
	}
	r.Question[0].Name = "evil.org."
	if sameQuestion(q, r) {
		t.Fatal("reply for another name accepted")
	}
	r.Question[0].Name, r.Question[0].Qtype = "EXAMPLE.org.", dns.TypeAAAA
	if sameQuestion(q, r) {
		t.Fatal("reply for another type accepted")
	}
}
