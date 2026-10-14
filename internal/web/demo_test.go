package web

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/audit"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/proxy"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
)

type demoProxy struct {
	mu   sync.Mutex
	rows map[string]*proxy.ClientStat
}

func (p *demoProxy) ClientStats() []proxy.ClientStat {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []proxy.ClientStat{}
	for _, s := range p.rows {
		out = append(out, *s)
	}
	return out
}

func (p *demoProxy) Disconnect(pf netip.Prefix) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.rows[pf.String()]; ok {
		n := s.Active
		s.Active = 0
		return n
	}
	return 0
}

func TestDemo(t *testing.T) {
	addr := os.Getenv("REDNS_DEMO")
	if addr == "" {
		t.Skip("make demo")
	}
	now := time.Now()
	dir := t.TempDir()
	tokens := []state.Token{
		{Name: "iPhone", Owner: "Я", Kind: "iphone", Token: "demoiphone0000000001", Created: now.Add(-30 * 24 * time.Hour)},
		{Name: "Mac", Owner: "Я", Kind: "mac", Token: "demomac0000000000002", Created: now.Add(-30 * 24 * time.Hour)},
		{Name: "Android", Owner: "Саша", Kind: "android", Token: "demoandroid000000003", Created: now.Add(-6 * 24 * time.Hour)},
		{Name: "Windows", Owner: "Саша", Kind: "windows", Token: "demowindows000000004", Created: now.Add(-6 * 24 * time.Hour)},
		{Name: "iPhone", Owner: "Мама", Kind: "iphone", Token: "demomama000000000005", Created: now.Add(-2 * 24 * time.Hour)},
	}
	data := state.Data{Tokens: tokens, Bans: []state.Ban{{Prefix: "192.0.2.0/24", Reason: "качал через прокси торренты", Created: now.Add(-20 * time.Hour)}}}
	store, err := state.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(func(d *state.Data) error { *d = data; return nil }); err != nil {
		t.Fatal(err)
	}
	acc := access.New("dns.example.com", config.Access{Mode: "private", AuthTTL: 24 * time.Hour}, data)

	devices := map[string]string{
		"127.0.0.1": tokens[1].Token, "203.0.113.24": tokens[0].Token, "198.51.100.71": tokens[2].Token,
		"198.51.100.72": tokens[3].Token, "203.0.113.150": tokens[4].Token,
	}
	for ip, tok := range devices {
		acc.Authorize(netip.MustParseAddr(ip), tok)
		for range 40 + rand.IntN(400) {
			acc.Touch(netip.MustParseAddr(ip), "doh")
		}
	}
	acc.Touch(netip.MustParseAddr("203.0.113.201"), "udp")

	px := &demoProxy{rows: map[string]*proxy.ClientStat{
		"203.0.113.24/32":  {Prefix: "203.0.113.24/32", Active: 6, Total: 1840, Up: 210 << 20, Down: 3200 << 20, LastSeen: now, Hosts: []string{"chatgpt.com", "claude.ai", "api.spotify.com"}},
		"127.0.0.1/32":     {Prefix: "127.0.0.1/32", Active: 11, Total: 5210, Up: 640 << 20, Down: 9100 << 20, LastSeen: now, Hosts: []string{"api.anthropic.com", "chatgpt.com", "github.com"}},
		"198.51.100.71/32": {Prefix: "198.51.100.71/32", Active: 3, Total: 760, Up: 40 << 20, Down: 1900 << 20, LastSeen: now.Add(-40 * time.Second), Hosts: []string{"game.brawlstarsgame.com", "supercell.com"}},
		"198.51.100.72/32": {Prefix: "198.51.100.72/32", Total: 120, Up: 3 << 20, Down: 80 << 20, LastSeen: now.Add(-3 * time.Hour), Hosts: []string{"twitch.tv"}},
		"203.0.113.150/32": {Prefix: "203.0.113.150/32", Total: 44, Up: 1 << 20, Down: 12 << 20, LastSeen: now.Add(-50 * time.Minute), Hosts: []string{"gemini.google.com"}},
		"203.0.113.201/32": {Prefix: "203.0.113.201/32", Active: 2, Total: 97, Up: 2 << 20, Down: 310 << 20, LastSeen: now, Hosts: []string{"chatgpt.com"}},
	}}

	st := stats.New(1000)
	st.Started = now.Add(-(9*24 + 5) * time.Hour)
	st.Queries.Store(1_284_330)
	st.Forwarded.Store(1_102_904)
	st.CacheHits.Store(781_000)
	st.Blocked.Store(96_412)
	st.UpstreamErrs.Store(37)
	st.BytesDown.Store(48 << 30)
	st.BytesUp.Store(3 << 30)
	st.ConnsActive.Store(22)
	for host, n := range map[string]int{"chatgpt.com": 9120, "api.anthropic.com": 6400, "claude.ai": 4100, "game.brawlstarsgame.com": 2800, "gemini.google.com": 2100, "api.spotify.com": 1650, "usher.ttvnw.net": 900, "cursor.sh": 620} {
		for range n {
			st.ProxiedConn(host)
		}
	}
	type qe struct{ ip, name, action string }
	queries := []qe{{"127.0.0.1", "api.anthropic.com", "proxy"}, {"203.0.113.24", "chatgpt.com", "proxy"}, {"203.0.113.24", "ads.example.net", "block"},
		{"198.51.100.71", "game.brawlstarsgame.com", "proxy"}, {"127.0.0.1", "github.com", "forward"}, {"203.0.113.150", "gemini.google.com", "proxy"},
		{"127.0.0.1", "statsig.anthropic.com", "proxy"}, {"203.0.113.24", "app-measurement.com", "block"}, {"198.51.100.71", "api.spotify.com", "proxy"}}
	for i, q := range queries {
		st.Log().Add(stats.Entry{Time: now.Add(time.Duration(i-len(queries)) * 3 * time.Second), Client: q.ip, Proto: "doh", Name: q.name, Type: "A", Action: q.action, Rcode: "NOERROR"})
	}
	type ce struct {
		ip, dev, host string
		port          int
		down          uint64
		ms            int64
		err           string
	}
	conns := []ce{{"203.0.113.201", "", "chatgpt.com", 443, 84 << 20, 912000, ""}, {"198.51.100.71", "Саша · Android", "game.brawlstarsgame.com", 9339, 31 << 20, 1_800_000, ""},
		{"127.0.0.1", "Mac", "api.anthropic.com", 443, 2 << 20, 64000, ""}, {"203.0.113.24", "iPhone", "audio-ak.spotifycdn.com", 443, 9 << 20, 240000, ""},
		{"127.0.0.1", "Mac", "chatgpt.com", 443, 410 << 10, 8200, ""}, {"203.0.113.150", "Мама · iPhone", "gemini.google.com", 443, 1 << 20, 31000, ""},
		{"203.0.113.24", "iPhone", "ab.chatgpt.com", 443, 0, 3000, "не удалось подключиться"}, {"127.0.0.1", "Mac", "claude.ai", 443, 6 << 20, 120000, ""}}
	for i, c := range conns {
		st.Conns().Add(stats.Conn{Time: now.Add(time.Duration(i-len(conns)) * 7 * time.Second), Client: c.ip, Device: c.dev, Host: c.host, Port: c.port, Down: c.down, Up: c.down / 12, Ms: c.ms, Err: c.err})
	}

	logPath := filepath.Join(dir, "audit.log")
	events := []audit.Entry{
		{Time: now.Add(-26 * time.Hour), Level: "info", Action: "Сервер запущен", Detail: "v1.4.0"},
		{Time: now.Add(-25 * time.Hour), Level: "info", Action: "Вход в админку", IP: "127.0.0.1", Detail: "Mac · Safari"},
		{Time: now.Add(-21 * time.Hour), Level: "warn", Action: "Подбор ключа: IP заблокирован на час", IP: "192.0.2.14"},
		{Time: now.Add(-20 * time.Hour), Level: "warn", Action: "Бан", IP: "127.0.0.1", Detail: "192.0.2.0/24 · качал через прокси торренты"},
		{Time: now.Add(-6 * 24 * time.Hour), Level: "info", Action: "Добавлено устройство", IP: "127.0.0.1", Detail: "Саша · Android"},
		{Time: now.Add(-2 * 24 * time.Hour), Level: "info", Action: "Добавлено устройство", IP: "127.0.0.1", Detail: "Мама · iPhone"},
		{Time: now.Add(-3 * time.Hour), Level: "warn", Action: "Неверный пароль", IP: "198.51.100.200"},
		{Time: now.Add(-40 * time.Minute), Level: "info", Action: "Клиент отключён", IP: "127.0.0.1", Detail: "203.0.113.201/32"},
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	f, _ := os.Create(logPath)
	for _, e := range events {
		raw, _ := json.Marshal(e)
		f.Write(append(raw, '\n'))
	}
	f.Close()
	alog, err := audit.Open(logPath, 2000)
	if err != nil {
		t.Fatal(err)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte("demo"), bcrypt.MinCost)
	w := New(Options{
		Host: "dns.example.com", IPv4: "203.0.113.10", Access: acc, DoH: http.NotFoundHandler(), Version: "v1.4.0",
		Info:  func() Info { return Info{ProxyRules: 1312, BlockRules: 74210, CacheSize: 8841} },
		Proxy: px, Stats: st, Store: store, Apply: func(d state.Data) { acc.Update(config.Access{Mode: "private", AuthTTL: 24 * time.Hour}, d) },
		PasswordHash: func() string { return string(hash) }, Audit: alog,
	})
	go func() {
		for t := range time.Tick(100 * time.Millisecond) {
			wave := 1 + 0.5*math.Sin(float64(t.UnixMilli())/2500) + 0.15*rand.Float64()
			st.Queries.Add(uint64(4 * wave))
			st.BytesDown.Add(uint64(500_000 * wave))
			st.BytesUp.Add(uint64(40_000 * wave))
			st.ConnsActive.Store(int64(14 + 8*wave))
		}
	}()
	t.Logf("http://%s/admin  пароль: demo", addr)
	h := w.HTTPS()
	if err := http.ListenAndServe(addr, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.Host = "dns.example.com"
		h.ServeHTTP(rw, r)
	})); err != nil {
		t.Fatal(err)
	}
}
