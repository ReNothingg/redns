package access

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/state"
)

type tokenInfo struct {
	name    string
	owner   string
	kind    string
	source  string
	created time.Time
}

type rules struct {
	private bool
	strict  bool
	tokens  map[string]tokenInfo
	cidrs   []netip.Prefix
	bans    []netip.Prefix
	ttl     time.Duration
}

type entry struct {
	authUntil time.Time
	token     string
	lastSeen  time.Time
	proto     string
	queries   uint64
}

type strikes struct {
	n     int
	first time.Time
	until time.Time
}

const Owner = "Я"

const (
	maxStrikes    = 10
	strikeWindow  = 10 * time.Minute
	strikePenalty = time.Hour
)

type Access struct {
	host  string
	rules atomic.Pointer[rules]

	mu      sync.Mutex
	clients map[netip.Prefix]*entry
	bad     map[netip.Prefix]*strikes
	now     func() time.Time
	onBlock func(netip.Prefix)
}

func (a *Access) OnBlock(fn func(netip.Prefix)) { a.onBlock = fn }

func New(host string, cfg config.Access, st state.Data) *Access {
	a := &Access{
		host:    strings.ToLower(host),
		clients: map[netip.Prefix]*entry{},
		bad:     map[netip.Prefix]*strikes{},
		now:     time.Now,
	}
	a.Update(cfg, st)
	return a
}

func (a *Access) Update(cfg config.Access, st state.Data) {
	r := &rules{
		private: cfg.Mode != "public",
		strict:  cfg.StrictProxy,
		tokens:  map[string]tokenInfo{},
		ttl:     cfg.AuthTTL,
	}
	if st.StrictProxy != nil {
		r.strict = *st.StrictProxy
	}
	revoked := map[string]bool{}
	for _, t := range st.Revoked {
		revoked[t] = true
	}
	for _, t := range cfg.Tokens {
		if !revoked[t.Token] {
			r.tokens[t.Token] = tokenInfo{name: t.Name, owner: Owner, source: "config"}
		}
	}
	for _, t := range st.Tokens {
		if !revoked[t.Token] {
			owner := t.Owner
			if owner == "" {
				owner = Owner
			}
			r.tokens[t.Token] = tokenInfo{name: t.Name, owner: owner, kind: t.Kind, source: "panel", created: t.Created}
		}
	}
	for _, c := range cfg.AllowCIDRs {
		if p, err := config.ParsePrefix(c); err == nil {
			r.cidrs = append(r.cidrs, p)
		}
	}
	for _, b := range st.Bans {
		if p, err := config.ParsePrefix(b.Prefix); err == nil {
			r.bans = append(r.bans, p)
		}
	}
	a.rules.Store(r)
	a.mu.Lock()
	for _, e := range a.clients {
		if _, ok := r.tokens[e.token]; e.token != "" && !ok {
			e.authUntil = time.Time{}
			e.token = ""
		}
	}
	a.mu.Unlock()
}

func (a *Access) Private() bool { return a.rules.Load().private }
func (a *Access) Strict() bool  { return a.rules.Load().strict }

func Key(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p
	}
	return netip.PrefixFrom(ip, 32)
}

func (a *Access) ValidToken(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	tok = strings.ToLower(tok)
	_, ok := a.rules.Load().tokens[tok]
	return tok, ok
}

func (a *Access) TokenName(tok string) string {
	return a.rules.Load().tokens[tok].name
}

func (a *Access) TokenFromServerName(sni string) (string, bool) {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	label, rest, ok := strings.Cut(sni, ".")
	if !ok || rest != a.host {
		return "", false
	}
	return a.ValidToken(label)
}

func (a *Access) IsOwnName(sni string) bool {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if sni == a.host {
		return true
	}
	_, rest, ok := strings.Cut(sni, ".")
	return ok && rest == a.host
}

func (a *Access) Banned(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range a.rules.Load().bans {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *Access) Authorize(ip netip.Addr, tok string) {
	if a.Banned(ip) {
		return
	}
	r := a.rules.Load()
	k := Key(ip)
	now := a.now()
	a.mu.Lock()
	e := a.clients[k]
	if e == nil {
		e = &entry{}
		a.clients[k] = e
	}
	e.authUntil = now.Add(r.ttl)
	e.token = tok
	a.mu.Unlock()
}

func (a *Access) Deauthorize(p netip.Prefix) int {
	n := 0
	a.mu.Lock()
	for k, e := range a.clients {
		if p.Overlaps(k) && !e.authUntil.IsZero() {
			e.authUntil = time.Time{}
			n++
		}
	}
	a.mu.Unlock()
	return n
}

func (a *Access) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if a.Banned(ip) {
		return false
	}
	r := a.rules.Load()
	if !r.private || ip.IsLoopback() {
		return true
	}
	for _, p := range r.cidrs {
		if p.Contains(ip) {
			return true
		}
	}
	a.mu.Lock()
	e := a.clients[Key(ip)]
	ok := e != nil && a.now().Before(e.authUntil)
	a.mu.Unlock()
	return ok
}

func (a *Access) ProxyAllowed(ip netip.Addr) bool {
	if a.Banned(ip) {
		return false
	}
	if !a.rules.Load().strict {
		return true
	}
	return a.Allowed(ip)
}

func (a *Access) Strike(ip netip.Addr) {
	k := Key(ip)
	now := a.now()
	a.mu.Lock()
	s := a.bad[k]
	if s == nil || now.Sub(s.first) > strikeWindow {
		if len(a.bad) > 100000 {
			a.mu.Unlock()
			return
		}
		s = &strikes{first: now}
		a.bad[k] = s
	}
	s.n++
	blocked := s.n == maxStrikes
	if s.n >= maxStrikes {
		s.until = now.Add(strikePenalty)
	}
	a.mu.Unlock()
	if blocked && a.onBlock != nil {
		a.onBlock(k)
	}
}

func (a *Access) Throttled(ip netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.bad[Key(ip)]
	return s != nil && a.now().Before(s.until)
}

func (a *Access) Trusted(ip netip.Addr) bool {
	ip = ip.Unmap()
	if a.Banned(ip) {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, p := range a.rules.Load().cidrs {
		if p.Contains(ip) {
			return true
		}
	}
	r := a.rules.Load()
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.clients[Key(ip)]
	return e != nil && e.token != "" && r.tokens[e.token].owner == Owner && a.now().Before(e.authUntil)
}

func (a *Access) TokenOwner(tok string) string {
	return a.rules.Load().tokens[tok].owner
}

func (a *Access) Touch(ip netip.Addr, proto string) {
	k := Key(ip)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.clients[k]
	if e == nil {
		if len(a.clients) > 200000 {
			return
		}
		e = &entry{}
		a.clients[k] = e
	}
	e.lastSeen = now
	e.proto = proto
	e.queries++
}

type Client struct {
	Prefix    string    `json:"prefix"`
	Device    string    `json:"device,omitempty"`
	AuthUntil time.Time `json:"auth_until,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	Queries   uint64    `json:"queries"`
}

func (a *Access) client(k netip.Prefix, e *entry) Client {
	return Client{Prefix: k.String(), Device: a.TokenName(e.token), AuthUntil: e.authUntil, LastSeen: e.lastSeen, Proto: e.proto, Queries: e.queries}
}

func (a *Access) Lookup(ip netip.Addr) (Client, bool) {
	k := Key(ip)
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.clients[k]
	if e == nil {
		return Client{}, false
	}
	return a.client(k, e), true
}

func (a *Access) Clients() []Client {
	a.mu.Lock()
	out := make([]Client, 0, len(a.clients))
	for k, e := range a.clients {
		out = append(out, a.client(k, e))
	}
	a.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

type Device struct {
	Name     string    `json:"name"`
	Owner    string    `json:"owner"`
	Kind     string    `json:"kind,omitempty"`
	Token    string    `json:"token"`
	Source   string    `json:"source"`
	Created  time.Time `json:"created,omitempty"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	IPs      []string  `json:"ips"`
	Queries  uint64    `json:"queries"`
}

func (a *Access) Devices() []Device {
	r := a.rules.Load()
	byToken := map[string]*Device{}
	for tok, info := range r.tokens {
		byToken[tok] = &Device{Name: info.name, Owner: info.owner, Kind: info.kind, Token: tok, Source: info.source, Created: info.created, IPs: []string{}}
	}
	a.mu.Lock()
	for k, e := range a.clients {
		d := byToken[e.token]
		if d == nil {
			continue
		}
		d.IPs = append(d.IPs, k.String())
		d.Queries += e.queries
		if e.lastSeen.After(d.LastSeen) {
			d.LastSeen = e.lastSeen
		}
	}
	a.mu.Unlock()
	out := make([]Device, 0, len(byToken))
	for _, d := range byToken {
		sort.Strings(d.IPs)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner != out[j].Owner {
			return out[i].Owner == Owner || (out[j].Owner != Owner && out[i].Owner < out[j].Owner)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (a *Access) GC() {
	now := a.now()
	a.mu.Lock()
	for k, e := range a.clients {
		if now.After(e.authUntil) && now.Sub(e.lastSeen) > 24*time.Hour {
			delete(a.clients, k)
		}
	}
	for k, s := range a.bad {
		if now.After(s.until) && now.Sub(s.first) > strikeWindow {
			delete(a.bad, k)
		}
	}
	a.mu.Unlock()
}
