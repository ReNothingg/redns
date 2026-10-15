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

func (t tokenInfo) label() string {
	if t.owner == "" || t.owner == Owner {
		return t.name
	}
	return t.owner + " · " + t.name
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
	locked    bool
	lastSeen  time.Time
	proto     string
	queries   uint64
}

type usage struct {
	last    time.Time
	queries uint64
	ips     map[netip.Prefix]time.Time
	clients map[string]time.Time
}

const (
	maxDeviceIPs     = 32
	maxDeviceClients = 8
)

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
	used    map[string]*usage
	locks   map[string]string
	refused map[string]time.Time
	bad     map[netip.Prefix]*strikes
	now     func() time.Time
	onBlock func(netip.Prefix)
	onNew   func(label string, clients int)
	onBind  func(tok, fp, label string)
	onDeny  func(label string, ip netip.Addr)
}

func (a *Access) OnBlock(fn func(netip.Prefix)) { a.onBlock = fn }

func (a *Access) OnNewClient(fn func(label string, clients int)) { a.onNew = fn }

func (a *Access) OnLock(bind func(tok, fp, label string), deny func(label string, ip netip.Addr)) {
	a.onBind, a.onDeny = bind, deny
}

func (a *Access) Admit(ip netip.Addr, tok, fp string) bool {
	info, ok := a.rules.Load().tokens[tok]
	if !ok || a.Banned(ip) {
		return false
	}
	a.mu.Lock()
	bound, locked := a.locks[tok]
	bind := false
	if locked {
		switch {
		case bound == "" && fp != "":
			a.locks[tok], bind = fp, true
		case fp == "" || bound != fp:
			key := tok + "|" + fp
			report := a.now().Sub(a.refused[key]) > time.Hour
			if report {
				a.refused[key] = a.now()
			}
			a.mu.Unlock()
			if report && a.onDeny != nil {
				a.onDeny(info.label(), ip)
			}
			return false
		}
	}
	a.mu.Unlock()
	if bind && a.onBind != nil {
		a.onBind(tok, fp, info.label())
	}
	a.Authorize(ip, tok)
	a.Seen(ip, tok, fp)
	return true
}

func (a *Access) SoleClient(tok string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.used[tok]
	if u == nil || len(u.clients) != 1 {
		return ""
	}
	for fp := range u.clients {
		return fp
	}
	return ""
}

func New(host string, cfg config.Access, st state.Data) *Access {
	a := &Access{
		host:    strings.ToLower(host),
		clients: map[netip.Prefix]*entry{},
		used:    map[string]*usage{},
		locks:   map[string]string{},
		refused: map[string]time.Time{},
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
	a.locks = map[string]string{}
	for tok, fp := range st.Locks {
		if _, ok := r.tokens[tok]; ok {
			a.locks[tok] = fp
		}
	}
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
	if _, ok := a.rules.Load().tokens[tok]; !ok {
		return "", false
	}
	return tok, true
}

func (a *Access) TokenName(tok string) string {
	return a.rules.Load().tokens[tok].name
}

func (a *Access) TokenFromSNI(ip netip.Addr, sni string) string {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	label, rest, ok := strings.Cut(sni, ".")
	if !ok || label == "" || rest != a.host || a.Throttled(ip) {
		return ""
	}
	tok, valid := a.ValidToken(label)
	if !valid {
		a.Strike(ip)
		return ""
	}
	return tok
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
	if _, ok := r.tokens[tok]; !ok {
		return
	}
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
	_, e.locked = a.locks[tok]
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
	ok := e != nil && a.now().Before(e.authUntil) && !e.locked
	a.mu.Unlock()
	return ok
}

func (a *Access) authorized(ip netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.clients[Key(ip.Unmap())]
	return e != nil && a.now().Before(e.authUntil)
}

func (a *Access) ProxyAllowed(ip netip.Addr) bool {
	if a.Banned(ip) {
		return false
	}
	if !a.rules.Load().strict {
		return true
	}
	return a.Allowed(ip) || a.authorized(ip)
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

func (a *Access) Seen(ip netip.Addr, tok, fp string) {
	info, ok := a.rules.Load().tokens[tok]
	if !ok {
		return
	}
	k := Key(ip)
	now := a.now()
	a.mu.Lock()
	u := a.used[tok]
	if u == nil {
		u = &usage{ips: map[netip.Prefix]time.Time{}, clients: map[string]time.Time{}}
		a.used[tok] = u
	}
	u.last = now
	u.queries++
	if _, ok := u.ips[k]; ok || len(u.ips) < maxDeviceIPs {
		u.ips[k] = now
	}
	fresh := false
	if fp != "" {
		if _, ok := u.clients[fp]; !ok && len(u.clients) < maxDeviceClients {
			fresh = len(u.clients) > 0
			u.clients[fp] = now
		} else if ok {
			u.clients[fp] = now
		}
	}
	n := len(u.clients)
	a.mu.Unlock()
	if fresh && a.onNew != nil {
		a.onNew(info.label(), n)
	}
}

func (a *Access) ResetUsage(tok string) {
	a.mu.Lock()
	delete(a.used, tok)
	a.mu.Unlock()
}

func (a *Access) TokenKind(tok string) string {
	return a.rules.Load().tokens[tok].kind
}

func (a *Access) client(k netip.Prefix, e *entry) Client {
	r := a.rules.Load()
	type named struct {
		name string
		at   time.Time
	}
	var names []named
	for tok, u := range a.used {
		if at, ok := u.ips[k]; ok {
			if info, ok := r.tokens[tok]; ok {
				names = append(names, named{info.label(), at})
			}
		}
	}
	device := ""
	if info, ok := r.tokens[e.token]; ok {
		device = info.label()
	}
	if len(names) > 0 {
		sort.Slice(names, func(i, j int) bool { return names[i].at.After(names[j].at) })
		parts := make([]string, len(names))
		for i, n := range names {
			parts[i] = n.name
		}
		device = strings.Join(parts, ", ")
	}
	return Client{Prefix: k.String(), Device: device, AuthUntil: e.authUntil, LastSeen: e.lastSeen, Proto: e.proto, Queries: e.queries}
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
	Name     string               `json:"name"`
	Owner    string               `json:"owner"`
	Kind     string               `json:"kind,omitempty"`
	Token    string               `json:"token"`
	Source   string               `json:"source"`
	Created  time.Time            `json:"created,omitempty"`
	LastSeen time.Time            `json:"last_seen,omitempty"`
	IPs      []string             `json:"ips"`
	Queries  uint64               `json:"queries"`
	Locked   bool                 `json:"locked"`
	Bound    bool                 `json:"bound"`
	Networks int                  `json:"networks"`
	Clients  int                  `json:"clients"`
	IPSeen   map[string]time.Time `json:"-"`
}

func (a *Access) Devices() []Device {
	r := a.rules.Load()
	byToken := map[string]*Device{}
	for tok, info := range r.tokens {
		byToken[tok] = &Device{Name: info.name, Owner: info.owner, Kind: info.kind, Token: tok, Source: info.source, Created: info.created, IPs: []string{}, IPSeen: map[string]time.Time{}}
	}
	a.mu.Lock()
	for tok, fp := range a.locks {
		if d := byToken[tok]; d != nil {
			d.Locked, d.Bound = true, fp != ""
		}
	}
	for tok, u := range a.used {
		d := byToken[tok]
		if d == nil {
			continue
		}
		d.LastSeen, d.Queries, d.Clients = u.last, u.queries, len(u.clients)
		for k, at := range u.ips {
			d.IPSeen[k.String()] = at
			if a.now().Sub(at) < 24*time.Hour {
				d.Networks++
			}
		}
	}
	for k, e := range a.clients {
		if d := byToken[e.token]; d != nil {
			if _, ok := d.IPSeen[k.String()]; !ok {
				d.IPSeen[k.String()] = e.authUntil.Add(-a.rules.Load().ttl)
			}
		}
	}
	a.mu.Unlock()
	out := make([]Device, 0, len(byToken))
	for _, d := range byToken {
		for ip := range d.IPSeen {
			d.IPs = append(d.IPs, ip)
		}
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
	tokens := a.rules.Load().tokens
	for tok, u := range a.used {
		if _, ok := tokens[tok]; !ok {
			delete(a.used, tok)
			continue
		}
		for k, at := range u.ips {
			if now.Sub(at) > 24*time.Hour {
				delete(u.ips, k)
			}
		}
	}
	a.mu.Unlock()
}
