package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
)

const (
	sessionCookie = "redns_admin"
	sessionTTL    = 7 * 24 * time.Hour
	maxFails      = 5
	lockout       = 15 * time.Minute
)

type admin struct {
	w *Web

	mu       sync.Mutex
	sessions map[string]time.Time
	fails    map[netip.Prefix]failState
	now      func() time.Time
}

type failState struct {
	n     int
	until time.Time
}

func newAdmin(w *Web) *admin {
	return &admin{w: w, sessions: map[string]time.Time{}, fails: map[netip.Prefix]failState{}, now: time.Now}
}

func (a *admin) enabled() bool {
	return a.w.o.PasswordHash != nil && a.w.o.PasswordHash() != "" && a.w.o.Store != nil
}

func (a *admin) visible(r *http.Request) bool {
	if a.w.o.AdminPublic != nil && a.w.o.AdminPublic() {
		return true
	}
	return a.w.o.Access.Trusted(remoteIP(r))
}

func (a *admin) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if !a.enabled() || !a.visible(r) {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Cache-Control", "no-store")
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/admin" {
		render(rw, adminTmpl, map[string]string{"Host": a.w.o.Host, "Version": a.w.o.Version})
		return
	}
	api, ok := strings.CutPrefix(path, "/admin/api/")
	if !ok {
		http.NotFound(rw, r)
		return
	}
	if r.Method == http.MethodPost && r.Header.Get("X-ReDNS") != "1" {
		http.Error(rw, "missing header", http.StatusForbidden)
		return
	}
	if api == "login" {
		a.login(rw, r)
		return
	}
	if !a.authed(r) {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	type handler struct {
		method string
		fn     func(http.ResponseWriter, *http.Request)
	}
	routes := map[string]handler{
		"logout":         {http.MethodPost, a.logout},
		"overview":       {http.MethodGet, a.overview},
		"clients":        {http.MethodGet, a.clients},
		"devices":        {http.MethodGet, a.devices},
		"devices/add":    {http.MethodPost, a.addDevice},
		"devices/revoke": {http.MethodPost, a.revokeDevice},
		"bans/add":       {http.MethodPost, a.ban},
		"bans/remove":    {http.MethodPost, a.unban},
		"kick":           {http.MethodPost, a.kick},
		"settings":       {http.MethodPost, a.settings},
		"log":            {http.MethodGet, a.log},
	}
	h, ok := routes[api]
	if !ok {
		http.NotFound(rw, r)
		return
	}
	if r.Method != h.method {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.fn(rw, r)
}

func (a *admin) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok || a.now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

func (a *admin) login(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	k := access.Key(remoteIP(r))
	now := a.now()
	a.mu.Lock()
	f := a.fails[k]
	a.mu.Unlock()
	if now.Before(f.until) {
		rw.Header().Set("Retry-After", strconv.Itoa(int(f.until.Sub(now).Seconds())+1))
		http.Error(rw, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(a.w.o.PasswordHash()), []byte(body.Password)) != nil {
		a.mu.Lock()
		f := a.fails[k]
		f.n++
		if f.n >= maxFails {
			f = failState{until: now.Add(lockout)}
		}
		a.fails[k] = f
		a.mu.Unlock()
		http.Error(rw, "wrong password", http.StatusUnauthorized)
		return
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sid := base64.RawURLEncoding.EncodeToString(raw)
	a.mu.Lock()
	delete(a.fails, k)
	for id, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, id)
		}
	}
	a.sessions[sid] = now.Add(sessionTTL)
	a.mu.Unlock()
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/admin", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(rw, map[string]bool{"ok": true})
}

func (a *admin) logout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(rw, &http.Cookie{Name: sessionCookie, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(rw, map[string]bool{"ok": true})
}

func (a *admin) overview(rw http.ResponseWriter, r *http.Request) {
	o := a.w.o
	resp := map[string]any{
		"host":    o.Host,
		"version": o.Version,
		"private": o.Access.Private(),
		"strict":  o.Access.Strict(),
		"you":     access.Key(remoteIP(r)).String(),
	}
	if o.Stats != nil {
		resp["stats"] = o.Stats.Snapshot()
		resp["uptime_sec"] = int(time.Since(o.Stats.Started).Seconds())
	}
	if o.Info != nil {
		resp["info"] = o.Info()
	}
	resp["bans"] = o.Store.Get().Bans
	writeJSON(rw, resp)
}

type clientRow struct {
	Prefix   string    `json:"prefix"`
	Device   string    `json:"device,omitempty"`
	Own      bool      `json:"own"`
	You      bool      `json:"you"`
	Banned   bool      `json:"banned"`
	Authed   bool      `json:"authorized"`
	DNSSeen  time.Time `json:"dns_seen,omitempty"`
	Proto    string    `json:"proto,omitempty"`
	Queries  uint64    `json:"queries"`
	Active   int       `json:"active"`
	Conns    uint64    `json:"conns"`
	Up       uint64    `json:"up"`
	Down     uint64    `json:"down"`
	LastSeen time.Time `json:"last_seen"`
	Hosts    []string  `json:"hosts,omitempty"`
}

func (a *admin) clients(rw http.ResponseWriter, r *http.Request) {
	o := a.w.o
	you := access.Key(remoteIP(r)).String()
	now := a.now()
	rows := map[string]*clientRow{}
	get := func(p string) *clientRow {
		if rows[p] == nil {
			rows[p] = &clientRow{Prefix: p, You: p == you}
		}
		return rows[p]
	}
	for _, c := range o.Access.Clients() {
		row := get(c.Prefix)
		row.Device, row.Own = c.Device, c.Device != ""
		row.Authed = now.Before(c.AuthUntil)
		row.DNSSeen, row.Proto, row.Queries = c.LastSeen, c.Proto, c.Queries
		row.LastSeen = c.LastSeen
	}
	if o.Proxy != nil {
		for _, s := range o.Proxy.ClientStats() {
			row := get(s.Prefix)
			row.Active, row.Conns, row.Up, row.Down, row.Hosts = s.Active, s.Total, s.Up, s.Down, s.Hosts
			if s.LastSeen.After(row.LastSeen) {
				row.LastSeen = s.LastSeen
			}
		}
	}
	out := make([]*clientRow, 0, len(rows))
	for _, row := range rows {
		if p, err := netip.ParsePrefix(row.Prefix); err == nil {
			row.Banned = o.Access.Banned(p.Addr())
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > 500 {
		out = out[:500]
	}
	writeJSON(rw, out)
}

type deviceRow struct {
	access.Device
	SetupURL string `json:"setup_url"`
}

func (a *admin) devices(rw http.ResponseWriter, r *http.Request) {
	ds := a.w.o.Access.Devices()
	out := make([]deviceRow, 0, len(ds))
	for _, d := range ds {
		out = append(out, deviceRow{Device: d, SetupURL: a.setupURL(d.Token)})
	}
	writeJSON(rw, out)
}

func (a *admin) setupURL(tok string) string {
	return "https://" + a.w.o.Host + "/setup/" + tok
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(v)
}

func (a *admin) update(rw http.ResponseWriter, fn func(*state.Data) error) bool {
	d, err := a.w.o.Store.Update(fn)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return false
	}
	a.w.o.Apply(d)
	return true
}

func newToken() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func (a *admin) addDevice(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(r, &body); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len([]rune(name)) > 40 {
		http.Error(rw, "имя от 1 до 40 символов", http.StatusBadRequest)
		return
	}
	tok := newToken()
	if !a.update(rw, func(d *state.Data) error {
		d.Tokens = append(d.Tokens, state.Token{Name: name, Token: tok, Created: a.now()})
		return nil
	}) {
		return
	}
	writeJSON(rw, map[string]string{"name": name, "token": tok, "setup_url": a.setupURL(tok)})
}

func (a *admin) revokeDevice(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(r, &body); err != nil || body.Token == "" {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if !a.update(rw, func(d *state.Data) error {
		kept := d.Tokens[:0]
		found := false
		for _, t := range d.Tokens {
			if t.Token == body.Token {
				found = true
				continue
			}
			kept = append(kept, t)
		}
		d.Tokens = kept
		if !found {
			d.Revoked = append(d.Revoked, body.Token)
		}
		return nil
	}) {
		return
	}
	writeJSON(rw, map[string]bool{"ok": true})
}

func parseTarget(s string) (netip.Prefix, error) {
	p, err := config.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errors.New("нужен IP или подсеть, например 203.0.113.7 или 203.0.113.0/24")
	}
	if p.Addr().Is6() && p.Bits() == 128 {
		p = access.Key(p.Addr())
	}
	return p, nil
}

func (a *admin) ban(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	p, err := parseTarget(body.Target)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if p.Contains(remoteIP(r)) {
		http.Error(rw, "это твой собственный IP", http.StatusBadRequest)
		return
	}
	if p.Bits() < 8 {
		http.Error(rw, "слишком широкая подсеть", http.StatusBadRequest)
		return
	}
	if !a.update(rw, func(d *state.Data) error {
		for _, b := range d.Bans {
			if b.Prefix == p.String() {
				return nil
			}
		}
		d.Bans = append(d.Bans, state.Ban{Prefix: p.String(), Reason: strings.TrimSpace(body.Reason), Created: a.now()})
		return nil
	}) {
		return
	}
	a.w.o.Access.Deauthorize(p)
	n := 0
	if a.w.o.Proxy != nil {
		n = a.w.o.Proxy.Disconnect(p)
	}
	writeJSON(rw, map[string]any{"ok": true, "prefix": p.String(), "closed": n})
}

func (a *admin) unban(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Prefix string `json:"prefix"`
	}
	if err := decode(r, &body); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if !a.update(rw, func(d *state.Data) error {
		kept := d.Bans[:0]
		for _, b := range d.Bans {
			if b.Prefix != body.Prefix {
				kept = append(kept, b)
			}
		}
		d.Bans = kept
		return nil
	}) {
		return
	}
	writeJSON(rw, map[string]bool{"ok": true})
}

func (a *admin) kick(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Prefix string `json:"prefix"`
	}
	if err := decode(r, &body); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	p, err := parseTarget(body.Prefix)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	a.w.o.Access.Deauthorize(p)
	n := 0
	if a.w.o.Proxy != nil {
		n = a.w.o.Proxy.Disconnect(p)
	}
	writeJSON(rw, map[string]any{"ok": true, "closed": n})
}

func (a *admin) settings(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		StrictProxy *bool `json:"strict_proxy"`
	}
	if err := decode(r, &body); err != nil || body.StrictProxy == nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if !a.update(rw, func(d *state.Data) error {
		v := *body.StrictProxy
		d.StrictProxy = &v
		return nil
	}) {
		return
	}
	writeJSON(rw, map[string]bool{"ok": true, "strict": a.w.o.Access.Strict()})
}

func (a *admin) log(rw http.ResponseWriter, r *http.Request) {
	var entries []stats.Entry
	if a.w.o.Stats != nil {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > 500 {
			n = 200
		}
		entries = a.w.o.Stats.Log().Recent(n, r.URL.Query().Get("q"))
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	writeJSON(rw, entries)
}
