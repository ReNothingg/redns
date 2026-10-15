package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rsc.io/qr"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/audit"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/proxy"
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
	sessions map[string]*session
	fails    map[netip.Prefix]failState
	now      func() time.Time
}

type session struct {
	Expires  time.Time `json:"expires"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	IP       string    `json:"ip"`
	Agent    string    `json:"agent"`
	PW       string    `json:"pw"`
}

func passwordTag(hash string) string {
	sum := sha256.Sum256([]byte("redns-session:" + hash))
	return hex.EncodeToString(sum[:8])
}

func sessionKey(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return hex.EncodeToString(sum[:])
}

func sessionID(key string) string { return key[:10] }

func (a *admin) loadSessions() {
	raw, err := os.ReadFile(a.w.o.SessionsPath)
	if err != nil {
		return
	}
	saved := map[string]*session{}
	if json.Unmarshal(raw, &saved) != nil {
		return
	}
	now := a.now()
	for k, s := range saved {
		if len(k) == 64 && s != nil && now.Before(s.Expires) {
			a.sessions[k] = s
		}
	}
}

func (a *admin) saveLocked() {
	path := a.w.o.SessionsPath
	if path == "" {
		return
	}
	raw, err := json.Marshal(a.sessions)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sessions-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(raw)
	if werr != nil || tmp.Chmod(0o600) != nil || tmp.Close() != nil || os.Rename(tmp.Name(), path) != nil {
		tmp.Close()
		os.Remove(tmp.Name())
	}
}

func agentLabel(ua string) string {
	osName := "Устройство"
	for _, p := range [][2]string{{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"Mac OS X", "Mac"}, {"Windows", "Windows"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, p[0]) {
			osName = p[1]
			break
		}
	}
	browser := ""
	for _, p := range [][2]string{{"YaBrowser", "Яндекс"}, {"Edg/", "Edge"}, {"Firefox", "Firefox"}, {"Chrome", "Chrome"}, {"Safari", "Safari"}} {
		if strings.Contains(ua, p[0]) {
			browser = p[1]
			break
		}
	}
	if browser == "" {
		return osName
	}
	return osName + " · " + browser
}

func (a *admin) record(r *http.Request, warn bool, action, detail string) {
	l := a.w.o.Audit
	ip := remoteIP(r).String()
	if warn {
		l.Warn(action, ip, detail)
		return
	}
	l.Info(action, ip, detail)
}

type failState struct {
	n     int
	until time.Time
}

func newAdmin(w *Web) *admin {
	a := &admin{w: w, sessions: map[string]*session{}, fails: map[netip.Prefix]failState{}, now: time.Now}
	if w.o.SessionsPath != "" {
		a.loadSessions()
	}
	return a
}

func (a *admin) enabled() bool {
	return a.w.o.PasswordHash != nil && a.w.o.PasswordHash() != "" && a.w.o.Store != nil
}

func (a *admin) visible(r *http.Request) bool {
	if a.w.o.AdminPublic != nil && a.w.o.AdminPublic() {
		return true
	}
	if _, ok := a.session(r); ok {
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
		render(rw, adminTmpl, map[string]any{"Host": a.w.o.Host, "Version": a.w.o.Version, "Assets": assetVersion, "Icons": icons})
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
	key, ok := a.session(r)
	if !ok {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	a.renew(rw, r, key)
	type handler struct {
		method string
		fn     func(http.ResponseWriter, *http.Request)
	}
	routes := map[string]handler{
		"logout":               {http.MethodPost, a.logout},
		"overview":             {http.MethodGet, a.overview},
		"clients":              {http.MethodGet, a.clients},
		"devices":              {http.MethodGet, a.devices},
		"devices/add":          {http.MethodPost, a.addDevice},
		"devices/revoke":       {http.MethodPost, a.revokeDevice},
		"devices/revoke-owner": {http.MethodPost, a.revokeOwner},
		"devices/reset":        {http.MethodPost, a.resetDevice},
		"devices/lock":         {http.MethodPost, a.lockDevice},
		"qr":                   {http.MethodGet, a.qr},
		"bans/add":             {http.MethodPost, a.ban},
		"bans/remove":          {http.MethodPost, a.unban},
		"kick":                 {http.MethodPost, a.kick},
		"settings":             {http.MethodPost, a.settings},
		"log":                  {http.MethodGet, a.log},
		"conns":                {http.MethodGet, a.conns},
		"audit":                {http.MethodGet, a.auditLog},
		"sessions":             {http.MethodGet, a.listSessions},
		"sessions/end":         {http.MethodPost, a.endSession},
		"sessions/end-others":  {http.MethodPost, a.endOtherSessions},
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

func (a *admin) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	key := sessionKey(c.Value)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key]
	if !ok {
		return "", false
	}
	if now.After(s.Expires) || s.PW != passwordTag(a.w.o.PasswordHash()) {
		delete(a.sessions, key)
		a.saveLocked()
		return "", false
	}
	s.LastSeen = now
	s.IP = remoteIP(r).String()
	return key, true
}

func (a *admin) renew(rw http.ResponseWriter, r *http.Request, key string) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	now := a.now()
	a.mu.Lock()
	s, ok := a.sessions[key]
	stale := ok && s.Expires.Sub(now) < sessionTTL-24*time.Hour
	if stale {
		s.Expires = now.Add(sessionTTL)
		a.saveLocked()
	}
	a.mu.Unlock()
	if stale {
		setSessionCookie(rw, c.Value, int(sessionTTL.Seconds()))
	}
}

func setSessionCookie(rw http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/admin", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
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
		a.record(r, true, "Вход отклонён: IP заблокирован после неверных паролей", "")
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
		if f.n == 0 {
			a.record(r, true, "Неверный пароль, вход заблокирован на 15 минут", "")
		} else {
			a.record(r, true, "Неверный пароль", "")
		}
		http.Error(rw, "wrong password", http.StatusUnauthorized)
		return
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sid := base64.RawURLEncoding.EncodeToString(raw)
	a.mu.Lock()
	delete(a.fails, k)
	for key, s := range a.sessions {
		if now.After(s.Expires) {
			delete(a.sessions, key)
		}
	}
	agent := agentLabel(r.UserAgent())
	a.sessions[sessionKey(sid)] = &session{Expires: now.Add(sessionTTL), Created: now, LastSeen: now, IP: remoteIP(r).String(), Agent: agent, PW: passwordTag(a.w.o.PasswordHash())}
	a.saveLocked()
	a.mu.Unlock()
	a.record(r, false, "Вход в админку", agent)
	setSessionCookie(rw, sid, int(sessionTTL.Seconds()))
	writeJSON(rw, map[string]bool{"ok": true})
}

func (a *admin) logout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, sessionKey(c.Value))
		a.saveLocked()
		a.mu.Unlock()
	}
	a.record(r, false, "Выход из админки", "")
	setSessionCookie(rw, "", -1)
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
	SetupURL string    `json:"setup_url"`
	Online   bool      `json:"online"`
	Active   int       `json:"active"`
	Conns    uint64    `json:"conns"`
	Up       uint64    `json:"up"`
	Down     uint64    `json:"down"`
	Hosts    []string  `json:"hosts"`
	LastUsed time.Time `json:"last_used,omitempty"`
}

var kinds = map[string]string{
	"iphone": "iPhone", "ipad": "iPad", "mac": "Mac", "android": "Android", "windows": "Windows", "other": "Устройство",
}

func (a *admin) devices(rw http.ResponseWriter, r *http.Request) {
	stats := map[string]proxy.ClientStat{}
	if a.w.o.Proxy != nil {
		for _, s := range a.w.o.Proxy.ClientStats() {
			stats[s.Prefix] = s
		}
	}
	now := a.now()
	ds := a.w.o.Access.Devices()
	holder := map[string]string{}
	latest := map[string]time.Time{}
	for _, d := range ds {
		for ip, at := range d.IPSeen {
			if at.After(latest[ip]) {
				latest[ip], holder[ip] = at, d.Token
			}
		}
	}
	out := make([]deviceRow, 0, len(ds))
	for _, d := range ds {
		row := deviceRow{Device: d, SetupURL: a.setupURL(d.Token), Hosts: []string{}, LastUsed: d.LastSeen}
		seen := map[string]bool{}
		for _, ip := range d.IPs {
			s, ok := stats[ip]
			if !ok || holder[ip] != d.Token {
				continue
			}
			row.Active += s.Active
			row.Conns += s.Total
			row.Up += s.Up
			row.Down += s.Down
			if s.LastSeen.After(row.LastUsed) {
				row.LastUsed = s.LastSeen
			}
			for _, h := range s.Hosts {
				if !seen[h] && len(row.Hosts) < 8 {
					seen[h] = true
					row.Hosts = append(row.Hosts, h)
				}
			}
		}
		row.Online = row.Active > 0 || now.Sub(row.LastUsed) < 2*time.Minute
		out = append(out, row)
	}
	writeJSON(rw, out)
}

func (a *admin) qr(rw http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if _, ok := a.w.o.Access.ValidToken(tok); !ok {
		http.NotFound(rw, r)
		return
	}
	code, err := qr.Encode(a.setupURL(tok), qr.M)
	if err != nil {
		http.Error(rw, "qr", http.StatusInternalServerError)
		return
	}
	code.Scale = 8
	rw.Header().Set("Content-Type", "image/png")
	rw.Header().Set("Cache-Control", "no-store")
	_, _ = rw.Write(code.PNG())
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
		Owner string `json:"owner"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
	}
	if err := decode(r, &body); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	owner := strings.TrimSpace(body.Owner)
	if owner == "" {
		owner = access.Owner
	}
	if len([]rune(owner)) > 30 {
		http.Error(rw, "имя человека до 30 символов", http.StatusBadRequest)
		return
	}
	label, ok := kinds[body.Kind]
	if !ok {
		body.Kind, label = "other", kinds["other"]
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = label
	}
	if len([]rune(name)) > 40 {
		http.Error(rw, "название до 40 символов", http.StatusBadRequest)
		return
	}
	tok := newToken()
	if !a.update(rw, func(d *state.Data) error {
		d.Tokens = append(d.Tokens, state.Token{Name: name, Owner: owner, Kind: body.Kind, Token: tok, Created: a.now()})
		return nil
	}) {
		return
	}
	a.record(r, false, "Добавлено устройство", owner+" · "+name)
	writeJSON(rw, map[string]string{"name": name, "owner": owner, "kind": body.Kind, "token": tok, "setup_url": a.setupURL(tok)})
}

func (a *admin) revokeOwner(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner string `json:"owner"`
	}
	if err := decode(r, &body); err != nil || body.Owner == "" {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	if body.Owner == access.Owner {
		http.Error(rw, "Все свои устройства разом отключить нельзя: потеряешь доступ к DNS и админке. Отключай по одному.", http.StatusConflict)
		return
	}
	var tokens []string
	for _, d := range a.w.o.Access.Devices() {
		if d.Owner == body.Owner {
			tokens = append(tokens, d.Token)
		}
	}
	if !a.update(rw, func(d *state.Data) error {
		drop := map[string]bool{}
		for _, t := range tokens {
			drop[t] = true
		}
		kept := d.Tokens[:0]
		for _, t := range d.Tokens {
			if drop[t.Token] {
				delete(drop, t.Token)
				continue
			}
			kept = append(kept, t)
		}
		d.Tokens = kept
		for _, t := range tokens {
			delete(d.Locks, t)
		}
		for t := range drop {
			d.Revoked = append(d.Revoked, t)
		}
		return nil
	}) {
		return
	}
	a.record(r, false, "Отключены все устройства", body.Owner)
	writeJSON(rw, map[string]any{"ok": true, "revoked": len(tokens)})
}

func (a *admin) lockDevice(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
		Mode  string `json:"mode"`
	}
	if err := decode(r, &body); err != nil || body.Token == "" {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	label := ""
	for _, d := range a.w.o.Access.Devices() {
		if d.Token == body.Token {
			label = d.Owner + " · " + d.Name
		}
	}
	if label == "" {
		http.Error(rw, "нет такого устройства", http.StatusNotFound)
		return
	}
	sole := a.w.o.Access.SoleClient(body.Token)
	action := ""
	if !a.update(rw, func(d *state.Data) error {
		if d.Locks == nil {
			d.Locks = map[string]string{}
		}
		switch body.Mode {
		case "on":
			d.Locks[body.Token] = sole
			action = "Жёсткий режим включён"
		case "rebind":
			d.Locks[body.Token] = ""
			action = "Привязка сброшена, ключ ждёт нового клиента"
		case "off":
			delete(d.Locks, body.Token)
			action = "Жёсткий режим выключен"
		default:
			return errors.New("mode: on, off или rebind")
		}
		return nil
	}) {
		return
	}
	a.record(r, false, action, label)
	writeJSON(rw, map[string]any{"ok": true, "bound": body.Mode == "on" && sole != ""})
}

func (a *admin) resetDevice(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(r, &body); err != nil || body.Token == "" {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	label := ""
	for _, d := range a.w.o.Access.Devices() {
		if d.Token == body.Token {
			label = d.Owner + " · " + d.Name
		}
	}
	if label == "" {
		http.Error(rw, "нет такого устройства", http.StatusNotFound)
		return
	}
	a.w.o.Access.ResetUsage(body.Token)
	a.record(r, false, "Сброшены клиенты и сети устройства", label)
	writeJSON(rw, map[string]bool{"ok": true})
}

func (a *admin) revokeDevice(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(r, &body); err != nil || body.Token == "" {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	label, mine, own := "?", false, 0
	for _, d := range a.w.o.Access.Devices() {
		if d.Owner == access.Owner {
			own++
		}
		if d.Token == body.Token {
			label = d.Owner + " · " + d.Name
			mine = d.Owner == access.Owner
		}
	}
	if mine && own <= 1 {
		http.Error(rw, "Это твоё последнее устройство. Отключишь — сам потеряешь доступ к DNS и админке. Сначала добавь новое.", http.StatusConflict)
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
		delete(d.Locks, body.Token)
		if !found {
			d.Revoked = append(d.Revoked, body.Token)
		}
		return nil
	}) {
		return
	}
	a.record(r, false, "Отключено устройство", label)
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
	detail := p.String()
	if reason := strings.TrimSpace(body.Reason); reason != "" {
		detail += " · " + reason
	}
	a.record(r, true, "Бан", detail)
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
	a.record(r, false, "Бан снят", body.Prefix)
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
	a.record(r, false, "Клиент отключён", p.String())
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
	if *body.StrictProxy {
		a.record(r, false, "Прокси только для своих: включено", "")
	} else {
		a.record(r, false, "Прокси только для своих: выключено", "")
	}
	writeJSON(rw, map[string]bool{"ok": true, "strict": a.w.o.Access.Strict()})
}

func (a *admin) log(rw http.ResponseWriter, r *http.Request) {
	entries := []stats.Entry{}
	if a.w.o.Stats != nil {
		entries = append(entries, a.w.o.Stats.Log().Recent(limit(r), r.URL.Query().Get("q"))...)
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	writeJSON(rw, entries)
}

func limit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 500 {
		n = 200
	}
	return n
}

func (a *admin) conns(rw http.ResponseWriter, r *http.Request) {
	var out []stats.Conn
	if a.w.o.Stats != nil {
		out = a.w.o.Stats.Conns().Recent(limit(r), r.URL.Query().Get("q"))
	}
	if out == nil {
		out = []stats.Conn{}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	writeJSON(rw, out)
}

func (a *admin) auditLog(rw http.ResponseWriter, r *http.Request) {
	out := a.w.o.Audit.Recent(limit(r), r.URL.Query().Get("q"))
	if out == nil {
		out = []audit.Entry{}
	}
	writeJSON(rw, out)
}

type sessionRow struct {
	ID       string    `json:"id"`
	IP       string    `json:"ip"`
	Agent    string    `json:"agent"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	Current  bool      `json:"current"`
}

func (a *admin) listSessions(rw http.ResponseWriter, r *http.Request) {
	cur, _ := a.session(r)
	now := a.now()
	a.mu.Lock()
	out := make([]sessionRow, 0, len(a.sessions))
	tag := passwordTag(a.w.o.PasswordHash())
	for key, s := range a.sessions {
		if now.After(s.Expires) || s.PW != tag {
			continue
		}
		out = append(out, sessionRow{ID: sessionID(key), IP: s.IP, Agent: s.Agent, Created: s.Created, LastSeen: s.LastSeen, Current: key == cur})
	}
	a.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	writeJSON(rw, out)
}

func (a *admin) endSession(rw http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := decode(r, &body); err != nil || body.ID == "" {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	cur, _ := a.session(r)
	ended := ""
	a.mu.Lock()
	for key, s := range a.sessions {
		if sessionID(key) == body.ID && key != cur {
			ended = s.Agent + " · " + s.IP
			delete(a.sessions, key)
		}
	}
	a.saveLocked()
	a.mu.Unlock()
	if ended == "" {
		http.Error(rw, "нет такой сессии", http.StatusNotFound)
		return
	}
	a.record(r, false, "Сессия завершена", ended)
	writeJSON(rw, map[string]bool{"ok": true})
}

func (a *admin) endOtherSessions(rw http.ResponseWriter, r *http.Request) {
	cur, _ := a.session(r)
	n := 0
	a.mu.Lock()
	for key := range a.sessions {
		if key != cur {
			delete(a.sessions, key)
			n++
		}
	}
	a.saveLocked()
	a.mu.Unlock()
	a.record(r, false, "Завершены все остальные сессии", strconv.Itoa(n))
	writeJSON(rw, map[string]int{"ended": n})
}
