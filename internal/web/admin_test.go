package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/audit"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
)

const testPassword = "correct horse"

type adminEnv struct {
	w   *Web
	h   http.Handler
	acc *access.Access
	log *audit.Log
	st  *stats.Stats
}

func newAdminEnv(t *testing.T) adminEnv {
	t.Helper()
	return newAdminEnvAt(t, "", nil)
}

func newAdminEnvAt(t *testing.T, sessions string, hash *string) adminEnv {
	t.Helper()
	cfg := config.Access{Mode: "private", Tokens: []config.Token{{Name: "me", Token: testToken}}, AuthTTL: time.Hour}
	acc := access.New("dns.example.com", cfg, state.Data{})
	store, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if hash == nil {
		raw, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
		h := string(raw)
		hash = &h
	}
	st := stats.New(50)
	w := New(Options{
		Host: "dns.example.com", IPv4: "203.0.113.10", Access: acc, DoH: http.NotFoundHandler(),
		Store: store, Apply: func(d state.Data) { acc.Update(cfg, d) }, Stats: st, Audit: log, SessionsPath: sessions,
		PasswordHash: func() string { return *hash },
	})
	return adminEnv{w: w, h: w.HTTPS(), acc: acc, log: log, st: st}
}

func (e adminEnv) call(method, path, ip, cookie, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://dns.example.com/admin/api/"+path, strings.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Mobile Safari/604.1")
	if method == http.MethodPost {
		r.Header.Set("X-ReDNS", "1")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (e adminEnv) login(t *testing.T, ip string) string {
	t.Helper()
	rec := e.call(http.MethodPost, "login", ip, "", `{"password":"`+testPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login from %s = %d %s", ip, rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestSessionKeepsAdminVisibleAfterIPChange(t *testing.T) {
	e := newAdminEnv(t)
	home, vpn := "198.51.100.20", "192.0.2.77"
	e.acc.Authorize(netip.MustParseAddr(home), testToken)
	sid := e.login(t, home)

	if rec := e.call(http.MethodGet, "overview", vpn, "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("no cookie from an unknown IP must stay hidden, got %d", rec.Code)
	}
	if rec := e.call(http.MethodGet, "overview", vpn, "forged-session-id", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("a made-up cookie must not reveal the admin, got %d", rec.Code)
	}
	if rec := e.call(http.MethodGet, "overview", vpn, sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("logged-in browser on a new IP must keep access, got %d", rec.Code)
	}
	e.call(http.MethodPost, "logout", vpn, sid, "")
	if rec := e.call(http.MethodGet, "overview", vpn, sid, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("after logout the admin must hide again, got %d", rec.Code)
	}
}

func TestSessionsCanBeEnded(t *testing.T) {
	e := newAdminEnv(t)
	ip := "198.51.100.21"
	e.acc.Authorize(netip.MustParseAddr(ip), testToken)
	mine, other, third := e.login(t, ip), e.login(t, ip), e.login(t, ip)

	var list []sessionRow
	json.Unmarshal(e.call(http.MethodGet, "sessions", ip, mine, "").Body.Bytes(), &list)
	if len(list) != 3 {
		t.Fatalf("sessions = %+v", list)
	}
	var target string
	current := 0
	for _, s := range list {
		if s.Current {
			current++
		} else {
			target = s.ID
		}
		if s.Agent != "iPhone · Safari" || s.IP != ip {
			t.Fatalf("session row = %+v", s)
		}
	}
	if current != 1 || strings.Contains(e.call(http.MethodGet, "sessions", ip, mine, "").Body.String(), mine) {
		t.Fatal("exactly one current session, and raw session ids never leave the server")
	}
	if rec := e.call(http.MethodPost, "sessions/end", ip, mine, `{"id":"`+target+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("end = %d", rec.Code)
	}
	if rec := e.call(http.MethodPost, "sessions/end-others", ip, mine, ""); !strings.Contains(rec.Body.String(), `"ended":1`) {
		t.Fatalf("end-others = %s", rec.Body)
	}
	for _, sid := range []string{other, third} {
		if rec := e.call(http.MethodGet, "overview", ip, sid, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("ended session still works: %d", rec.Code)
		}
	}
	if rec := e.call(http.MethodGet, "overview", ip, mine, ""); rec.Code != http.StatusOK {
		t.Fatalf("own session must survive, got %d", rec.Code)
	}
}

func TestAuditAndConnectionLog(t *testing.T) {
	e := newAdminEnv(t)
	ip := "198.51.100.22"
	e.acc.Authorize(netip.MustParseAddr(ip), testToken)
	e.call(http.MethodPost, "login", ip, "", `{"password":"wrong"}`)
	sid := e.login(t, ip)
	e.call(http.MethodPost, "bans/add", ip, sid, `{"target":"192.0.2.0/24","reason":"leech"}`)
	e.st.Conns().Add(stats.Conn{Time: time.Now(), Client: "203.0.113.5", Device: "iPhone", Host: "chatgpt.com", Port: 443, Down: 4096})
	e.st.Conns().Add(stats.Conn{Time: time.Now(), Client: "203.0.113.6", Host: "game.brawlstarsgame.com", Port: 9339, Err: "не удалось подключиться"})

	var events []audit.Entry
	json.Unmarshal(e.call(http.MethodGet, "audit?n=10", ip, sid, "").Body.Bytes(), &events)
	got := []string{}
	for _, ev := range events {
		got = append(got, ev.Level+":"+ev.Action)
	}
	want := []string{"warn:Бан", "info:Вход в админку", "warn:Неверный пароль"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit = %v, want %v", got, want)
	}
	if events[0].Detail == "" || events[0].IP != ip {
		t.Fatalf("ban entry = %+v", events[0])
	}

	var conns []stats.Conn
	json.Unmarshal(e.call(http.MethodGet, "conns?q=iphone", ip, sid, "").Body.Bytes(), &conns)
	if len(conns) != 1 || conns[0].Host != "chatgpt.com" || conns[0].Down != 4096 {
		t.Fatalf("filtered conns = %+v", conns)
	}
	json.Unmarshal(e.call(http.MethodGet, "conns", ip, sid, "").Body.Bytes(), &conns)
	if len(conns) != 2 || conns[0].Port != 9339 {
		t.Fatalf("conns must be newest first: %+v", conns)
	}
	if rec := e.call(http.MethodGet, "audit", ip, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("audit without login = %d", rec.Code)
	}
}

func TestActiveSessionSlides(t *testing.T) {
	e := newAdminEnv(t)
	ip := "198.51.100.23"
	e.acc.Authorize(netip.MustParseAddr(ip), testToken)
	clock := time.Now()
	e.w.admin.now = func() time.Time { return clock }
	sid := e.login(t, ip)

	clock = clock.Add(3 * 24 * time.Hour)
	rec := e.call(http.MethodGet, "overview", ip, sid, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=604800") {
		t.Fatalf("visit after 3 days must renew the cookie: %d %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
	if rec := e.call(http.MethodGet, "overview", ip, sid, ""); rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("fresh session must not re-send the cookie on every request")
	}
	clock = clock.Add(6 * 24 * time.Hour)
	if rec := e.call(http.MethodGet, "overview", ip, sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("9 days after login but 6 after last visit must still work, got %d", rec.Code)
	}
	clock = clock.Add(8 * 24 * time.Hour)
	if rec := e.call(http.MethodGet, "overview", ip, sid, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a week of silence must end the session, got %d", rec.Code)
	}
}

func TestSessionsSurviveRestartButNotPasswordChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-sessions.json")
	raw, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	hash := string(raw)
	ip, vpn := "198.51.100.24", "192.0.2.88"

	first := newAdminEnvAt(t, path, &hash)
	first.acc.Authorize(netip.MustParseAddr(ip), testToken)
	sid := first.login(t, ip)

	disk, _ := os.ReadFile(path)
	if strings.Contains(string(disk), sid) {
		t.Fatal("raw session cookie must never be written to disk")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("sessions file mode %v", st.Mode().Perm())
	}

	restarted := newAdminEnvAt(t, path, &hash)
	if rec := restarted.call(http.MethodGet, "overview", vpn, sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("session must survive a restart, got %d", rec.Code)
	}

	other, _ := bcrypt.GenerateFromPassword([]byte("new password"), bcrypt.MinCost)
	hash = string(other)
	if rec := restarted.call(http.MethodGet, "overview", vpn, sid, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("password change must end old sessions, got %d", rec.Code)
	}
}

func TestCannotRevokeLastOwnDevice(t *testing.T) {
	e := newAdminEnv(t)
	ip := "198.51.100.25"
	e.acc.Authorize(netip.MustParseAddr(ip), testToken)
	sid := e.login(t, ip)

	rec := e.call(http.MethodPost, "devices/revoke", ip, sid, `{"token":"`+testToken+`"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "последнее устройство") {
		t.Fatalf("revoking the only own device must be refused: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(http.MethodPost, "devices/revoke-owner", ip, sid, `{"owner":"`+access.Owner+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("revoking all own devices must be refused, got %d", rec.Code)
	}
	if _, ok := e.acc.ValidToken(testToken); !ok {
		t.Fatal("key must survive refused revokes")
	}

	if rec := e.call(http.MethodPost, "devices/add", ip, sid, `{"kind":"iphone"}`); rec.Code != http.StatusOK {
		t.Fatalf("add = %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(http.MethodPost, "devices/revoke", ip, sid, `{"token":"`+testToken+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("with a second own device the first can go, got %d %s", rec.Code, rec.Body)
	}
}
