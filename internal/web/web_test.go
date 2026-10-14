package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/state"
)

const testToken = "webtesttoken12345"

func TestAgreementIsPlainText(t *testing.T) {
	a := Agreement("dns.example.com")
	if a == "" || strings.Contains(a, "**") || strings.Contains(a, "{host}") || !strings.Contains(a, "dns.example.com") {
		t.Fatalf("agreement must be plain text with the host filled in:\n%s", a)
	}
}

func newTestWeb(t *testing.T) (*Web, *access.Access) {
	t.Helper()
	acc := access.New("dns.example.com", config.Access{
		Mode: "private", Tokens: []config.Token{{Name: "me", Token: testToken}}, AuthTTL: time.Hour,
	}, state.Data{})
	store, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := New(Options{
		Host: "dns.example.com", IPv4: "203.0.113.10", Access: acc,
		DoH: http.NotFoundHandler(), Store: store, Apply: func(d state.Data) {},
		PasswordHash: func() string { return "$2a$04$abcdefghijklmnopqrstuuJ5v0ZyVZ0p6sCqk3Yz1t1yC9c9v7l1e" },
	})
	return w, acc
}

func get(h http.Handler, path, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://dns.example.com"+path, nil)
	r.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAdminHiddenFromStrangers(t *testing.T) {
	w, acc := newTestWeb(t)
	h := w.HTTPS()
	if rec := get(h, "/admin", "198.51.100.7"); rec.Code != http.StatusNotFound {
		t.Fatalf("stranger must get 404, got %d", rec.Code)
	}
	acc.Authorize(netip.MustParseAddr("198.51.100.7"), testToken)
	rec := get(h, "/admin", "198.51.100.7")
	if rec.Code != http.StatusOK {
		t.Fatalf("own device must see the admin login, got %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP = %q", csp)
	}
	if rec.Header().Get("Strict-Transport-Security") == "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	if strings.Contains(rec.Body.String(), "style=\"") {
		t.Fatal("inline styles would be blocked by CSP")
	}
}

func TestKeyGuessingIsThrottled(t *testing.T) {
	w, _ := newTestWeb(t)
	h := w.HTTPS()
	ip := "198.51.100.8"
	if rec := get(h, "/setup/"+testToken, ip); rec.Code != http.StatusOK {
		t.Fatalf("valid key = %d", rec.Code)
	}
	for i := 0; i < 10; i++ {
		get(h, "/setup/wrongkey00000000"+string(rune('a'+i)), ip)
	}
	if rec := get(h, "/setup/"+testToken, ip); rec.Code != http.StatusNotFound {
		t.Fatalf("after 10 wrong keys even the right one must be refused for a while, got %d", rec.Code)
	}
	if rec := get(h, "/setup/"+testToken, "198.51.100.9"); rec.Code != http.StatusOK {
		t.Fatalf("other IPs are not affected, got %d", rec.Code)
	}
}
