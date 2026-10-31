package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/state"
)

const testTok = "abcdefgh12345678"

func testWeb(mode string, st state.Data) *Web {
	acc := access.New("dns.example.com", config.Access{Mode: mode, Tokens: []config.Token{{Name: "me", Token: testTok}}}, st)
	return New(Options{Host: "dns.example.com", IPv4: "192.0.2.1", IPv6: "2001:db8::2", Access: acc, DoH: http.NotFoundHandler()})
}

func get(t *testing.T, w *Web, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://dns.example.com"+path, nil)
	req.RemoteAddr = "198.51.100.7:5000"
	rec := httptest.NewRecorder()
	w.HTTPS().ServeHTTP(rec, req)
	return rec
}

func TestWindowsScript(t *testing.T) {
	b := string(WindowsScript(WindowsParams{
		Mode: "install", Host: "dns.example.com", DoHURL: "https://dns.example.com/dns-query/" + testTok,
		ScriptURL: "https://dns.example.com/setup/" + testTok + "/windows.ps1",
		IPv4:      "192.0.2.1", IPv6: "2001:db8::2", Label: "Pavel's PC",
	}))
	for _, want := range []string{
		"$Mode = 'install'",
		"$Template = 'https://dns.example.com/dns-query/" + testTok + "'",
		"$Server4 = '192.0.2.1'",
		"$Server6 = '2001:db8::2'",
		"$Label = 'Pavel''s PC'",
		"-AllowFallbackToUdp $false",
		"\r\n    Invoke-ReDNS\r\n",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(b, "{{") || strings.Contains(b, "<no value>") {
		t.Error("unrendered template")
	}
	if strings.Contains(strings.ReplaceAll(b, "\r\n", ""), "\n") {
		t.Error("script has bare LF")
	}
}

func TestPSQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":     "'plain'",
		"it's":      "'it''s'",
		"a’b":       "'a''b'",
		"x\ny\r":    "'x y'",
		"$(rm -rf)": "'$(rm -rf)'",
	} {
		if got := psq(in); got != want {
			t.Errorf("psq(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestWindowsRoutes(t *testing.T) {
	w := testWeb("private", state.Data{})

	rec := get(t, w, "/setup/"+testTok+"/windows.ps1")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; charset=utf-8") {
		t.Fatalf("script: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "$Mode = 'install'") || !strings.Contains(body, "/dns-query/"+testTok+"'") || !strings.Contains(body, "/setup/"+testTok+"/windows.ps1'") {
		t.Fatal("script lacks key or self URL")
	}

	if body := get(t, w, "/setup/"+testTok+"/windows-remove.ps1").Body.String(); !strings.Contains(body, "$Mode = 'remove'") {
		t.Fatal("remove script mode")
	}

	rec = get(t, w, "/setup/"+testTok+"/ReDNS-Windows.cmd")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "ReDNS-Windows.cmd") {
		t.Fatalf("cmd: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "irm 'https://dns.example.com/setup/"+testTok+"/windows.ps1' | iex") {
		t.Fatal("cmd does not fetch the script")
	}

	if code := get(t, w, "/setup/windows.ps1").Code; code != http.StatusNotFound {
		t.Fatalf("private keyless script: %d", code)
	}
	if code := get(t, w, "/setup/wrongkey00000000/windows.ps1").Code; code != http.StatusNotFound {
		t.Fatalf("bad key: %d", code)
	}

	page := get(t, w, "/setup/"+testTok).Body.String()
	if !strings.Contains(page, "irm https://dns.example.com/setup/"+testTok+"/windows.ps1 | iex") {
		t.Fatal("setup page lacks install command")
	}
}

func TestWindowsRoutesOtherKinds(t *testing.T) {
	ios := "ios0000000000001"
	w := testWeb("private", state.Data{Tokens: []state.Token{{Name: "phone", Kind: "iphone", Token: ios}}})
	if code := get(t, w, "/setup/"+ios+"/windows.ps1").Code; code != http.StatusNotFound {
		t.Fatalf("iphone key gets windows script: %d", code)
	}

	pub := testWeb("public", state.Data{})
	rec := get(t, pub, "/setup/windows.ps1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "$Template = 'https://dns.example.com/dns-query'") {
		t.Fatalf("public script: %d", rec.Code)
	}
}
