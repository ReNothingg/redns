package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/bcrypt"

	"github.com/renothingg/redns/internal/config"
)

const itToken = "integration0token1"

func freePort(t *testing.T, udp bool) string {
	t.Helper()
	if udp {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func fakeUpstream(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

type itEnv struct {
	dns, dot, doq, https, http, admin string
	stateFile                         string
}

const adminPassword = "test-admin-pass"

var adminHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

func startApp(t *testing.T, mode string) itEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ai.txt"), []byte("chatgpt.com\nclaude.ai\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "block.txt"), []byte("||ads.example^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := itEnv{
		dns: freePort(t, true), dot: freePort(t, false), doq: freePort(t, true),
		https: freePort(t, false), http: freePort(t, false), admin: freePort(t, false),
	}
	cfgText := fmt.Sprintf(`
hostname: dns.test.net
public_ipv4: "198.51.100.53"
access:
  mode: %s
  tokens: [{name: it, token: %s}]
listen: {dns: %q, dot: %q, doq: %q, https: %q, http: %q, admin: %q}
tls: {acme: false, self_signed: true}
upstream: {servers: [%q], fallback: [], ecs: true, timeout: 1s}
proxy:
  lists: [ai.txt]
  forwards: []
block: {enabled: true, lists: [block.txt]}
lists: {refresh: 0s, cache_dir: %q}
log: {level: error, querylog_size: 100}
admin: {password_hash: %q}
state_file: %q
`, mode, itToken, e.dns, e.dot, e.doq, e.https, e.http, e.admin, fakeUpstream(t), filepath.Join(dir, "cache"), adminHash, filepath.Join(dir, "state.json"))
	e.stateFile = filepath.Join(dir, "state.json")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := New(ctx, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		sctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		a.Shutdown(sctx)
		c()
	})
	time.Sleep(100 * time.Millisecond)
	return e
}

func aOf(t *testing.T, m *dns.Msg) string {
	t.Helper()
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

func q(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func TestIntegrationPublic(t *testing.T) {
	e := startApp(t, "public")

	for _, netw := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: netw, Timeout: 2 * time.Second}
		m, _, err := c.Exchange(q("chatgpt.com"), e.dns)
		if err != nil || aOf(t, m) != "198.51.100.53" {
			t.Fatalf("%s proxied: %v %v", netw, m, err)
		}
		m, _, err = c.Exchange(q("example.org"), e.dns)
		if err != nil || aOf(t, m) != "192.0.2.1" {
			t.Fatalf("%s forward: %v %v", netw, m, err)
		}
		m, _, err = c.Exchange(q("x.ads.example"), e.dns)
		if err != nil || aOf(t, m) != "0.0.0.0" {
			t.Fatalf("%s block: %v %v", netw, m, err)
		}
	}

	dot := &dns.Client{Net: "tcp-tls", Timeout: 2 * time.Second, TLSConfig: &tls.Config{ServerName: "dns.test.net", InsecureSkipVerify: true}}
	if m, _, err := dot.Exchange(q("claude.ai"), e.dot); err != nil || aOf(t, m) != "198.51.100.53" {
		t.Fatalf("dot: %v %v", m, err)
	}

	if m := doqExchange(t, e.doq, "dns.test.net", q("chatgpt.com")); aOf(t, m) != "198.51.100.53" {
		t.Fatalf("doq: %v", m)
	}

	hc := httpsClient(e.https, "dns.test.net")
	raw, _ := q("chatgpt.com").Pack()
	resp, err := hc.Get("https://dns.test.net/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpackResp(t, resp); aOf(t, m) != "198.51.100.53" {
		t.Fatalf("doh get: %v", m)
	}
	resp, err = hc.Post("https://dns.test.net/dns-query", "application/dns-message", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("DoH should negotiate HTTP/2, got %s", resp.Proto)
	}
	if m := unpackResp(t, resp); aOf(t, m) != "198.51.100.53" {
		t.Fatalf("doh post: %v", m)
	}

	resp, err = hc.Get("https://dns.test.net/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ReDNS") {
		t.Fatalf("landing: %d", resp.StatusCode)
	}
	resp, err = hc.Get("https://dns.test.net/setup/redns.mobileconfig")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("profile content type %q", resp.Header.Get("Content-Type"))
	}
	if err := xml.Unmarshal(body, new(struct{})); err != nil {
		t.Fatalf("profile is not XML: %v", err)
	}
	for _, want := range []string{"https://dns.test.net/dns-query", "<string>HTTPS</string>", "<string>TLS</string>", "198.51.100.53", "ConsentText", "СОГЛАШЕНИЕ"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("profile lacks %q: %s", want, body)
		}
	}

	conn, err := tls.Dial("tcp", e.https, &tls.Config{ServerName: "not-listed.org", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "dns.test.net" {
		t.Fatalf("fallback cert CN = %q", cn)
	}
	conn.Close()

	resp, err = http.Get("http://" + e.admin + "/check?name=api.chatgpt.com")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"proxy"`) {
		t.Fatalf("admin check: %s", body)
	}
}

func TestIntegrationPrivate(t *testing.T) {
	e := startApp(t, "private")
	hc := httpsClient(e.https, "dns.test.net")

	raw, _ := q("chatgpt.com").Pack()
	resp, err := hc.Post("https://dns.test.net/dns-query/"+itToken, "application/dns-message", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpackResp(t, resp); aOf(t, m) != "198.51.100.53" {
		t.Fatalf("doh with token: %v", m)
	}
	resp, err = hc.Post("https://dns.test.net/dns-query/wrongtoken12345", "application/dns-message", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("bad token must 404, got %d", resp.StatusCode)
	}

	resp, err = hc.Get("https://dns.test.net/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("private landing must 404, got %d", resp.StatusCode)
	}
	resp, err = hc.Get("https://dns.test.net/setup/" + itToken)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "/dns-query/"+itToken) {
		t.Fatal("setup page must show the DoH URL with the key")
	}
	if strings.Contains(string(body), itToken+".dns.test.net") {
		t.Fatal("the key must never be put into a host name: it would end up in public certificate logs")
	}
	resp, err = hc.Get("https://dns.test.net/setup/" + itToken + "/redns.mobileconfig")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "<string>HTTPS</string>") || strings.Contains(string(body), "<string>TLS</string>") {
		t.Fatalf("private profile must be DoH only: %s", body)
	}

	dot := &dns.Client{Net: "tcp-tls", Timeout: 2 * time.Second, TLSConfig: &tls.Config{ServerName: itToken + ".dns.test.net", InsecureSkipVerify: true}}
	if m, _, err := dot.Exchange(q("claude.ai"), e.dot); err != nil || aOf(t, m) != "198.51.100.53" {
		t.Fatalf("dot token: %v %v", m, err)
	}
}

func httpsClient(addr, host string) *http.Client {
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}

func unpackResp(t *testing.T, resp *http.Response) *dns.Msg {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("doh status %d %q: %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		t.Fatal(err)
	}
	return m
}

func doqExchange(t *testing.T, addr, sni string, m *dns.Msg) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m.Id = 0
	raw, _ := m.Pack()
	buf := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(buf, uint16(len(raw)))
	copy(buf[2:], raw)
	if _, err := st.Write(buf); err != nil {
		t.Fatal(err)
	}
	st.Close()
	resp, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) < 2 {
		t.Fatal("short doq response")
	}
	out := new(dns.Msg)
	if err := out.Unpack(resp[2:]); err != nil {
		t.Fatal(err)
	}
	return out
}

func adminCall(t *testing.T, hc *http.Client, method, path string, body any, header bool) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, "https://dns.test.net/admin/api/"+path, rd)
	if header {
		req.Header.Set("X-ReDNS", "1")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestIntegrationAdmin(t *testing.T) {
	e := startApp(t, "private")
	hc := httpsClient(e.https, "dns.test.net")
	hc.Jar, _ = cookiejar.New(nil)

	resp, err := hc.Get("https://dns.test.net/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin page status %d", resp.StatusCode)
	}
	if code, _ := adminCall(t, hc, "GET", "overview", nil, false); code != 401 {
		t.Fatalf("overview without session = %d", code)
	}
	if code, _ := adminCall(t, hc, "POST", "login", map[string]string{"password": adminPassword}, false); code != 403 {
		t.Fatalf("login without CSRF header = %d", code)
	}
	if code, _ := adminCall(t, hc, "POST", "login", map[string]string{"password": "nope"}, true); code != 401 {
		t.Fatalf("wrong password = %d", code)
	}
	if code, _ := adminCall(t, hc, "POST", "login", map[string]string{"password": adminPassword}, true); code != 200 {
		t.Fatalf("login = %d", code)
	}

	code, raw := adminCall(t, hc, "POST", "devices/add", map[string]string{"name": "iPad"}, true)
	var dev struct {
		Token    string `json:"token"`
		SetupURL string `json:"setup_url"`
	}
	if code != 200 || json.Unmarshal(raw, &dev) != nil || dev.Token == "" {
		t.Fatalf("add device = %d %s", code, raw)
	}
	q, _ := q("chatgpt.com").Pack()
	resp, err = hc.Post("https://dns.test.net/dns-query/"+dev.Token, "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpackResp(t, resp); aOf(t, m) != "198.51.100.53" {
		t.Fatal("new device token must work for DoH")
	}

	if code, _ := adminCall(t, hc, "POST", "bans/add", map[string]string{"target": "127.0.0.1"}, true); code != 400 {
		t.Fatalf("banning yourself must be refused, got %d", code)
	}
	if code, raw := adminCall(t, hc, "POST", "bans/add", map[string]string{"target": "198.51.100.0/24", "reason": "leech"}, true); code != 200 {
		t.Fatalf("ban = %d %s", code, raw)
	}
	if code, _ := adminCall(t, hc, "POST", "settings", map[string]bool{"strict_proxy": true}, true); code != 200 {
		t.Fatal("settings")
	}
	code, raw = adminCall(t, hc, "GET", "overview", nil, false)
	var ov struct {
		Strict bool                      `json:"strict"`
		Bans   []struct{ Prefix string } `json:"bans"`
	}
	if code != 200 || json.Unmarshal(raw, &ov) != nil || !ov.Strict || len(ov.Bans) != 1 {
		t.Fatalf("overview = %d %s", code, raw)
	}
	code, raw = adminCall(t, hc, "GET", "clients", nil, false)
	if code != 200 || !bytes.Contains(raw, []byte(`"you":true`)) {
		t.Fatalf("clients = %d %s", code, raw)
	}
	saved, err := os.ReadFile(e.stateFile)
	if err != nil || !bytes.Contains(saved, []byte("198.51.100.0/24")) || !bytes.Contains(saved, []byte(dev.Token)) {
		t.Fatalf("state not persisted: %s %v", saved, err)
	}

	if code, _ := adminCall(t, hc, "POST", "devices/revoke", map[string]string{"token": dev.Token}, true); code != 200 {
		t.Fatal("revoke")
	}
	resp, err = hc.Post("https://dns.test.net/dns-query/"+dev.Token, "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("revoked token must stop working, got %d", resp.StatusCode)
	}

	stranger := httpsClient(e.https, "dns.test.net")
	stranger.Jar, _ = cookiejar.New(nil)
	for i := 0; i < 5; i++ {
		adminCall(t, stranger, "POST", "login", map[string]string{"password": "guess"}, true)
	}
	if code, _ := adminCall(t, stranger, "POST", "login", map[string]string{"password": adminPassword}, true); code != 429 {
		t.Fatalf("brute force must be locked out, got %d", code)
	}
}
