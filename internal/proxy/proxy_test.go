package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/dnsx"
	"github.com/renothingg/redns/internal/lists"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
)

func captureHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	cl, sv := net.Pipe()
	go func() {
		c := tls.Client(cl, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true})
		_ = c.Handshake()
	}()
	_ = sv.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, h, err := ReadClientHello(sv)
	sv.Close()
	cl.Close()
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerName != sni {
		t.Fatalf("sni = %q", h.ServerName)
	}
	return raw
}

func TestReadClientHello(t *testing.T) {
	raw := captureHello(t, "chatgpt.com", []string{"h2", "http/1.1"})
	_, h, err := ReadClientHello(bytes.NewReader(raw))
	if err != nil || h.ServerName != "chatgpt.com" || len(h.ALPN) != 2 || h.ALPN[0] != "h2" {
		t.Fatalf("hello = %+v err=%v", h, err)
	}
}

func TestFragmentedClientHello(t *testing.T) {
	raw := captureHello(t, "api.anthropic.com", nil)
	body := raw[5:]
	var frag []byte
	for i := 0; i < len(body); i += 7 {
		end := min(i+7, len(body))
		frag = append(frag, 22, 3, 1, 0, byte(end-i))
		frag = append(frag, body[i:end]...)
	}
	got, h, err := ReadClientHello(bytes.NewReader(frag))
	if err != nil || h.ServerName != "api.anthropic.com" {
		t.Fatalf("hello = %+v err=%v", h, err)
	}
	if !bytes.Equal(got, frag) {
		t.Fatal("consumed bytes must equal input for replay")
	}
}

func TestNotTLS(t *testing.T) {
	if _, _, err := ReadClientHello(strings.NewReader("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != ErrNotTLS {
		t.Fatalf("err = %v", err)
	}
}

type env struct {
	p        *Proxy
	acc      *access.Access
	st       *stats.Stats
	localTLS *Local
	tlsAddr  string
	httpAddr string
	dialed   []string
	mu       sync.Mutex
}

func newEnv(t *testing.T, mode string, backends map[string]string, forwards []config.Forward) *env {
	t.Helper()
	proxyList := lists.NewRules()
	for _, d := range []string{"example.com", "chatgpt.com", "brawlstarsgame.com", "clashofclans.com"} {
		proxyList.Add(lists.Rule{Kind: lists.Suffix, Value: d}, "")
	}
	pol := &dnsx.Policy{Host: "dns.test.net", Proxy: proxyList, Exclude: lists.NewRules()}
	strict := mode == "strict"
	if strict {
		mode = "private"
	}
	acc := access.New("dns.test.net", config.Access{Mode: mode, StrictProxy: strict, Tokens: []config.Token{{Name: "t", Token: "testtoken0123456"}}, AuthTTL: time.Hour}, state.Data{})
	e := &env{acc: acc, st: stats.New(0), localTLS: NewLocal(&net.TCPAddr{})}

	ips := map[string]netip.Addr{}
	routes := map[string]string{}
	i := 10
	for host, addr := range backends {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		i++
		ips[host] = ip
		routes[ip.String()] = addr
	}
	e.p = New(Options{
		Access: acc,
		Policy: func() *dnsx.Policy { return pol },
		Lookup: func(_ context.Context, host string, _ bool) ([]netip.Addr, error) {
			if ip, ok := ips[host]; ok {
				return []netip.Addr{ip}, nil
			}
			return nil, fmt.Errorf("nxdomain %s", host)
		},
		Stats:        e.st,
		Hints:        NewHints(forwards),
		Forwards:     forwards,
		AllowPrivate: true,
		LocalTLS:     e.localTLS,
		LocalHTTP:    NewLocal(&net.TCPAddr{}),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			e.mu.Lock()
			e.dialed = append(e.dialed, addr)
			e.mu.Unlock()
			real, ok := routes[host]
			if !ok {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, real)
		},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.tlsAddr = ln.Addr().String()
	ln.Close()
	if err := e.p.ServeTLS(e.tlsAddr); err != nil {
		t.Fatal(err)
	}
	ln, _ = net.Listen("tcp", "127.0.0.1:0")
	e.httpAddr = ln.Addr().String()
	ln.Close()
	if err := e.p.ServeHTTP(e.httpAddr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.p.Close() })
	return e
}

func TestSNIRelay(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.Host)
	}))
	defer backend.Close()
	e := newEnv(t, "public", map[string]string{"chatgpt.com": backend.Listener.Addr().String()}, nil)

	conn, err := tls.Dial("tcp", e.tlsAddr, &tls.Config{ServerName: "chatgpt.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(conn)
	if !strings.Contains(string(body), "hello from chatgpt.com") {
		t.Fatalf("response = %q", body)
	}
	if !strings.HasSuffix(e.dialed[0], ":443") {
		t.Fatalf("dialed %v", e.dialed)
	}
}

func TestSNIDeniedGoesLocal(t *testing.T) {
	e := newEnv(t, "public", nil, nil)
	go func() {
		c, err := tls.Dial("tcp", e.tlsAddr, &tls.Config{ServerName: "not-in-list.org", InsecureSkipVerify: true})
		if err == nil {
			c.Close()
		}
	}()
	select {
	case c := <-e.localTLS.ch:
		raw, h, err := ReadClientHello(c)
		if err != nil || h.ServerName != "not-in-list.org" || len(raw) == 0 {
			t.Fatalf("local got %+v %v", h, err)
		}
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("denied SNI was not handed to the local server")
	}
	if e.st.ConnsDenied.Load() != 1 {
		t.Fatal("denied counter")
	}
}

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (a addrConn) RemoteAddr() net.Addr { return a.remote }

func TestPrivateModeRelaysListedNamesForNewIPs(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "relayed")
	}))
	defer backend.Close()
	e := newEnv(t, "private", map[string]string{"chatgpt.com": backend.Listener.Addr().String()}, nil)
	cl, sv := net.Pipe()
	go e.p.handleTLS(addrConn{sv, &net.TCPAddr{IP: net.ParseIP("198.51.100.99"), Port: 1}})
	c := tls.Client(cl, &tls.Config{ServerName: "chatgpt.com", InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(c)
	if !strings.Contains(string(body), "relayed") {
		t.Fatalf("listed name must be relayed for an unknown IP: %q", body)
	}
}

func TestStrictProxyRequiresAuthorization(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "relayed")
	}))
	defer backend.Close()
	e := newEnv(t, "strict", map[string]string{"chatgpt.com": backend.Listener.Addr().String()}, nil)
	stranger := &net.TCPAddr{IP: net.ParseIP("198.51.100.23"), Port: 5555}

	connect := func() (*tls.Conn, error) {
		cl, sv := net.Pipe()
		go e.p.handleTLS(addrConn{sv, stranger})
		c := tls.Client(cl, &tls.Config{ServerName: "chatgpt.com", InsecureSkipVerify: true})
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		return c, c.Handshake()
	}

	go func() {
		if c, err := connect(); err == nil {
			c.Close()
		}
	}()
	select {
	case c := <-e.localTLS.ch:
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("unauthorized client must be handed to the local server")
	}

	tok, _ := e.acc.ValidToken("testtoken0123456")
	e.acc.Authorize(netip.MustParseAddr("198.51.100.23"), tok)
	c, err := connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(c)
	if !strings.Contains(string(body), "relayed") {
		t.Fatalf("authorized client was not relayed: %q", body)
	}
}

func TestHTTPRelay(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain %s %s", r.Host, r.URL.Path)
	}))
	defer backend.Close()
	e := newEnv(t, "public", map[string]string{"example.com": backend.Listener.Addr().String()}, nil)
	c, err := net.Dial("tcp", e.httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /ok HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain example.com /ok" {
		t.Fatalf("body = %q", body)
	}
	if !strings.HasSuffix(e.dialed[0], ":80") {
		t.Fatalf("dialed %v", e.dialed)
	}
}

func echoServer(t *testing.T, tag string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				fmt.Fprintf(c, "%s:%s", tag, buf[:n])
			}()
		}
	}()
	return ln.Addr().String()
}

func TestForwardRoutesByHint(t *testing.T) {
	bs := echoServer(t, "brawl")
	coc := echoServer(t, "coc")
	fw := []config.Forward{{
		Port: 0, TargetPort: 9339, Default: "game.brawlstarsgame.com",
		Targets: []string{"game.brawlstarsgame.com", "gamea.clashofclans.com"}, HintTTL: time.Hour,
	}}
	e := newEnv(t, "public", map[string]string{"game.brawlstarsgame.com": bs, "gamea.clashofclans.com": coc}, fw)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.p.accept(ln, func(c net.Conn) { e.p.handleForward(c, fw[0]) })
	defer ln.Close()

	talk := func() string {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("hi"))
		b, _ := io.ReadAll(c)
		return string(b)
	}
	if got := talk(); got != "brawl:hi" {
		t.Fatalf("default route = %q", got)
	}
	e.p.o.Hints.Hint(netip.MustParseAddr("127.0.0.1"), "gamea.clashofclans.com")
	if got := talk(); got != "coc:hi" {
		t.Fatalf("hinted route = %q", got)
	}
	e.p.o.Hints.Hint(netip.MustParseAddr("127.0.0.1"), "chatgpt.com")
	if got := talk(); got != "coc:hi" {
		t.Fatalf("unrelated name changed route: %q", got)
	}
}

func TestForbiddenTargets(t *testing.T) {
	p := New(Options{SelfIPs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}})
	for addr, want := range map[string]bool{
		"8.8.8.8":         false,
		"10.0.0.1":        true,
		"127.0.0.1":       true,
		"169.254.1.1":     true,
		"100.64.0.1":      true,
		"203.0.113.10":    true,
		"::1":             true,
		"fd00::1":         true,
		"2606:4700::1":    false,
		"::ffff:10.0.0.1": true,
	} {
		if got := p.forbidden(netip.MustParseAddr(addr)); got != want {
			t.Errorf("forbidden(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestHappyEyeballsSkipsDeadAddress(t *testing.T) {
	good := echoServer(t, "ok")
	p := New(Options{
		AllowPrivate: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "192.0.2.1:") {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			var d net.Dialer
			return d.DialContext(ctx, network, good)
		},
	})
	start := time.Now()
	c, err := p.happyEyeballs(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}
