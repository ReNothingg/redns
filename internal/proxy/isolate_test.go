package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/renothingg/redns/internal/stats"
)

func tlsServer(t *testing.T, names ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
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
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func connPair(t *testing.T) (proxySide, clientSide net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	clientSide, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxySide, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxySide.Close(); clientSide.Close() })
	return proxySide, clientSide
}

func closed(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return err != nil
}

func TestIsolateClosesCoveringConns(t *testing.T) {
	wild := tlsServer(t, "example.test", "*.example.test")
	narrow := tlsServer(t, "api.example.test")
	p := New(Options{
		Stats: stats.New(0),
		Exits: map[string]string{"wild": wild, "narrow": narrow},
	})
	me, other := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")
	add := func(ip netip.Addr, host string, port int, exit string) net.Conn {
		ps, cs := connPair(t)
		if !p.acquire(ip, ps, host, port, exit) {
			t.Fatal("acquire failed")
		}
		return cs
	}
	covering := add(me, "platform.example.test", 443, "wild")
	apex := add(me, "example.test", 443, "wild")
	narrowConn := add(me, "api.example.test", 443, "narrow")
	same := add(me, "developers.example.test", 443, "wild")
	plain := add(me, "platform.example.test", 80, "wild")
	foreign := add(other, "platform.example.test", 443, "wild")
	otherZone := add(me, "platform.elsewhere.test", 443, "wild")

	p.Isolate(context.Background(), me, "developers.example.test")

	for name, c := range map[string]net.Conn{"covering": covering, "apex": apex} {
		if !closed(c) {
			t.Errorf("%s connection is still open", name)
		}
	}
	for name, c := range map[string]net.Conn{
		"narrow cert": narrowConn, "same name": same, "port 80": plain,
		"other client": foreign, "other zone": otherZone,
	} {
		if closed(c) {
			t.Errorf("%s connection was closed", name)
		}
	}
}

func TestSameZone(t *testing.T) {
	for _, c := range []struct {
		name, host string
		want       bool
	}{
		{"developers.openai.com", "platform.openai.com", true},
		{"developers.openai.com", "openai.com", true},
		{"developers.openai.com", "a.b.openai.com", true},
		{"developers.openai.com", "chatgpt.com", false},
		{"developers.openai.com", "notopenai.com", false},
		{"localhost", "localhost", false},
	} {
		if got := sameZone(c.name, c.host); got != c.want {
			t.Errorf("sameZone(%q, %q) = %v, want %v", c.name, c.host, got, c.want)
		}
	}
}
