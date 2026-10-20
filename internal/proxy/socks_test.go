package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/renothingg/redns/internal/config"
)

func fakeSocks(t *testing.T, gotHost chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 3)
		io.ReadFull(c, buf)
		c.Write([]byte{5, 0})
		head := make([]byte, 5)
		io.ReadFull(c, head)
		name := make([]byte, head[4])
		io.ReadFull(c, name)
		pb := make([]byte, 2)
		io.ReadFull(c, pb)
		gotHost <- string(name) + ":" + itoa(int(binary.BigEndian.Uint16(pb)))
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		line := make([]byte, 4)
		io.ReadFull(c, line)
		c.Write(bytes.ToUpper(line))
	}()
	return ln.Addr().String()
}

func itoa(n int) string {
	return string([]byte{byte('0' + n/100%10), byte('0' + n/10%10), byte('0' + n%10)})
}

func TestSocksExit(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeSocks(t, got)
	p := New(Options{Exits: map[string]string{"warp": "socks5://" + addr}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	up, err := p.dial(ctx, "login.unity.com", 443, "warp")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if h := <-got; h != "login.unity.com:443" {
		t.Fatalf("socks target = %q", h)
	}
	up.Write([]byte("ping"))
	resp := make([]byte, 4)
	if _, err := io.ReadFull(up, resp); err != nil || string(resp) != "PING" {
		t.Fatalf("relay = %q, %v", resp, err)
	}
}

func TestSocksExitConfig(t *testing.T) {
	if s, ok := config.SocksExit("socks5://127.0.0.1:40000"); !ok || s != "127.0.0.1:40000" {
		t.Fatalf("got %q %v", s, ok)
	}
	if s, ok := config.SocksExit("socks5://127.0.0.1"); !ok || s != "127.0.0.1:1080" {
		t.Fatalf("got %q %v", s, ok)
	}
	if _, ok := config.SocksExit("198.51.100.7"); ok {
		t.Fatal("plain exit treated as socks")
	}
}
