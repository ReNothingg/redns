package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/renothingg/redns/internal/access"
)

const (
	certTTL       = 12 * time.Hour
	certErrTTL    = 5 * time.Minute
	certProbeTime = 2 * time.Second
	isolateQuiet  = 120 * time.Millisecond
	isolateWait   = 700 * time.Millisecond
	isolatePoll   = 20 * time.Millisecond
	isolateSettle = 25 * time.Millisecond
)

type certKey struct {
	host string
	port int
	exit string
}

type certEntry struct {
	leaf    *x509.Certificate
	expires time.Time
}

type certCache struct {
	mu sync.Mutex
	m  map[certKey]certEntry
}

func (p *Proxy) leaf(ctx context.Context, k certKey) *x509.Certificate {
	now := time.Now()
	p.certs.mu.Lock()
	e, ok := p.certs.m[k]
	p.certs.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.leaf
	}
	ctx, cancel := context.WithTimeout(ctx, certProbeTime)
	defer cancel()
	e = certEntry{expires: now.Add(certErrTTL)}
	if c, err := p.dial(ctx, k.host, k.port, k.exit); err == nil {
		tc := tls.Client(c, &tls.Config{ServerName: k.host, InsecureSkipVerify: true})
		if err := tc.HandshakeContext(ctx); err == nil {
			if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
				e = certEntry{leaf: certs[0], expires: now.Add(certTTL)}
			}
		}
		c.Close()
	}
	p.certs.mu.Lock()
	if p.certs.m == nil {
		p.certs.m = map[certKey]certEntry{}
	}
	if len(p.certs.m) > 4096 {
		for old, v := range p.certs.m {
			if now.After(v.expires) {
				delete(p.certs.m, old)
			}
		}
	}
	p.certs.m[k] = e
	p.certs.mu.Unlock()
	return e.leaf
}

func sameZone(a, b string) bool {
	_, pa, ok := strings.Cut(a, ".")
	if !ok {
		return false
	}
	return b == pa || strings.HasSuffix(b, "."+pa)
}

func (p *Proxy) Isolate(ctx context.Context, client netip.Addr, name string) {
	k := access.Key(client)
	type cand struct {
		c net.Conn
		m connMeta
	}
	var cands []cand
	p.mu.Lock()
	if cs := p.clients[k]; cs != nil {
		for c, m := range cs.conns {
			if m.port == p.o.TLSPort && m.host != name && sameZone(name, m.host) {
				cands = append(cands, cand{c, m})
			}
		}
	}
	p.mu.Unlock()
	if len(cands) == 0 {
		return
	}
	covers := map[certKey]bool{}
	var victims []net.Conn
	for _, x := range cands {
		ck := certKey{x.m.host, x.m.port, x.m.exit}
		v, ok := covers[ck]
		if !ok {
			leaf := p.leaf(ctx, ck)
			v = leaf != nil && leaf.VerifyHostname(name) == nil
			covers[ck] = v
		}
		if v {
			victims = append(victims, x.c)
		}
	}
	if len(victims) == 0 {
		return
	}
	deadline := time.Now().Add(isolateWait)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		busy := false
		for _, c := range victims {
			if d, ok := idleFor(c); ok && d < isolateQuiet {
				busy = true
				break
			}
		}
		if !busy {
			break
		}
		time.Sleep(isolatePoll)
	}
	for _, c := range victims {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		c.Close()
	}
	slog.Info("isolated", "client", k.String(), "name", name, "closed", len(victims))
	time.Sleep(isolateSettle)
}
