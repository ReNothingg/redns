package dnsx

import (
	"strings"
	"sync"
	"time"
)

type Probes struct {
	mu sync.Mutex
	m  map[string]probeHit
}

type probeHit struct {
	proto string
	at    time.Time
}

const (
	probePrefix = "p-"
	maxProbes   = 10000
	probeTTL    = 2 * time.Minute
)

func NewProbes() *Probes {
	return &Probes{m: map[string]probeHit{}}
}

func ProbeNonce(label string) (string, bool) {
	n, ok := strings.CutPrefix(label, probePrefix)
	if !ok || len(n) < 8 || len(n) > 32 {
		return "", false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return "", false
		}
	}
	return n, true
}

func (p *Probes) record(name, proto string) {
	if p == nil {
		return
	}
	label, _, _ := strings.Cut(name, ".")
	nonce, ok := ProbeNonce(label)
	if !ok {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.m) >= maxProbes {
		for k, h := range p.m {
			if now.Sub(h.at) > probeTTL {
				delete(p.m, k)
			}
		}
		if len(p.m) >= maxProbes {
			return
		}
	}
	if _, ok := p.m[nonce]; !ok {
		p.m[nonce] = probeHit{proto: proto, at: now}
	}
}

func (p *Probes) Seen(nonce string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.m[nonce]
	if !ok || time.Since(h.at) > probeTTL {
		return "", false
	}
	return h.proto, true
}
