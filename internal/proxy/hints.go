package proxy

import (
	"net/netip"
	"sync"
	"time"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/lists"
)

type Hints struct {
	forwards []hintForward
	mu       sync.Mutex
	m        map[hintKey]hintVal
	now      func() time.Time
}

type hintForward struct {
	port  int
	rules *lists.Rules
	ttl   time.Duration
}

type hintKey struct {
	client netip.Prefix
	port   int
}

type hintVal struct {
	name    string
	expires time.Time
}

func NewHints(forwards []config.Forward) *Hints {
	h := &Hints{m: map[hintKey]hintVal{}, now: time.Now}
	for _, f := range forwards {
		r := lists.NewRules()
		for _, t := range f.Targets {
			for _, rule := range lists.ParseLine(t) {
				r.Add(rule, "")
			}
		}
		if f.Default != "" {
			for _, rule := range lists.ParseLine("full:" + f.Default) {
				r.Add(rule, "")
			}
		}
		h.forwards = append(h.forwards, hintForward{port: f.Port, rules: r, ttl: f.HintTTL})
	}
	return h
}

func (h *Hints) Hint(client netip.Addr, name string) {
	if h == nil || len(h.forwards) == 0 {
		return
	}
	now := h.now()
	k := access.Key(client)
	for _, f := range h.forwards {
		if _, ok := f.rules.Match(name); !ok {
			continue
		}
		key := hintKey{k, f.port}
		h.mu.Lock()
		if _, ok := h.m[key]; ok || len(h.m) < 1_000_000 {
			h.m[key] = hintVal{name, now.Add(f.ttl)}
		}
		h.mu.Unlock()
	}
}

func (h *Hints) Get(client netip.Addr, port int) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.m[hintKey{access.Key(client), port}]
	if !ok || h.now().After(v.expires) {
		return "", false
	}
	return v.name, true
}

func (h *Hints) GC() {
	now := h.now()
	h.mu.Lock()
	for k, v := range h.m {
		if now.After(v.expires) {
			delete(h.m, k)
		}
	}
	h.mu.Unlock()
}
