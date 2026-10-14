package dnsx

import (
	"net/netip"
	"sync"
	"time"

	"github.com/renothingg/redns/internal/access"
)

type Limiter struct {
	rate  float64
	burst float64
	mu    sync.Mutex
	m     map[netip.Prefix]*bucket
	now   func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewLimiter(qps int) *Limiter {
	if qps <= 0 {
		return nil
	}
	return &Limiter{rate: float64(qps), burst: float64(qps) * 4, m: map[netip.Prefix]*bucket{}, now: time.Now}
}

func (l *Limiter) Allow(ip netip.Addr) bool {
	if l == nil {
		return true
	}
	k := access.Key(ip)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[k]
	if b == nil {
		if len(l.m) > 500000 {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[k] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) GC() {
	if l == nil {
		return
	}
	now := l.now()
	l.mu.Lock()
	for k, b := range l.m {
		if now.Sub(b.last) > time.Minute {
			delete(l.m, k)
		}
	}
	l.mu.Unlock()
}
