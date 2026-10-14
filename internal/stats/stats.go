package stats

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	Started time.Time

	Queries      atomic.Uint64
	ByProto      sync.Map
	Proxied      atomic.Uint64
	Blocked      atomic.Uint64
	Forwarded    atomic.Uint64
	CacheHits    atomic.Uint64
	StaleServed  atomic.Uint64
	UpstreamErrs atomic.Uint64
	Refused      atomic.Uint64
	RateLimited  atomic.Uint64

	ConnsTotal  atomic.Uint64
	ConnsActive atomic.Int64
	ConnsDenied atomic.Uint64
	DialErrors  atomic.Uint64
	BytesUp     atomic.Uint64
	BytesDown   atomic.Uint64

	topMu sync.Mutex
	top   map[string]uint64

	log *QueryLog
}

func New(queryLogSize int) *Stats {
	return &Stats{Started: time.Now(), top: map[string]uint64{}, log: NewQueryLog(queryLogSize)}
}

func (s *Stats) Proto(p string) {
	v, _ := s.ByProto.LoadOrStore(p, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

func (s *Stats) ProxiedConn(name string) {
	s.ConnsTotal.Add(1)
	s.topMu.Lock()
	if _, ok := s.top[name]; ok || len(s.top) < 5000 {
		s.top[name]++
	}
	s.topMu.Unlock()
}

func (s *Stats) Log() *QueryLog { return s.log }

type Count struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type Snapshot struct {
	Uptime       string            `json:"uptime"`
	Queries      uint64            `json:"queries"`
	ByProto      map[string]uint64 `json:"by_proto"`
	Proxied      uint64            `json:"proxied_answers"`
	Blocked      uint64            `json:"blocked"`
	Forwarded    uint64            `json:"forwarded"`
	CacheHits    uint64            `json:"cache_hits"`
	StaleServed  uint64            `json:"stale_served"`
	UpstreamErrs uint64            `json:"upstream_errors"`
	Refused      uint64            `json:"refused"`
	RateLimited  uint64            `json:"rate_limited"`
	ConnsTotal   uint64            `json:"proxy_conns_total"`
	ConnsActive  int64             `json:"proxy_conns_active"`
	ConnsDenied  uint64            `json:"proxy_conns_denied"`
	DialErrors   uint64            `json:"proxy_dial_errors"`
	BytesUp      uint64            `json:"proxy_bytes_up"`
	BytesDown    uint64            `json:"proxy_bytes_down"`
	TopProxied   []Count           `json:"top_proxied"`
}

func (s *Stats) Snapshot() Snapshot {
	snap := Snapshot{
		Uptime:       time.Since(s.Started).Round(time.Second).String(),
		Queries:      s.Queries.Load(),
		ByProto:      map[string]uint64{},
		Proxied:      s.Proxied.Load(),
		Blocked:      s.Blocked.Load(),
		Forwarded:    s.Forwarded.Load(),
		CacheHits:    s.CacheHits.Load(),
		StaleServed:  s.StaleServed.Load(),
		UpstreamErrs: s.UpstreamErrs.Load(),
		Refused:      s.Refused.Load(),
		RateLimited:  s.RateLimited.Load(),
		ConnsTotal:   s.ConnsTotal.Load(),
		ConnsActive:  s.ConnsActive.Load(),
		ConnsDenied:  s.ConnsDenied.Load(),
		DialErrors:   s.DialErrors.Load(),
		BytesUp:      s.BytesUp.Load(),
		BytesDown:    s.BytesDown.Load(),
	}
	s.ByProto.Range(func(k, v any) bool {
		snap.ByProto[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	s.topMu.Lock()
	for n, c := range s.top {
		snap.TopProxied = append(snap.TopProxied, Count{n, c})
	}
	s.topMu.Unlock()
	sort.Slice(snap.TopProxied, func(i, j int) bool { return snap.TopProxied[i].Count > snap.TopProxied[j].Count })
	if len(snap.TopProxied) > 30 {
		snap.TopProxied = snap.TopProxied[:30]
	}
	return snap
}

type Entry struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Proto    string    `json:"proto"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Action   string    `json:"action"`
	Rcode    string    `json:"rcode"`
	Answer   string    `json:"answer,omitempty"`
	Duration float64   `json:"ms"`
}

type QueryLog struct {
	mu   sync.Mutex
	buf  []Entry
	next int
	full bool
	seq  uint64
}

func NewQueryLog(size int) *QueryLog {
	if size <= 0 {
		return &QueryLog{}
	}
	return &QueryLog{buf: make([]Entry, size)}
}

func (l *QueryLog) Add(e Entry) {
	if l == nil || len(l.buf) == 0 {
		return
	}
	l.mu.Lock()
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	l.seq++
	l.mu.Unlock()
}

func (l *QueryLog) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

func (l *QueryLog) Recent(n int, filter string) []Entry {
	if l == nil || len(l.buf) == 0 {
		return nil
	}
	filter = strings.ToLower(filter)
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.next
	if l.full {
		size = len(l.buf)
	}
	out := make([]Entry, 0, min(n, size))
	for i := 0; i < size && len(out) < n; i++ {
		idx := (l.next - 1 - i + len(l.buf)) % len(l.buf)
		e := l.buf[idx]
		if filter != "" && !strings.Contains(e.Name, filter) && !strings.Contains(e.Client, filter) && e.Action != filter {
			continue
		}
		out = append(out, e)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
