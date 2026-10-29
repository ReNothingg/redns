package dnsx

import (
	"bufio"
	"encoding/gob"
	"hash/maphash"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	name   string
	qtype  uint16
	do, cd bool
	ecs    netip.Prefix
}

type cacheEntry struct {
	msg      *dns.Msg
	stored   time.Time
	ttl      uint32
	hits     atomic.Uint32
	fetching atomic.Bool
}

func (e *cacheEntry) expires() time.Time { return e.stored.Add(time.Duration(e.ttl) * time.Second) }

func (e *cacheEntry) age(now time.Time) uint32 {
	d := now.Sub(e.stored)
	if d < 0 {
		return 0
	}
	return uint32(d / time.Second)
}

const cacheShards = 64

type cacheShard struct {
	mu sync.Mutex
	m  map[cacheKey]*cacheEntry
}

type Cache struct {
	shards   [cacheShards]cacheShard
	perShard int
	minTTL   uint32
	maxTTL   uint32
	stale    time.Duration
	seed     maphash.Seed
	now      func() time.Time
}

func NewCache(size int, minTTL, maxTTL, stale time.Duration) *Cache {
	c := &Cache{
		perShard: max(size/cacheShards, 16),
		minTTL:   uint32(minTTL / time.Second),
		maxTTL:   uint32(maxTTL / time.Second),
		stale:    stale,
		seed:     maphash.MakeSeed(),
		now:      time.Now,
	}
	for i := range c.shards {
		c.shards[i].m = map[cacheKey]*cacheEntry{}
	}
	return c
}

func (c *Cache) shard(k cacheKey) *cacheShard {
	h := maphash.String(c.seed, k.name)
	return &c.shards[(h^uint64(k.qtype))%cacheShards]
}

func (c *Cache) Get(k cacheKey) (e *cacheEntry, fresh bool) {
	s := c.shard(k)
	s.mu.Lock()
	e = s.m[k]
	s.mu.Unlock()
	if e == nil {
		return nil, false
	}
	now := c.now()
	if now.Before(e.expires()) {
		e.hits.Add(1)
		return e, true
	}
	if c.stale > 0 && now.Before(e.expires().Add(c.stale)) {
		return e, false
	}
	return nil, false
}

func (c *Cache) expiredFor(e *cacheEntry) time.Duration { return c.now().Sub(e.expires()) }

func (c *Cache) TTLFor(m *dns.Msg) uint32 {
	if m == nil || m.Truncated {
		return 0
	}
	var ttl uint32
	switch {
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
		ttl = ^uint32(0)
		for _, rr := range m.Answer {
			ttl = min(ttl, rr.Header().Ttl)
		}
	case m.Rcode == dns.RcodeSuccess || m.Rcode == dns.RcodeNameError:
		ttl = 30
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl = min(soa.Hdr.Ttl, soa.Minttl)
				break
			}
		}
		ttl = min(ttl, 3600)
	default:
		return 0
	}
	ttl = max(ttl, c.minTTL)
	if c.maxTTL > 0 {
		ttl = min(ttl, c.maxTTL)
	}
	return ttl
}

func (c *Cache) Set(k cacheKey, m *dns.Msg) {
	ttl := c.TTLFor(m)
	if ttl == 0 {
		return
	}
	e := &cacheEntry{msg: m, stored: c.now(), ttl: ttl}
	s := c.shard(k)
	s.mu.Lock()
	if len(s.m) >= c.perShard {
		c.evict(s)
	}
	s.m[k] = e
	s.mu.Unlock()
}

func (c *Cache) evict(s *cacheShard) {
	now := c.now()
	for k, e := range s.m {
		if now.After(e.expires().Add(c.stale)) {
			delete(s.m, k)
		}
	}
	for k := range s.m {
		if len(s.m) < c.perShard*9/10 {
			break
		}
		delete(s.m, k)
	}
}

func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		c.shards[i].mu.Lock()
		n += len(c.shards[i].m)
		c.shards[i].mu.Unlock()
	}
	return n
}

func copyRRs(rrs []dns.RR, age, fixed uint32) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		cp := dns.Copy(rr)
		h := cp.Header()
		switch {
		case fixed > 0:
			h.Ttl = fixed
		case h.Ttl > age:
			h.Ttl -= age
		default:
			h.Ttl = 1
		}
		out = append(out, cp)
	}
	return out
}

type dumpEntry struct {
	Name   string
	Qtype  uint16
	DO, CD bool
	ECS    string
	Stored int64
	TTL    uint32
	Msg    []byte
}

func (c *Cache) Save(path string) (int, error) {
	now := c.now()
	var out []dumpEntry
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, e := range s.m {
			if now.After(e.expires().Add(c.stale)) {
				continue
			}
			b, err := e.msg.Pack()
			if err != nil {
				continue
			}
			d := dumpEntry{Name: k.name, Qtype: k.qtype, DO: k.do, CD: k.cd, Stored: e.stored.UnixNano(), TTL: e.ttl, Msg: b}
			if k.ecs.IsValid() {
				d.ECS = k.ecs.String()
			}
			out = append(out, d)
		}
		s.mu.Unlock()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriter(f)
	err = gob.NewEncoder(w).Encode(out)
	if err == nil {
		err = w.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return len(out), os.Rename(tmp, path)
}

func (c *Cache) Load(path string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var in []dumpEntry
	if err := gob.NewDecoder(bufio.NewReader(f)).Decode(&in); err != nil {
		return 0, err
	}
	now := c.now()
	n := 0
	for _, d := range in {
		e := &cacheEntry{stored: time.Unix(0, d.Stored), ttl: d.TTL}
		if e.stored.After(now) || now.After(e.expires().Add(c.stale)) {
			continue
		}
		m := new(dns.Msg)
		if m.Unpack(d.Msg) != nil {
			continue
		}
		e.msg = m
		k := cacheKey{name: d.Name, qtype: d.Qtype, do: d.DO, cd: d.CD}
		if d.ECS != "" {
			if k.ecs, err = netip.ParsePrefix(d.ECS); err != nil {
				continue
			}
		}
		s := c.shard(k)
		s.mu.Lock()
		if len(s.m) < c.perShard {
			s.m[k] = e
			n++
		}
		s.mu.Unlock()
	}
	return n, nil
}
