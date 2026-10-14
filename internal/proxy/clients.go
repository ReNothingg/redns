package proxy

import (
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/renothingg/redns/internal/access"
)

type clientStat struct {
	conns map[net.Conn]struct{}
	total uint64
	up    uint64
	down  uint64
	last  time.Time
	hosts map[string]uint64
}

type ClientStat struct {
	Prefix   string    `json:"prefix"`
	Active   int       `json:"active"`
	Total    uint64    `json:"total"`
	Up       uint64    `json:"up"`
	Down     uint64    `json:"down"`
	LastSeen time.Time `json:"last_seen"`
	Hosts    []string  `json:"hosts"`
}

func (p *Proxy) acquire(ip netip.Addr, c net.Conn, host string) bool {
	if p.o.MaxConns > 0 && p.active.Load() >= int64(p.o.MaxConns) {
		return false
	}
	k := access.Key(ip)
	p.mu.Lock()
	defer p.mu.Unlock()
	cs := p.clients[k]
	if cs == nil {
		cs = &clientStat{conns: map[net.Conn]struct{}{}, hosts: map[string]uint64{}}
		p.clients[k] = cs
	}
	if p.o.MaxConnsPerClient > 0 && len(cs.conns) >= p.o.MaxConnsPerClient {
		return false
	}
	cs.conns[c] = struct{}{}
	cs.total++
	cs.last = time.Now()
	if _, ok := cs.hosts[host]; ok || len(cs.hosts) < 64 {
		cs.hosts[host]++
	}
	p.active.Add(1)
	p.o.Stats.ConnsActive.Add(1)
	return true
}

func (p *Proxy) release(ip netip.Addr, c net.Conn, up, down int64) {
	k := access.Key(ip)
	p.mu.Lock()
	if cs := p.clients[k]; cs != nil {
		delete(cs.conns, c)
		cs.up += uint64(up)
		cs.down += uint64(down)
		cs.last = time.Now()
	}
	p.mu.Unlock()
	p.active.Add(-1)
	p.o.Stats.ConnsActive.Add(-1)
}

func (p *Proxy) Disconnect(prefix netip.Prefix) int {
	var victims []net.Conn
	p.mu.Lock()
	for k, cs := range p.clients {
		if prefix.Overlaps(k) {
			for c := range cs.conns {
				victims = append(victims, c)
			}
		}
	}
	p.mu.Unlock()
	for _, c := range victims {
		c.Close()
	}
	return len(victims)
}

func (p *Proxy) ClientStats() []ClientStat {
	p.mu.Lock()
	out := make([]ClientStat, 0, len(p.clients))
	for k, cs := range p.clients {
		hosts := make([]string, 0, len(cs.hosts))
		for h := range cs.hosts {
			hosts = append(hosts, h)
		}
		sort.Slice(hosts, func(i, j int) bool { return cs.hosts[hosts[i]] > cs.hosts[hosts[j]] })
		if len(hosts) > 6 {
			hosts = hosts[:6]
		}
		out = append(out, ClientStat{
			Prefix: k.String(), Active: len(cs.conns), Total: cs.total,
			Up: cs.up, Down: cs.down, LastSeen: cs.last, Hosts: hosts,
		})
	}
	p.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func (p *Proxy) GC() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	p.mu.Lock()
	for k, cs := range p.clients {
		if len(cs.conns) == 0 && cs.last.Before(cutoff) {
			delete(p.clients, k)
		}
	}
	p.mu.Unlock()
}
