package dnsx

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/lists"
	"github.com/renothingg/redns/internal/stats"
)

type Client struct {
	IP    netip.Addr
	Proto string

	Token string
}

func (c Client) plain() bool { return c.Proto == "udp" || c.Proto == "tcp" }

type Hinter interface {
	Hint(client netip.Addr, name string)
}

type Options struct {
	IPv4, IPv6 netip.Addr
	AnswerTTL  uint32
	ECS        bool
	ServeStale bool
	Prefetch   bool
	BlockTTL   uint32
}

type Resolver struct {
	opt    Options
	policy atomic.Pointer[Policy]
	cache  *Cache
	up     *Upstream
	access *access.Access
	stats  *stats.Stats
	hinter Hinter
	sf     singleflight.Group
}

func NewResolver(opt Options, p *Policy, cache *Cache, up *Upstream, acc *access.Access, st *stats.Stats, h Hinter) *Resolver {
	if opt.AnswerTTL == 0 {
		opt.AnswerTTL = 300
	}
	if opt.BlockTTL == 0 {
		opt.BlockTTL = 60
	}
	r := &Resolver{opt: opt, cache: cache, up: up, access: acc, stats: st, hinter: h}
	r.policy.Store(p)
	return r
}

func (r *Resolver) SetPolicy(p *Policy) { r.policy.Store(p) }
func (r *Resolver) Policy() *Policy     { return r.policy.Load() }
func (r *Resolver) Cache() *Cache       { return r.cache }

func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg, c Client) *dns.Msg {
	start := time.Now()
	r.stats.Queries.Add(1)
	r.stats.Proto(c.Proto)
	if c.Token != "" {
		r.access.Authorize(c.IP, c.Token)
	}
	if !r.access.Allowed(c.IP) {
		r.stats.Refused.Add(1)
		if c.plain() {
			return nil
		}
		return rcode(req, dns.RcodeRefused)
	}
	r.access.Touch(c.IP, c.Proto)

	if len(req.Question) != 1 || req.Response {
		return rcode(req, dns.RcodeFormatError)
	}
	if req.Opcode != dns.OpcodeQuery {
		return rcode(req, dns.RcodeNotImplemented)
	}
	q := req.Question[0]
	name := lists.Normalize(q.Name)
	var (
		resp   *dns.Msg
		action string
	)
	switch {
	case q.Qclass != dns.ClassINET:
		resp, action = rcode(req, dns.RcodeRefused), "refused"
	case q.Qtype == dns.TypeANY:
		resp, action = r.anyReply(req), "any"
	default:
		resp, action = r.resolveIN(ctx, req, q, name, c)
	}
	r.log(start, c, name, q.Qtype, action, resp)
	return resp
}

func (r *Resolver) resolveIN(ctx context.Context, req *dns.Msg, q dns.Question, name string, c Client) (*dns.Msg, string) {
	p := r.policy.Load()
	act, _ := p.Decide(name)
	switch act {
	case ActSelf:
		return r.addrReply(req, q, r.opt.IPv4, r.opt.IPv6, r.opt.AnswerTTL), "self"
	case ActHosts:
		var v4, v6 []netip.Addr
		for _, a := range p.Hosts[name] {
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		return r.addrsReply(req, q, v4, v6, r.opt.AnswerTTL), "hosts"
	case ActNXDomain:
		m := rcode(req, dns.RcodeNameError)
		m.Ns = []dns.RR{fakeSOA(q.Name)}
		return m, "nxdomain"
	case ActProxy:
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			r.stats.Proxied.Add(1)
			if r.hinter != nil {
				r.hinter.Hint(c.IP, name)
			}
			v6 := r.opt.IPv6
			if c.IP.Unmap().Is4() {
				v6 = netip.Addr{}
			}
			return r.addrReply(req, q, r.opt.IPv4, v6, r.opt.AnswerTTL), "proxy"
		case dns.TypeHTTPS, dns.TypeSVCB:

			return nodata(req, q.Name, r.opt.AnswerTTL), "proxy"
		}
	case ActBlock:
		r.stats.Blocked.Add(1)
		zero4, zero6 := netip.IPv4Unspecified(), netip.IPv6Unspecified()
		return r.addrReply(req, q, zero4, zero6, r.opt.BlockTTL), "block"
	}
	return r.forward(ctx, req, q, name, c)
}

func (r *Resolver) ecsPrefix(ip netip.Addr) netip.Prefix {
	if !r.opt.ECS {
		return netip.Prefix{}
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return netip.Prefix{}
	}
	bits := 24
	if ip.Is6() {
		bits = 56
	}
	p, _ := ip.Prefix(bits)
	return p
}

func (r *Resolver) forward(ctx context.Context, req *dns.Msg, q dns.Question, name string, c Client) (*dns.Msg, string) {
	r.stats.Forwarded.Add(1)
	k := cacheKey{name: name, qtype: q.Qtype, cd: req.CheckingDisabled, ecs: r.ecsPrefix(c.IP)}
	if o := req.IsEdns0(); o != nil {
		k.do = o.Do()
	}
	e, fresh := r.cache.Get(k)
	if fresh {
		r.stats.CacheHits.Add(1)
		if r.opt.Prefetch {
			r.maybePrefetch(k, e)
		}
		return reply(req, e.msg, e.age(time.Now()), 0), "cache"
	}
	m, err := r.fetch(ctx, k)
	if err == nil && m != nil {
		return reply(req, m, 0, 0), "forward"
	}
	r.stats.UpstreamErrs.Add(1)
	if e != nil && r.opt.ServeStale {
		r.stats.StaleServed.Add(1)
		return reply(req, e.msg, 0, 30), "stale"
	}
	return rcode(req, dns.RcodeServerFailure), "error"
}

func (r *Resolver) fetch(ctx context.Context, k cacheKey) (*dns.Msg, error) {
	sfKey := k.name + "|" + strconv.Itoa(int(k.qtype)) + "|" + k.ecs.String() + "|" + strconv.FormatBool(k.do) + strconv.FormatBool(k.cd)
	v, err, _ := r.sf.Do(sfKey, func() (any, error) {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(k.name), k.qtype)
		q.RecursionDesired = true
		q.CheckingDisabled = k.cd
		q.SetEdns0(1232, k.do)
		if k.ecs.IsValid() {
			o := q.IsEdns0()
			sub := &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				SourceNetmask: uint8(k.ecs.Bits()),
				Address:       k.ecs.Addr().AsSlice(),
			}
			if k.ecs.Addr().Is4() {
				sub.Family = 1
			} else {
				sub.Family = 2
			}
			o.Option = append(o.Option, sub)
		}

		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.up.timeout*2)
		defer cancel()
		m, err := r.up.Exchange(uctx, q)
		if err != nil {
			return nil, err
		}
		if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
			return m, errors.New(dns.RcodeToString[m.Rcode])
		}
		r.cache.Set(k, m)
		return m, nil
	})
	if v == nil {
		return nil, err
	}
	return v.(*dns.Msg), err
}

func (r *Resolver) maybePrefetch(k cacheKey, e *cacheEntry) {
	if e.ttl < 20 || e.hits.Load() < 3 {
		return
	}
	remaining := time.Until(e.expires())
	if remaining > time.Duration(e.ttl)*time.Second/10 || !e.fetching.CompareAndSwap(false, true) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), r.up.timeout*2)
		defer cancel()
		_, _ = r.fetch(ctx, k)
	}()
}

func (r *Resolver) LookupNetIP(ctx context.Context, host string, want6 bool) ([]netip.Addr, error) {
	host = lists.Normalize(host)
	types := []uint16{dns.TypeA}
	if want6 {
		types = append(types, dns.TypeAAAA)
	}
	type res struct {
		addrs []netip.Addr
		err   error
	}
	ch := make(chan res, len(types))
	for _, t := range types {
		go func(t uint16) {
			k := cacheKey{name: host, qtype: t}
			e, fresh := r.cache.Get(k)
			var m *dns.Msg
			var err error
			if fresh {
				m = e.msg
			} else if m, err = r.fetch(ctx, k); err != nil && e != nil {
				m, err = e.msg, nil
			}
			ch <- res{addrsFrom(m), err}
		}(t)
	}
	var out []netip.Addr
	var errs []error
	for range types {
		x := <-ch
		out = append(out, x.addrs...)
		if x.err != nil {
			errs = append(errs, x.err)
		}
	}
	if len(out) == 0 {
		if err := errors.Join(errs...); err != nil {
			return nil, err
		}
		return nil, errors.New("no addresses for " + host)
	}
	return out, nil
}

func addrsFrom(m *dns.Msg) []netip.Addr {
	if m == nil {
		return nil
	}
	var out []netip.Addr
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out = append(out, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

func (r *Resolver) log(start time.Time, c Client, name string, qtype uint16, action string, m *dns.Msg) {
	l := r.stats.Log()
	if l == nil {
		return
	}
	e := stats.Entry{
		Time:     start,
		Client:   c.IP.Unmap().String(),
		Proto:    c.Proto,
		Name:     name,
		Type:     dns.TypeToString[qtype],
		Action:   action,
		Duration: float64(time.Since(start).Microseconds()) / 1000,
	}
	if m != nil {
		e.Rcode = dns.RcodeToString[m.Rcode]
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.A:
				e.Answer = v.A.String()
			case *dns.AAAA:
				e.Answer = v.AAAA.String()
			case *dns.CNAME:
				if e.Answer == "" {
					e.Answer = v.Target
				}
				continue
			default:
				continue
			}
			break
		}
	}
	l.Add(e)
}

func newReply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.Authoritative = false
	if o := req.IsEdns0(); o != nil {
		m.SetEdns0(1232, o.Do())
	}
	return m
}

func rcode(req *dns.Msg, code int) *dns.Msg {
	m := newReply(req)
	m.Rcode = code
	return m
}

func fakeSOA(owner string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "redns.invalid.",
		Mbox:    "hostmaster.redns.invalid.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}

func nodata(req *dns.Msg, owner string, ttl uint32) *dns.Msg {
	m := newReply(req)
	soa := fakeSOA(owner)
	soa.Header().Ttl = min(ttl, 300)
	m.Ns = []dns.RR{soa}
	return m
}

func (r *Resolver) addrReply(req *dns.Msg, q dns.Question, v4, v6 netip.Addr, ttl uint32) *dns.Msg {
	var a4, a6 []netip.Addr
	if v4.IsValid() {
		a4 = []netip.Addr{v4}
	}
	if v6.IsValid() {
		a6 = []netip.Addr{v6}
	}
	return r.addrsReply(req, q, a4, a6, ttl)
}

func (r *Resolver) addrsReply(req *dns.Msg, q dns.Question, v4, v6 []netip.Addr, ttl uint32) *dns.Msg {
	m := newReply(req)
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
	switch q.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		for _, a := range v4 {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: a.AsSlice()})
		}
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		for _, a := range v6 {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()})
		}
	}
	if len(m.Answer) == 0 {
		return nodata(req, q.Name, ttl)
	}
	return m
}

func (r *Resolver) anyReply(req *dns.Msg) *dns.Msg {
	m := newReply(req)
	m.Answer = []dns.RR{&dns.HINFO{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 3600},
		Cpu: "RFC8482",
	}}
	return m
}

func reply(req, src *dns.Msg, age, fixedTTL uint32) *dns.Msg {
	m := newReply(req)
	m.Rcode = src.Rcode
	m.Answer = copyRRs(src.Answer, age, fixedTTL)
	m.Ns = copyRRs(src.Ns, age, fixedTTL)
	m.Extra = append(copyRRs(src.Extra, age, fixedTTL), m.Extra...)
	if o := req.IsEdns0(); (o != nil && o.Do()) || req.AuthenticatedData {
		m.AuthenticatedData = src.AuthenticatedData
	}
	return m
}
