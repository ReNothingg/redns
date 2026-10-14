package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/dnsx"
	"github.com/renothingg/redns/internal/lists"
	"github.com/renothingg/redns/internal/stats"
)

type LookupFunc func(ctx context.Context, host string, want6 bool) ([]netip.Addr, error)

type Options struct {
	Access     *access.Access
	Policy     func() *dnsx.Policy
	Lookup     LookupFunc
	Stats      *stats.Stats
	Hints      *Hints
	Exits      map[string]string
	Forwards   []config.Forward
	SelfIPs    []netip.Addr
	IPv6Egress bool

	AllowPrivate      bool
	DialTimeout       time.Duration
	HandshakeTimeout  time.Duration
	MaxConns          int
	MaxConnsPerClient int
	ConnRate          int

	LocalTLS  *Local
	LocalHTTP *Local

	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	TLSPort, HTTPPort int
}

type Proxy struct {
	o       Options
	limiter *dnsx.Limiter
	dialer  net.Dialer
	active  atomic.Int64
	mu      sync.Mutex
	clients map[netip.Prefix]*clientStat
	self    map[netip.Addr]bool
	lns     []net.Listener
	closed  atomic.Bool
}

func New(o Options) *Proxy {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 8 * time.Second
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 15 * time.Second
	}
	if o.TLSPort == 0 {
		o.TLSPort = 443
	}
	if o.HTTPPort == 0 {
		o.HTTPPort = 80
	}
	p := &Proxy{
		o:       o,
		limiter: dnsx.NewLimiter(o.ConnRate),
		dialer:  net.Dialer{KeepAlive: 30 * time.Second},
		clients: map[netip.Prefix]*clientStat{},
		self:    map[netip.Addr]bool{},
	}
	for _, a := range o.SelfIPs {
		p.self[a.Unmap()] = true
	}
	return p
}

func listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	return lc.Listen(context.Background(), "tcp", addr)
}

func (p *Proxy) ServeTLS(addr string) error {
	ln, err := listenTCP(addr)
	if err != nil {
		return err
	}
	p.track(ln)
	go p.accept(ln, p.handleTLS)
	return nil
}

func (p *Proxy) ServeHTTP(addr string) error {
	ln, err := listenTCP(addr)
	if err != nil {
		return err
	}
	p.track(ln)
	go p.accept(ln, p.handleHTTP)
	return nil
}

func (p *Proxy) ServeForwards(host string) error {
	for _, f := range p.o.Forwards {
		ln, err := listenTCP(net.JoinHostPort(host, strconv.Itoa(f.Port)))
		if err != nil {
			return err
		}
		p.track(ln)
		go p.accept(ln, func(c net.Conn) { p.handleForward(c, f) })
	}
	return nil
}

func (p *Proxy) track(ln net.Listener) {
	p.mu.Lock()
	p.lns = append(p.lns, ln)
	p.mu.Unlock()
}

func (p *Proxy) Close() error {
	p.closed.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ln := range p.lns {
		ln.Close()
	}
	return nil
}

func (p *Proxy) accept(ln net.Listener, handle func(net.Conn)) {
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if p.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}

			backoff = min(max(backoff*2, 5*time.Millisecond), time.Second)
			slog.Warn("accept error", "err", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if ip := remoteIP(c); p.o.Access.Banned(ip) || !p.limiter.Allow(ip) {
			c.Close()
			continue
		}
		go handle(c)
	}
}

func (p *Proxy) GCLimiter() { p.limiter.GC() }

func remoteIP(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		a, _ := netip.AddrFromSlice(ta.IP)
		return a.Unmap()
	}
	return netip.Addr{}
}

func (p *Proxy) handleTLS(c net.Conn) {
	ip := remoteIP(c)
	if p.o.Access.Banned(ip) {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(p.o.HandshakeTimeout))
	raw, hello, err := ReadClientHello(c)
	if err != nil {

		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	sni := lists.Normalize(hello.ServerName)

	if sni == "" || p.o.Access.IsOwnName(sni) {
		p.local(p.o.LocalTLS, c, raw)
		return
	}
	exit, ok := p.o.Policy().ProxyTarget(sni)
	if !ok || !p.o.Access.ProxyAllowed(ip) {

		p.o.Stats.ConnsDenied.Add(1)
		p.local(p.o.LocalTLS, c, raw)
		return
	}
	p.relay(c, ip, sni, p.o.TLSPort, exit, raw)
}

func (p *Proxy) handleHTTP(c net.Conn) {
	ip := remoteIP(c)
	if p.o.Access.Banned(ip) {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(p.o.HandshakeTimeout))
	var buf bytes.Buffer
	req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(c, &buf)))
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = lists.Normalize(host)
	if host == "" || p.o.Access.IsOwnName(host) {
		p.local(p.o.LocalHTTP, c, buf.Bytes())
		return
	}
	exit, ok := p.o.Policy().ProxyTarget(host)
	if !ok || !p.o.Access.ProxyAllowed(ip) {
		p.o.Stats.ConnsDenied.Add(1)
		p.local(p.o.LocalHTTP, c, buf.Bytes())
		return
	}
	p.relay(c, ip, host, p.o.HTTPPort, exit, buf.Bytes())
}

func (p *Proxy) handleForward(c net.Conn, f config.Forward) {
	ip := remoteIP(c)
	if !p.o.Access.ProxyAllowed(ip) {
		p.o.Stats.ConnsDenied.Add(1)
		c.Close()
		return
	}
	target, ok := p.o.Hints.Get(ip, f.Port)
	if !ok {
		target = f.Default
	}
	if target == "" {
		c.Close()
		return
	}
	p.relay(c, ip, target, f.TargetPort, "", nil)
}

func (p *Proxy) local(l *Local, c net.Conn, prefix []byte) {
	if l == nil || !l.Push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}) {
		c.Close()
	}
}

func (p *Proxy) relay(c net.Conn, ip netip.Addr, host string, port int, exit string, prefix []byte) {
	defer c.Close()
	if !p.acquire(ip, c, host) {
		p.o.Stats.ConnsDenied.Add(1)
		return
	}
	var upN, downN int64
	defer func() { p.release(ip, c, upN, downN) }()
	p.o.Stats.ProxiedConn(host)

	ctx, cancel := context.WithTimeout(context.Background(), p.o.DialTimeout)
	up, err := p.dial(ctx, host, port, exit)
	cancel()
	if err != nil {
		p.o.Stats.DialErrors.Add(1)
		slog.Debug("dial failed", "host", host, "port", port, "exit", exit, "err", err)
		return
	}
	defer up.Close()
	if len(prefix) > 0 {
		_ = up.SetWriteDeadline(time.Now().Add(p.o.DialTimeout))
		if _, err := up.Write(prefix); err != nil {
			return
		}
		_ = up.SetWriteDeadline(time.Time{})
	}
	upN, downN = splice(c, up)
	upN += int64(len(prefix))
	p.o.Stats.BytesUp.Add(uint64(upN))
	p.o.Stats.BytesDown.Add(uint64(downN))
}

const halfCloseTimeout = 5 * time.Minute

func splice(client, upstream net.Conn) (up, down int64) {
	type res struct {
		n   int64
		err error
		dir int
	}
	ch := make(chan res, 2)
	go func() {
		n, err := io.Copy(upstream, client)
		closeWrite(upstream)
		ch <- res{n, err, 0}
	}()
	go func() {
		n, err := io.Copy(client, upstream)
		closeWrite(client)
		ch <- res{n, err, 1}
	}()
	first := <-ch
	if first.err != nil {
		client.Close()
		upstream.Close()
	} else {
		dl := time.Now().Add(halfCloseTimeout)
		_ = client.SetDeadline(dl)
		_ = upstream.SetDeadline(dl)
	}
	second := <-ch
	for _, r := range []res{first, second} {
		if r.dir == 0 {
			up = r.n
		} else {
			down = r.n
		}
	}
	return up, down
}

func closeWrite(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if v, ok := c.(cw); ok {
		_ = v.CloseWrite()
		return
	}
	if v, ok := c.(*prefixConn); ok {
		closeWrite(v.Conn)
	}
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func (p *Proxy) forbidden(a netip.Addr) bool {
	a = a.Unmap()
	if p.self[a] || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	if p.o.AllowPrivate {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return true
	}
	for _, r := range reserved {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

func (p *Proxy) dialAddr(ctx context.Context, addr string) (net.Conn, error) {
	if p.o.Dial != nil {
		return p.o.Dial(ctx, "tcp", addr)
	}
	return p.dialer.DialContext(ctx, "tcp", addr)
}

func (p *Proxy) dial(ctx context.Context, host string, port int, exit string) (net.Conn, error) {
	if exit != "" {
		addr, ok := p.o.Exits[exit]
		if !ok {
			return nil, errors.New("unknown exit " + exit)
		}
		def := strconv.Itoa(port)
		if port == p.o.HTTPPort {

			h, _, err := net.SplitHostPort(config.HostPort(addr, "443"))
			if err != nil {
				return nil, err
			}
			addr = h
		}
		return p.dialAddr(ctx, config.HostPort(addr, def))
	}
	addrs, err := p.o.Lookup(ctx, host, p.o.IPv6Egress)
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		if p.forbidden(a) {
			continue
		}
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}

	var order []netip.Addr
	for i := 0; i < max(len(v4), len(v6)); i++ {
		if i < len(v4) {
			order = append(order, v4[i])
		}
		if i < len(v6) {
			order = append(order, v6[i])
		}
	}
	if len(order) == 0 {
		return nil, errors.New("no usable addresses for " + host)
	}
	if len(order) > 4 {
		order = order[:4]
	}
	return p.happyEyeballs(ctx, order, port)
}

func (p *Proxy) happyEyeballs(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, len(addrs))
	next := 0
	start := func() {
		a := netip.AddrPortFrom(addrs[next], uint16(port)).String()
		next++
		go func() {
			c, err := p.dialAddr(ctx, a)
			ch <- res{c, err}
		}()
	}
	start()
	pending := 1
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	var errs []error
	for pending > 0 {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				cancel()

				go func(n int) {
					for i := 0; i < n; i++ {
						if x := <-ch; x.c != nil {
							x.c.Close()
						}
					}
				}(pending)
				return r.c, nil
			}
			errs = append(errs, r.err)
			if next < len(addrs) {
				start()
				pending++
				timer.Reset(250 * time.Millisecond)
			}
		case <-timer.C:
			if next < len(addrs) {
				start()
				pending++
				timer.Reset(250 * time.Millisecond)
			}
		case <-ctx.Done():
			go func(n int) {
				for i := 0; i < n; i++ {
					if x := <-ch; x.c != nil {
						x.c.Close()
					}
				}
			}(pending)
			return nil, ctx.Err()
		}
	}
	return nil, errors.Join(errs...)
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

type Local struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
	addr net.Addr
}

func NewLocal(addr net.Addr) *Local {
	return &Local{ch: make(chan net.Conn, 128), done: make(chan struct{}), addr: addr}
}

func (l *Local) Push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *Local) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Local) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *Local) Addr() net.Addr { return l.addr }
