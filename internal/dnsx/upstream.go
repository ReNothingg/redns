package dnsx

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	String() string
}

type Upstream struct {
	primary  []exchanger
	fallback []exchanger
	timeout  time.Duration
}

func NewUpstream(primary, fallback []string, timeout time.Duration) (*Upstream, error) {
	u := &Upstream{timeout: timeout}
	for _, s := range primary {
		e, err := parseUpstream(s, timeout)
		if err != nil {
			return nil, err
		}
		u.primary = append(u.primary, e)
	}
	for _, s := range fallback {
		e, err := parseUpstream(s, timeout)
		if err != nil {
			return nil, err
		}
		u.fallback = append(u.fallback, e)
	}
	if len(u.primary) == 0 {
		return nil, errors.New("no upstream servers")
	}
	return u, nil
}

func parseUpstream(s string, timeout time.Duration) (exchanger, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		scheme, rest = "udp", s
	}
	switch scheme {
	case "udp", "tcp":
		addr := withPort(rest, "53")
		p := &plainUpstream{addr: addr, tcpOnly: scheme == "tcp"}
		p.udp = &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 1232}
		p.tcp = &dns.Client{Net: "tcp", Timeout: timeout}
		return p, nil
	case "tls":
		host, sni, _ := strings.Cut(rest, "#")
		if sni == "" {
			sni = host
			if h, _, err := net.SplitHostPort(host); err == nil {
				sni = h
			}
		}
		return &tlsUpstream{addr: withPort(host, "853"), c: &dns.Client{
			Net: "tcp-tls", Timeout: timeout,
			TLSConfig: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12},
		}}, nil
	case "https":
		return &dohUpstream{url: s, client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: timeout,
			},
		}}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream %q", s)
	}
}

func withPort(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port)
}

type plainUpstream struct {
	addr     string
	tcpOnly  bool
	udp, tcp *dns.Client
}

func (p *plainUpstream) String() string { return p.addr }

func (p *plainUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if !p.tcpOnly {
		r, _, err := p.udp.ExchangeContext(ctx, m, p.addr)
		if err != nil || !r.Truncated {
			return r, err
		}
	}
	r, _, err := p.tcp.ExchangeContext(ctx, m, p.addr)
	return r, err
}

type tlsUpstream struct {
	addr string
	c    *dns.Client
}

func (t *tlsUpstream) String() string { return "tls://" + t.addr }

func (t *tlsUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	r, _, err := t.c.ExchangeContext(ctx, m, t.addr)
	return r, err
}

type dohUpstream struct {
	url    string
	client *http.Client
}

func (d *dohUpstream) String() string { return d.url }

func (d *dohUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	id := m.Id
	m.Id = 0
	buf, err := m.Pack()
	m.Id = id
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", d.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	r.Id = id
	return r, nil
}

type result struct {
	msg *dns.Msg
	err error
}

func usable(m *dns.Msg) bool {
	return m != nil && (m.Rcode == dns.RcodeSuccess || m.Rcode == dns.RcodeNameError)
}

func (u *Upstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	r, err := u.race(ctx, u.primary, m)
	if usable(r) || len(u.fallback) == 0 || ctx.Err() != nil {
		return r, err
	}
	r2, err2 := u.race(ctx, u.fallback, m)
	if usable(r2) {
		return r2, nil
	}
	if r != nil {
		return r, nil
	}
	if r2 != nil {
		return r2, nil
	}
	return nil, errors.Join(err, err2)
}

func (u *Upstream) race(ctx context.Context, group []exchanger, m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	ch := make(chan result, len(group))
	for _, e := range group {
		q := m.Copy()
		q.Id = dns.Id()
		go func(e exchanger, q *dns.Msg) {
			r, err := e.Exchange(ctx, q)
			if err != nil {
				err = fmt.Errorf("%s: %w", e, err)
			} else if r.Id != q.Id || !sameQuestion(q, r) {
				r, err = nil, fmt.Errorf("%s: response does not match the query", e)
			}
			ch <- result{r, err}
		}(e, q)
	}
	var last *dns.Msg
	var errs []error
	for range group {
		res := <-ch
		if usable(res.msg) {
			return res.msg, nil
		}
		if res.msg != nil {
			last = res.msg
		}
		if res.err != nil {
			errs = append(errs, res.err)
		}
	}
	if last != nil {
		return last, nil
	}
	return nil, errors.Join(errs...)
}

func sameQuestion(q, r *dns.Msg) bool {
	if len(q.Question) != 1 || len(r.Question) != 1 {
		return false
	}
	a, b := q.Question[0], r.Question[0]
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && strings.EqualFold(a.Name, b.Name)
}
