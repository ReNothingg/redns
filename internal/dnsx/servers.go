package dnsx

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/renothingg/redns/internal/access"
)

const maxUDPReply = 1232

type Handler struct {
	R       *Resolver
	Access  *access.Access
	Limiter *Limiter
	Proto   string
	FP      *Fingerprints
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	ip := addrOf(w.RemoteAddr())
	c := Client{IP: ip, Proto: h.Proto}
	if h.Proto == "udp" || h.Proto == "tcp" {
		if !h.Limiter.Allow(ip) {
			h.R.stats.RateLimited.Add(1)
			return
		}
	}
	if h.Proto == "dot" {
		if cs, ok := w.(dns.ConnectionStater); ok {
			if st := cs.ConnectionState(); st != nil {
				c.Token = h.Access.TokenFromSNI(ip, st.ServerName)
				c.FP = h.FP.Get(w.LocalAddr().String() + "|" + w.RemoteAddr().String())
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp := h.R.Resolve(ctx, req, c)
	if resp == nil {
		return
	}
	if h.Proto == "udp" {
		size := dns.MinMsgSize
		if o := req.IsEdns0(); o != nil {
			size = max(dns.MinMsgSize, min(int(o.UDPSize()), maxUDPReply))
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)
}

func PlainServers(addr string, r *Resolver, acc *access.Access, lim *Limiter) ([]*dns.Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return nil, err
	}
	udp := &dns.Server{PacketConn: pc, Net: "udp", UDPSize: 65535,
		Handler: &Handler{R: r, Access: acc, Limiter: lim, Proto: "udp"}}
	tcp := &dns.Server{Listener: ln, Net: "tcp", MaxTCPQueries: 256,
		IdleTimeout: func() time.Duration { return 10 * time.Second },
		Handler:     &Handler{R: r, Access: acc, Limiter: lim, Proto: "tcp"}}
	for _, s := range []*dns.Server{udp, tcp} {
		go func(s *dns.Server) {
			if err := s.ActivateAndServe(); err != nil {
				slog.Error("dns server stopped", "net", s.Net, "err", err)
			}
		}(s)
	}
	return []*dns.Server{udp, tcp}, nil
}

func DoTServer(addr string, tlsConf *tls.Config, r *Resolver, acc *access.Access, fp *Fingerprints) (*dns.Server, error) {
	tc := fp.Wrap(tlsConf)
	tc.NextProtos = []string{"dot"}
	ln, err := tls.Listen("tcp", addr, tc)
	if err != nil {
		return nil, err
	}
	s := &dns.Server{Listener: ln, Net: "tcp-tls", MaxTCPQueries: -1,
		ReadTimeout: 10 * time.Second,
		IdleTimeout: func() time.Duration { return 5 * time.Minute },
		Handler:     &Handler{R: r, Access: acc, Proto: "dot", FP: fp}}
	go func() {
		if err := s.ActivateAndServe(); err != nil {
			slog.Error("dot server stopped", "err", err)
		}
	}()
	return s, nil
}

type DoQServer struct {
	ln     *quic.Listener
	r      *Resolver
	access *access.Access
	ctx    context.Context
	cancel context.CancelFunc
}

func NewDoQServer(addr string, tlsConf *tls.Config, r *Resolver, acc *access.Access) (*DoQServer, error) {
	tc := tlsConf.Clone()
	tc.NextProtos = []string{"doq"}
	tc.MinVersion = tls.VersionTLS13
	ln, err := quic.ListenAddr(addr, tc, &quic.Config{
		MaxIdleTimeout:        5 * time.Minute,
		MaxIncomingStreams:    256,
		MaxIncomingUniStreams: -1,
		KeepAlivePeriod:       0,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &DoQServer{ln: ln, r: r, access: acc, ctx: ctx, cancel: cancel}
	go s.serve()
	return s, nil
}

func (s *DoQServer) Close() error {
	s.cancel()
	return s.ln.Close()
}

func (s *DoQServer) serve() {
	for {
		conn, err := s.ln.Accept(s.ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, quic.ErrServerClosed) {
				slog.Error("doq accept", "err", err)
			}
			return
		}
		go s.handleConn(conn)
	}
}

func (s *DoQServer) handleConn(conn *quic.Conn) {
	ip := addrOf(conn.RemoteAddr())
	tok := s.access.TokenFromSNI(ip, conn.ConnectionState().TLS.ServerName)
	for {
		st, err := conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go s.handleStream(st, Client{IP: ip, Proto: "doq", Token: tok})
	}
}

func (s *DoQServer) handleStream(st *quic.Stream, c Client) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	var lb [2]byte
	if _, err := io.ReadFull(st, lb[:]); err != nil {
		st.CancelRead(0x2)
		return
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(st, buf); err != nil {
		st.CancelRead(0x2)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		st.CancelRead(0x2)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	resp := s.r.Resolve(ctx, req, c)
	if resp == nil {
		return
	}
	out, err := resp.Pack()
	if err != nil {
		return
	}
	msg := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(msg, uint16(len(out)))
	copy(msg[2:], out)
	_, _ = st.Write(msg)
}
