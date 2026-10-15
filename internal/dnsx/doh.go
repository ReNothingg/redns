package dnsx

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/renothingg/redns/internal/access"
)

type DoH struct {
	R      *Resolver
	Access *access.Access
	FP     *Fingerprints
}

const dohPath = "/dns-query"

func (d *DoH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := ""
	ip := clientIP(r)
	if rest, ok := strings.CutPrefix(r.URL.Path, dohPath+"/"); ok {
		var valid bool
		if tok, valid = d.Access.CheckKey(ip, strings.Trim(rest, "/")); !valid {
			http.NotFound(w, r)
			return
		}
	} else if r.TLS != nil {
		tok = d.Access.TokenFromSNI(ip, r.TLS.ServerName)
	}

	var raw []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(q, "="))
	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(r.Body, 65536))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(raw) < 12 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "malformed dns message", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp := d.R.Resolve(ctx, req, Client{IP: ip, Proto: "doh", Token: tok, FP: d.FP.Get(r.RemoteAddr)})
	if resp == nil {
		resp = rcode(req, dns.RcodeRefused)
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/dns-message")
	h.Set("Content-Length", strconv.Itoa(len(out)))
	if r.Method == http.MethodGet && tok == "" {
		h.Set("Cache-Control", "max-age="+strconv.Itoa(int(minTTL(resp))))
	} else {
		h.Set("Cache-Control", "no-store")
	}
	_, _ = w.Write(out)
}

func clientIP(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func minTTL(m *dns.Msg) uint32 {
	ttl := uint32(300)
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			ttl = min(ttl, rr.Header().Ttl)
		}
	}
	return ttl
}
