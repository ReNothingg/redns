package web

import (
	"crypto/rand"
	"encoding/json"
	"html/template"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/audit"
	"github.com/renothingg/redns/internal/proxy"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
)

type ProxyView interface {
	ClientStats() []proxy.ClientStat
	Disconnect(netip.Prefix) int
}

type Info struct {
	ProxyRules int `json:"proxy_rules"`
	BlockRules int `json:"block_rules"`
	CacheSize  int `json:"cache_entries"`
}

type Options struct {
	Host         string
	IPv4, IPv6   string
	Access       *access.Access
	DoH          http.Handler
	Version      string
	Info         func() Info
	Proxy        ProxyView
	Stats        *stats.Stats
	Store        *state.Store
	Apply        func(state.Data)
	PasswordHash func() string
	AdminPublic  func() bool
	Audit        *audit.Log
	SessionsPath string
	KeyedDoT     func() bool
}

type Web struct {
	o        Options
	testBuf  []byte
	testBusy atomic.Int32
	admin    *admin
}

func New(o Options) *Web {
	buf := make([]byte, 1<<20)
	_, _ = rand.Read(buf)
	w := &Web{o: o, testBuf: buf}
	w.admin = newAdmin(w)
	return w
}

func (w *Web) HTTPS() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/dns-query", w.o.DoH)
	mux.Handle("/dns-query/", w.o.DoH)
	mux.HandleFunc("/health", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("ok\n"))
	})
	mux.Handle("/assets/", http.StripPrefix("/assets/", staticFiles()))
	mux.HandleFunc("/api/whoami", w.whoami)
	mux.HandleFunc("/api/test", w.speedTest)
	mux.HandleFunc("/setup/", w.setup)
	mux.Handle("/admin", w.admin)
	mux.Handle("/admin/", w.admin)
	mux.HandleFunc("/", w.index)
	return w.ownHostOnly(w.noBanned(securityHeaders(mux)))
}

func (w *Web) HTTP() http.Handler {
	return w.ownHostOnly(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, "https://"+w.o.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))
}

func (w *Web) ownHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		if !w.o.Access.IsOwnName(host) {
			http.NotFound(rw, r)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *Web) noBanned(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin") && !strings.HasPrefix(r.URL.Path, "/assets/") && w.o.Access.Banned(remoteIP(r)) {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(rw, r)
	})
}

type pageData struct {
	Host, IPv4, IPv6 string
	Private          bool
	TokenName        string
	DoHURL           string
	DoTHost          string
	DoT              bool
	AndroidDoT       string
	ProfileBase      string
	Rules            int
	Version          string
	Assets           string
	Icons            template.HTML
	Admin            bool
}

func (w *Web) data(tok string) pageData {
	d := pageData{
		Host: w.o.Host, IPv4: w.o.IPv4, IPv6: w.o.IPv6,
		Private: w.o.Access.Private(), Version: w.o.Version, Assets: assetVersion, Icons: icons,
		DoHURL: "https://" + w.o.Host + "/dns-query", DoTHost: w.o.Host, DoT: !w.o.Access.Private(),
		ProfileBase: "/setup",
	}
	if d.DoT {
		d.AndroidDoT = d.DoTHost
	}
	if tok != "" {
		if d.Private && w.o.KeyedDoT != nil && w.o.KeyedDoT() {
			d.AndroidDoT = tok + "." + w.o.Host
		}
		d.TokenName = w.o.Access.TokenName(tok)
		d.Admin = w.admin.enabled() && w.o.Access.TokenOwner(tok) == access.Owner
		d.DoHURL += "/" + tok
		d.ProfileBase = "/setup/" + tok
	}
	if w.o.Info != nil {
		d.Rules = w.o.Info().ProxyRules
	}
	return d
}

func (w *Web) index(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || w.o.Access.Private() {
		http.NotFound(rw, r)
		return
	}
	render(rw, setupTmpl, w.data(""))
}

func render(rw http.ResponseWriter, t *template.Template, data any) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	_ = t.Execute(rw, data)
}

func (w *Web) setup(rw http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/setup"), "/"), "/")
	tok, file := "", ""
	switch {
	case len(parts) == 1 && strings.HasSuffix(parts[0], ".mobileconfig"):
		file = parts[0]
	case len(parts) == 1 && parts[0] != "":
		tok = parts[0]
	case len(parts) == 2:
		tok, file = parts[0], parts[1]
	}
	if tok != "" {
		ip := remoteIP(r)
		if w.o.Access.Throttled(ip) {
			http.NotFound(rw, r)
			return
		}
		var ok bool
		if tok, ok = w.o.Access.ValidToken(tok); !ok {
			w.o.Access.Strike(ip)
			http.NotFound(rw, r)
			return
		}
		w.o.Access.Authorize(remoteIP(r), tok)
	} else if w.o.Access.Private() {
		http.NotFound(rw, r)
		return
	}
	d := w.data(tok)
	switch file {
	case "":
		if tok == "" {
			http.Redirect(rw, r, "/", http.StatusFound)
			return
		}
		render(rw, setupTmpl, d)
	case "redns.mobileconfig", "redns-doh.mobileconfig", "redns-dot.mobileconfig":
		p := ProfileParams{Host: w.o.Host, Label: d.TokenName, DoHURL: d.DoHURL, DoTName: d.DoTHost, Consent: Agreement(w.o.Host)}
		for _, a := range []string{w.o.IPv4, w.o.IPv6} {
			if a != "" {
				p.Addresses = append(p.Addresses, a)
			}
		}
		switch {
		case !d.DoT || file == "redns-doh.mobileconfig":
			p.Only = "doh"
		case file == "redns-dot.mobileconfig":
			p.Only = "dot"
		}
		rw.Header().Set("Content-Type", "application/x-apple-aspen-config")
		rw.Header().Set("Content-Disposition", `attachment; filename="ReDNS-`+w.o.Host+`.mobileconfig"`)
		rw.Header().Set("Cache-Control", "no-store")
		_, _ = rw.Write(Profile(p))
	default:
		http.NotFound(rw, r)
	}
}

type whoamiResp struct {
	IP          string `json:"ip"`
	UsingDNS    bool   `json:"using_dns"`
	Proto       string `json:"proto,omitempty"`
	SecondsAgo  int    `json:"seconds_ago"`
	ProxyAccess bool   `json:"proxy_access"`
	Private     bool   `json:"private"`
	Host        string `json:"host"`
}

func (w *Web) whoami(rw http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	resp := whoamiResp{IP: ip.String(), ProxyAccess: w.o.Access.ProxyAllowed(ip), Private: w.o.Access.Private(), Host: w.o.Host}
	if c, ok := w.o.Access.Lookup(ip); ok && !c.LastSeen.IsZero() {
		ago := time.Since(c.LastSeen)
		resp.UsingDNS = ago < 10*time.Minute
		resp.Proto = c.Proto
		resp.SecondsAgo = int(ago.Seconds())
	}
	writeJSON(rw, resp)
}

func (w *Web) speedTest(rw http.ResponseWriter, r *http.Request) {
	if !w.o.Access.Allowed(remoteIP(r)) {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	if w.testBusy.Add(1) > 4 {
		w.testBusy.Add(-1)
		http.Error(rw, "busy", http.StatusTooManyRequests)
		return
	}
	defer w.testBusy.Add(-1)
	mb, _ := strconv.Atoi(r.URL.Query().Get("mb"))
	mb = min(max(mb, 1), 25)
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("Content-Length", strconv.Itoa(mb<<20))
	rw.Header().Set("Cache-Control", "no-store")
	for i := 0; i < mb; i++ {
		if _, err := rw.Write(w.testBuf); err != nil {
			return
		}
	}
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(rw).Encode(v)
}

func remoteIP(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}
