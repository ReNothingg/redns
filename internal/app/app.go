package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/audit"
	"github.com/renothingg/redns/internal/certs"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/dnsx"
	"github.com/renothingg/redns/internal/lists"
	"github.com/renothingg/redns/internal/proxy"
	"github.com/renothingg/redns/internal/state"
	"github.com/renothingg/redns/internal/stats"
	"github.com/renothingg/redns/internal/web"
)

type App struct {
	cfg     *config.Config
	version string

	stats    *stats.Stats
	audit    *audit.Log
	store    *state.Store
	access   *access.Access
	accCfg   atomic.Pointer[config.Access]
	pwHash   atomic.Pointer[string]
	adminPub atomic.Bool
	fetcher  *lists.Fetcher
	res      *dnsx.Resolver
	limiter  *dnsx.Limiter
	hints    *proxy.Hints
	proxy    *proxy.Proxy
	certs    *certs.Manager

	infos   atomic.Pointer[[]ListInfo]
	reloadM sync.Mutex

	dnsServers []*dns.Server
	doq        *dnsx.DoQServer
	httpSrvs   []*http.Server
	locals     []*proxy.Local
}

func New(ctx context.Context, cfg *config.Config, version string) (*App, error) {
	a := &App{cfg: cfg, version: version}
	a.stats = stats.New(cfg.Log.QueryLogSize)
	store, err := state.Open(cfg.Resolve(cfg.State))
	if err != nil {
		return nil, fmt.Errorf("state %s: %w", cfg.State, err)
	}
	a.store = store
	a.audit, err = audit.Open(filepath.Join(filepath.Dir(cfg.Resolve(cfg.State)), "audit.log"), 2000)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	accCfg := cfg.Access
	a.accCfg.Store(&accCfg)
	hash := cfg.Admin.PasswordHash
	if old := a.pwHash.Swap(&hash); old != nil && *old != hash {
		a.audit.Warn("Пароль админки сменён, все входы сброшены", "", "")
	}
	a.adminPub.Store(cfg.Admin.Public)
	a.access = access.New(cfg.Hostname, cfg.Access, store.Get())
	a.access.OnBlock(func(p netip.Prefix) {
		a.audit.Warn("Подбор ключа: IP заблокирован на час", p.String(), "")
	})
	a.fetcher = lists.NewFetcher(cfg.Resolve(cfg.Lists.CacheDir))

	pol, infos, err := BuildPolicy(ctx, cfg, a.fetcher)
	if err != nil {
		return nil, err
	}
	a.infos.Store(&infos)

	up, err := dnsx.NewUpstream(cfg.Upstream.Servers, cfg.Upstream.Fallback, cfg.Upstream.Timeout)
	if err != nil {
		return nil, err
	}
	a.hints = proxy.NewHints(cfg.Proxy.Forwards)
	var v4, v6 netip.Addr
	if cfg.PublicIPv4 != "" {
		v4 = netip.MustParseAddr(cfg.PublicIPv4)
	}
	if cfg.PublicIPv6 != "" {
		v6 = netip.MustParseAddr(cfg.PublicIPv6)
	}
	cache := dnsx.NewCache(cfg.Cache.Size, cfg.Cache.MinTTL, cfg.Cache.MaxTTL, staleWindow(cfg))
	a.res = dnsx.NewResolver(dnsx.Options{
		IPv4: v4, IPv6: v6,
		AnswerTTL:  uint32(cfg.Proxy.AnswerTTL / time.Second),
		ECS:        cfg.Upstream.ECS,
		ServeStale: cfg.Cache.ServeStale,
		Prefetch:   cfg.Cache.Prefetch,
	}, pol, cache, up, a.access, a.stats, a.hints)
	a.limiter = dnsx.NewLimiter(cfg.Access.RateLimit)

	a.certs, err = certs.New(cfg, a.access)
	if err != nil {
		return nil, err
	}
	var self []netip.Addr
	for _, ip := range []netip.Addr{v4, v6} {
		if ip.IsValid() {
			self = append(self, ip)
		}
	}
	localTLS := proxy.NewLocal(&net.TCPAddr{})
	localHTTP := proxy.NewLocal(&net.TCPAddr{})
	a.locals = []*proxy.Local{localTLS, localHTTP}
	a.proxy = proxy.New(proxy.Options{
		Access:            a.access,
		Policy:            a.res.Policy,
		Lookup:            a.res.LookupNetIP,
		Stats:             a.stats,
		Hints:             a.hints,
		Exits:             cfg.Proxy.Exits,
		Forwards:          cfg.Proxy.Forwards,
		SelfIPs:           self,
		IPv6Egress:        cfg.ProxyIPv6Egress(),
		AllowPrivate:      cfg.Proxy.AllowPrivateDestinations,
		DialTimeout:       cfg.Proxy.DialTimeout,
		HandshakeTimeout:  cfg.Proxy.HandshakeTimeout,
		MaxConns:          cfg.Proxy.MaxConns,
		MaxConnsPerClient: cfg.Proxy.MaxConnsPerClient,
		ConnRate:          cfg.Proxy.ConnRate,
		LocalTLS:          localTLS,
		LocalHTTP:         localHTTP,
	})
	return a, nil
}

func staleWindow(cfg *config.Config) time.Duration {
	if !cfg.Cache.ServeStale {
		return 0
	}
	return cfg.Cache.StaleTTL
}

func (a *App) Start(ctx context.Context) error {
	cfg := a.cfg
	w := web.New(web.Options{
		Host: cfg.Hostname, IPv4: cfg.PublicIPv4, IPv6: cfg.PublicIPv6,
		Access:  a.access,
		DoH:     &dnsx.DoH{R: a.res, Access: a.access},
		Version: a.version,
		Info: func() web.Info {
			p := a.res.Policy()
			return web.Info{ProxyRules: p.Proxy.Len(), BlockRules: p.Block.Len(), CacheSize: a.res.Cache().Len()}
		},
		Proxy:        a.proxy,
		Stats:        a.stats,
		Store:        a.store,
		Apply:        func(d state.Data) { a.access.Update(*a.accCfg.Load(), d) },
		PasswordHash: func() string { return *a.pwHash.Load() },
		AdminPublic:  func() bool { return a.adminPub.Load() },
		Audit:        a.audit,
		SessionsPath: filepath.Join(filepath.Dir(cfg.Resolve(cfg.State)), "admin-sessions.json"),
	})

	httpsSrv := &http.Server{
		Handler:           w.HTTPS(),
		TLSConfig:         a.certs.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          quietLog(),
	}
	httpSrv := &http.Server{
		Handler:           a.certs.HTTPHandler(w.HTTP()),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          quietLog(),
	}
	a.httpSrvs = append(a.httpSrvs, httpsSrv, httpSrv)
	go func() { _ = httpsSrv.ServeTLS(a.locals[0], "", "") }()
	go func() { _ = httpSrv.Serve(a.locals[1]) }()

	if cfg.Listen.HTTPS != "" {
		if err := a.proxy.ServeTLS(cfg.Listen.HTTPS); err != nil {
			return fmt.Errorf("listen https %s: %w", cfg.Listen.HTTPS, err)
		}
	}
	if cfg.Listen.HTTP != "" {
		if err := a.proxy.ServeHTTP(cfg.Listen.HTTP); err != nil {
			return fmt.Errorf("listen http %s: %w", cfg.Listen.HTTP, err)
		}
	}
	if err := a.proxy.ServeForwards(""); err != nil {
		return fmt.Errorf("listen forwards: %w", err)
	}
	if cfg.Listen.DNS != "" {
		s, err := dnsx.PlainServers(cfg.Listen.DNS, a.res, a.access, a.limiter)
		if err != nil {
			return fmt.Errorf("listen dns %s: %w", cfg.Listen.DNS, err)
		}
		a.dnsServers = append(a.dnsServers, s...)
	}
	if cfg.Listen.DoT != "" {
		s, err := dnsx.DoTServer(cfg.Listen.DoT, a.certs.TLSConfig(), a.res, a.access)
		if err != nil {
			return fmt.Errorf("listen dot %s: %w", cfg.Listen.DoT, err)
		}
		a.dnsServers = append(a.dnsServers, s)
	}
	if cfg.Listen.DoQ != "" {
		s, err := dnsx.NewDoQServer(cfg.Listen.DoQ, a.certs.TLSConfig(), a.res, a.access)
		if err != nil {
			return fmt.Errorf("listen doq %s: %w", cfg.Listen.DoQ, err)
		}
		a.doq = s
	}
	if cfg.Listen.Admin != "" {
		ln, err := net.Listen("tcp", cfg.Listen.Admin)
		if err != nil {
			return fmt.Errorf("listen admin %s: %w", cfg.Listen.Admin, err)
		}
		admin := &http.Server{Handler: a.adminHandler(), ReadHeaderTimeout: 5 * time.Second}
		a.httpSrvs = append(a.httpSrvs, admin)
		go func() { _ = admin.Serve(ln) }()
	}

	a.audit.Info("Сервер запущен", "", a.version)
	go a.certs.Warm(ctx)
	go a.maintenance(ctx)
	slog.Info("ReDNS started",
		"host", cfg.Hostname, "ipv4", cfg.PublicIPv4, "ipv6", cfg.PublicIPv6, "mode", cfg.Access.Mode,
		"proxy_rules", a.res.Policy().Proxy.Len(), "block_rules", a.res.Policy().Block.Len())
	return nil
}

func (a *App) maintenance(ctx context.Context) {
	gc := time.NewTicker(time.Minute)
	defer gc.Stop()
	var refresh <-chan time.Time
	if a.cfg.Lists.Refresh > 0 {
		t := time.NewTicker(a.cfg.Lists.Refresh)
		defer t.Stop()
		refresh = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-gc.C:
			a.access.GC()
			a.hints.GC()
			a.proxy.GC()
			a.proxy.GCLimiter()
			a.limiter.GC()
		case <-refresh:
			if err := a.Reload(ctx); err != nil {
				slog.Error("list refresh failed", "err", err)
			}
		}
	}
}

func (a *App) Reload(ctx context.Context) error {
	a.reloadM.Lock()
	defer a.reloadM.Unlock()
	cfg, err := config.Load(a.cfg.Path)
	if err != nil {
		return err
	}

	merged := *a.cfg
	merged.Access = cfg.Access
	merged.Proxy.Lists = cfg.Proxy.Lists
	merged.Proxy.Exclude = cfg.Proxy.Exclude
	merged.Block = cfg.Block
	merged.Hosts = cfg.Hosts
	pol, infos, err := BuildPolicy(ctx, &merged, a.fetcher)
	if err != nil {
		return err
	}
	accCfg := cfg.Access
	a.accCfg.Store(&accCfg)
	hash := cfg.Admin.PasswordHash
	a.pwHash.Store(&hash)
	a.adminPub.Store(cfg.Admin.Public)
	a.access.Update(cfg.Access, a.store.Get())
	a.res.SetPolicy(pol)
	a.infos.Store(&infos)
	a.audit.Info("Конфиг перечитан", "", "")
	slog.Info("reloaded", "proxy_rules", pol.Proxy.Len(), "block_rules", pol.Block.Len(), "tokens", len(cfg.Access.Tokens))
	return nil
}

func (a *App) Shutdown(ctx context.Context) {
	a.proxy.Close()
	for _, l := range a.locals {
		l.Close()
	}
	for _, s := range a.dnsServers {
		_ = s.ShutdownContext(ctx)
	}
	if a.doq != nil {
		_ = a.doq.Close()
	}
	for _, s := range a.httpSrvs {
		_ = s.Shutdown(ctx)
	}
}

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	}
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		snap := a.stats.Snapshot()
		writeJSON(w, map[string]any{
			"version": a.version, "stats": snap, "cache_entries": a.res.Cache().Len(),
			"proxy_rules": a.res.Policy().Proxy.Len(), "block_rules": a.res.Policy().Block.Len(),
		})
	})
	mux.HandleFunc("/querylog", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 {
			n = 100
		}
		writeJSON(w, map[string]any{"seq": a.stats.Log().Seq(), "entries": a.stats.Log().Recent(n, r.URL.Query().Get("q"))})
	})
	mux.HandleFunc("/clients", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.access.Clients())
	})
	mux.HandleFunc("/lists", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, *a.infos.Load())
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		name := lists.Normalize(r.URL.Query().Get("name"))
		act, exit := a.res.Policy().Decide(name)
		writeJSON(w, map[string]string{"name": name, "action": act.String(), "exit": exit})
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := a.Reload(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "reloaded"})
	})
	return mux
}

func quietLog() *log.Logger {
	return slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)
}
