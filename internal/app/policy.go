package app

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/dnsx"
	"github.com/renothingg/redns/internal/lists"
)

type ListInfo struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Rules  int    `json:"rules"`
	Stale  bool   `json:"stale,omitempty"`
	Error  string `json:"error,omitempty"`
}

type loaded struct {
	rules []lists.Rule
	info  ListInfo
	err   error
}

func load(ctx context.Context, cfg *config.Config, f *lists.Fetcher, kind string, s config.ListSource) loaded {
	l := loaded{info: ListInfo{Kind: kind, Source: s.String()}}
	var body []byte
	switch {
	case s.URL != "":
		b, stale, err := f.Fetch(ctx, s.URL)
		if err != nil {
			l.info.Error = err.Error()
			return l
		}
		body, l.info.Stale = b, stale
	case s.File != "":
		b, err := os.ReadFile(cfg.Resolve(s.File))
		if err != nil {
			l.err = err
			l.info.Error = err.Error()
			return l
		}
		body = b
	default:
		body = []byte(strings.Join(s.Domains, "\n"))
	}
	_ = lists.Parse(bytes.NewReader(body), func(r lists.Rule) { l.rules = append(l.rules, r) })
	l.info.Rules = len(l.rules)
	return l
}

func BuildPolicy(ctx context.Context, cfg *config.Config, f *lists.Fetcher) (*dnsx.Policy, []ListInfo, error) {
	type job struct {
		kind string
		src  config.ListSource
	}
	var jobs []job
	for _, s := range cfg.Proxy.Lists {
		jobs = append(jobs, job{"proxy", s})
	}
	for _, s := range cfg.Proxy.Exclude {
		jobs = append(jobs, job{"exclude", s})
	}
	if cfg.Block.Enabled {
		for _, s := range cfg.Block.Lists {
			jobs = append(jobs, job{"block", s})
		}
		for _, s := range cfg.Block.Allow {
			jobs = append(jobs, job{"allow", s})
		}
	}
	results := make([]loaded, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			results[i] = load(ctx, cfg, f, j.kind, j.src)
		}(i, j)
	}
	wg.Wait()

	p := &dnsx.Policy{
		Host:     cfg.Hostname,
		Proxy:    lists.NewRules(),
		Exclude:  lists.NewRules(),
		Allow:    lists.NewRules(),
		Hosts:    map[string][]netip.Addr{},
		AllowAll: cfg.Proxy.AllowAllDomains,
		Canaries: true,
	}
	if cfg.Block.Enabled {
		p.Block = lists.NewRules()
	}
	var infos []ListInfo
	for i, res := range results {
		if res.err != nil {
			return nil, nil, fmt.Errorf("%s list %s: %w", res.info.Kind, res.info.Source, res.err)
		}
		if res.info.Error != "" {
			slog.Warn("list unavailable", "kind", res.info.Kind, "source", res.info.Source, "err", res.info.Error)
		}
		infos = append(infos, res.info)
		via := jobs[i].src.Via
		for _, r := range res.rules {
			switch res.info.Kind {
			case "proxy":
				if !r.Exception {
					p.Proxy.Add(r, via)
				}
			case "exclude":
				p.Exclude.Add(r, "")
			case "block":
				if r.Exception {
					p.Allow.Add(r, "")
				} else {
					p.Block.Add(r, "")
				}
			case "allow":
				p.Allow.Add(r, "")
			}
		}
	}
	for _, h := range cfg.Hosts {
		name := lists.Normalize(h.Name)
		for _, s := range h.IPs {
			if a, err := netip.ParseAddr(s); err == nil {
				p.Hosts[name] = append(p.Hosts[name], a.Unmap())
			}
		}
	}
	return p, infos, nil
}
