package dnsx

import (
	"net/netip"
	"strings"

	"github.com/renothingg/redns/internal/lists"
)

type Action uint8

const (
	ActForward Action = iota
	ActProxy
	ActBlock
	ActSelf
	ActHosts
	ActNXDomain
)

func (a Action) String() string {
	switch a {
	case ActProxy:
		return "proxy"
	case ActBlock:
		return "block"
	case ActSelf:
		return "self"
	case ActHosts:
		return "hosts"
	case ActNXDomain:
		return "nxdomain"
	default:
		return "forward"
	}
}

var canaries = map[string]bool{
	"use-application-dns.net": true,
	"mask.icloud.com":         true,
	"mask-h2.icloud.com":      true,
}

type Policy struct {
	Host    string
	Proxy   *lists.Rules
	Exclude *lists.Rules
	Block   *lists.Rules
	Allow   *lists.Rules
	Hosts   map[string][]netip.Addr

	AllowAll bool

	Canaries bool
}

func (p *Policy) isSelf(name string) bool {
	if name == p.Host {
		return true
	}
	_, rest, ok := strings.Cut(name, ".")
	return ok && rest == p.Host
}

func (p *Policy) Decide(name string) (Action, string) {
	if p.isSelf(name) {
		return ActSelf, ""
	}
	if _, ok := p.Hosts[name]; ok {
		return ActHosts, ""
	}
	if p.Canaries && canaries[name] {
		return ActNXDomain, ""
	}
	if tag, ok := p.proxied(name); ok {
		return ActProxy, tag
	}
	if p.Block != nil {
		if _, ok := p.Block.Match(name); ok {
			if _, allowed := p.Allow.Match(name); !allowed {
				return ActBlock, ""
			}
		}
	}
	return ActForward, ""
}

func (p *Policy) proxied(name string) (string, bool) {
	tag, ok := p.Proxy.Match(name)
	if !ok {
		return "", false
	}
	if _, ex := p.Exclude.Match(name); ex {
		return "", false
	}
	return tag, true
}

func (p *Policy) ProxyTarget(name string) (string, bool) {
	if tag, ok := p.proxied(name); ok {
		return tag, true
	}
	if p.AllowAll && !p.isSelf(name) {
		return "", true
	}
	return "", false
}
