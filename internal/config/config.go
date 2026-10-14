package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Hostname   string `yaml:"hostname"`
	PublicIPv4 string `yaml:"public_ipv4"`
	PublicIPv6 string `yaml:"public_ipv6"`

	Access   Access   `yaml:"access"`
	Listen   Listen   `yaml:"listen"`
	TLS      TLS      `yaml:"tls"`
	Upstream Upstream `yaml:"upstream"`
	Cache    Cache    `yaml:"cache"`
	Proxy    Proxy    `yaml:"proxy"`
	Block    Block    `yaml:"block"`
	Hosts    []Host   `yaml:"hosts"`
	Lists    Lists    `yaml:"lists"`
	Log      Log      `yaml:"log"`
	Admin    Admin    `yaml:"admin"`
	State    string   `yaml:"state_file"`

	Path string `yaml:"-"`
	Dir  string `yaml:"-"`
}

type Access struct {
	Mode       string        `yaml:"mode"`
	Tokens     []Token       `yaml:"tokens"`
	AllowCIDRs []string      `yaml:"allow_cidrs"`
	AuthTTL    time.Duration `yaml:"auth_ttl"`

	RateLimit int `yaml:"rate_limit"`

	StrictProxy bool `yaml:"strict_proxy"`
}

type Token struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
}

type Listen struct {
	DNS   string `yaml:"dns"`
	DoT   string `yaml:"dot"`
	DoQ   string `yaml:"doq"`
	HTTPS string `yaml:"https"`
	HTTP  string `yaml:"http"`
	Admin string `yaml:"admin"`
}

type TLS struct {
	ACME       bool   `yaml:"acme"`
	Email      string `yaml:"email"`
	CacheDir   string `yaml:"cache_dir"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	SelfSigned bool   `yaml:"self_signed"`

	ACMEDirectory string `yaml:"acme_directory"`
}

type Upstream struct {
	Servers  []string      `yaml:"servers"`
	Fallback []string      `yaml:"fallback"`
	ECS      bool          `yaml:"ecs"`
	Timeout  time.Duration `yaml:"timeout"`
}

type Cache struct {
	Size       int           `yaml:"size"`
	ServeStale bool          `yaml:"serve_stale"`
	StaleTTL   time.Duration `yaml:"stale_ttl"`
	MinTTL     time.Duration `yaml:"min_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
	Prefetch   bool          `yaml:"prefetch"`
}

type Proxy struct {
	Lists   []ListSource `yaml:"lists"`
	Exclude []ListSource `yaml:"exclude"`

	AnswerTTL time.Duration `yaml:"answer_ttl"`
	Forwards  []Forward     `yaml:"forwards"`

	Exits map[string]string `yaml:"exits"`

	AllowAllDomains bool `yaml:"allow_all_domains"`

	AllowPrivateDestinations bool          `yaml:"allow_private_destinations"`
	MaxConns                 int           `yaml:"max_conns"`
	MaxConnsPerClient        int           `yaml:"max_conns_per_client"`
	ConnRate                 int           `yaml:"conn_rate"`
	DialTimeout              time.Duration `yaml:"dial_timeout"`
	HandshakeTimeout         time.Duration `yaml:"handshake_timeout"`

	IPv6Egress string `yaml:"ipv6_egress"`
}

type Forward struct {
	Port       int           `yaml:"port"`
	TargetPort int           `yaml:"target_port"`
	Default    string        `yaml:"default"`
	Targets    []string      `yaml:"targets"`
	HintTTL    time.Duration `yaml:"hint_ttl"`
}

type Block struct {
	Enabled bool         `yaml:"enabled"`
	Lists   []ListSource `yaml:"lists"`
	Allow   []ListSource `yaml:"allow"`
}

type Host struct {
	Name string   `yaml:"name"`
	IPs  []string `yaml:"ips"`
}

type Lists struct {
	Refresh  time.Duration `yaml:"refresh"`
	CacheDir string        `yaml:"cache_dir"`
}

type Admin struct {
	PasswordHash string `yaml:"password_hash"`
	Public       bool   `yaml:"public"`
}

type Log struct {
	Level        string `yaml:"level"`
	QueryLogSize int    `yaml:"querylog_size"`
}

type ListSource struct {
	File    string   `yaml:"file"`
	URL     string   `yaml:"url"`
	Domains []string `yaml:"domains"`

	Via string `yaml:"via"`

	Format string `yaml:"format"`
}

func (s *ListSource) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		v := strings.TrimSpace(n.Value)
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			s.URL = v
		} else {
			s.File = v
		}
		return nil
	}
	type plain ListSource
	return n.Decode((*plain)(s))
}

func (s ListSource) String() string {
	switch {
	case s.URL != "":
		return s.URL
	case s.File != "":
		return s.File
	default:
		return fmt.Sprintf("inline(%d)", len(s.Domains))
	}
}

func Default() *Config {
	return &Config{
		Access: Access{
			Mode:      "private",
			AuthTTL:   24 * time.Hour,
			RateLimit: 50,
		},
		Listen: Listen{
			DNS:   ":53",
			DoT:   ":853",
			DoQ:   ":853",
			HTTPS: ":443",
			HTTP:  ":80",
			Admin: "127.0.0.1:8053",
		},
		TLS: TLS{
			ACME:     true,
			CacheDir: "/var/lib/redns/certs",
		},
		Upstream: Upstream{
			Servers:  []string{"8.8.8.8", "8.8.4.4"},
			Fallback: []string{"1.1.1.1", "9.9.9.9"},
			ECS:      true,
			Timeout:  2500 * time.Millisecond,
		},
		Cache: Cache{
			Size:       100000,
			ServeStale: true,
			StaleTTL:   24 * time.Hour,
			MaxTTL:     24 * time.Hour,
			Prefetch:   true,
		},
		Proxy: Proxy{
			AnswerTTL:         300 * time.Second,
			MaxConns:          20000,
			MaxConnsPerClient: 1000,
			ConnRate:          100,
			DialTimeout:       8 * time.Second,
			HandshakeTimeout:  15 * time.Second,
			IPv6Egress:        "auto",
		},
		Lists: Lists{
			Refresh:  12 * time.Hour,
			CacheDir: "/var/lib/redns/lists",
		},
		Log: Log{
			Level:        "info",
			QueryLogSize: 2000,
		},
		State: "/var/lib/redns/state.json",
	}
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.Path = abs
	c.Dir = filepath.Dir(abs)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) Resolve(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir, p)
}

var (
	tokenRe = regexp.MustCompile(`^[a-z0-9]{12,63}$`)
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func ValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

func (c *Config) Validate() error {
	var errs []error
	c.Hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Hostname)), ".")
	if !ValidHostname(c.Hostname) {
		errs = append(errs, fmt.Errorf("hostname %q is not a valid DNS name", c.Hostname))
	}
	if c.PublicIPv4 == "" && c.PublicIPv6 == "" {
		errs = append(errs, errors.New("public_ipv4 (or public_ipv6) is required"))
	}
	if c.PublicIPv4 != "" {
		if a, err := netip.ParseAddr(c.PublicIPv4); err != nil || !a.Is4() {
			errs = append(errs, fmt.Errorf("public_ipv4 %q is not an IPv4 address", c.PublicIPv4))
		}
	}
	if c.PublicIPv6 != "" {
		if a, err := netip.ParseAddr(c.PublicIPv6); err != nil || !a.Is6() || a.Is4In6() {
			errs = append(errs, fmt.Errorf("public_ipv6 %q is not an IPv6 address", c.PublicIPv6))
		}
	}
	switch c.Access.Mode {
	case "private", "public":
	default:
		errs = append(errs, fmt.Errorf("access.mode must be private or public, got %q", c.Access.Mode))
	}
	seen := map[string]bool{}
	for i, t := range c.Access.Tokens {
		t.Token = strings.ToLower(strings.TrimSpace(t.Token))
		c.Access.Tokens[i].Token = t.Token
		if !tokenRe.MatchString(t.Token) {
			errs = append(errs, fmt.Errorf("access.tokens[%d]: token must be 12-63 chars of [a-z0-9]", i))
		}
		if seen[t.Token] {
			errs = append(errs, fmt.Errorf("access.tokens[%d]: duplicate token", i))
		}
		seen[t.Token] = true
	}
	if c.Access.Mode == "private" && len(c.Access.Tokens) == 0 && len(c.Access.AllowCIDRs) == 0 {
		errs = append(errs, errors.New("access.mode is private but no tokens or allow_cidrs are configured"))
	}
	for _, s := range c.Access.AllowCIDRs {
		if _, err := ParsePrefix(s); err != nil {
			errs = append(errs, fmt.Errorf("access.allow_cidrs: %w", err))
		}
	}
	if c.Access.AuthTTL <= 0 {
		c.Access.AuthTTL = 24 * time.Hour
	}
	if len(c.Upstream.Servers) == 0 {
		errs = append(errs, errors.New("upstream.servers is empty"))
	}
	if c.Upstream.Timeout <= 0 {
		c.Upstream.Timeout = 2500 * time.Millisecond
	}
	if !c.TLS.ACME && !c.TLS.SelfSigned && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls: enable acme, self_signed, or set cert_file and key_file"))
	}
	if c.Proxy.AnswerTTL <= 0 {
		c.Proxy.AnswerTTL = 300 * time.Second
	}
	ports := map[int]bool{}
	for i, f := range c.Proxy.Forwards {
		if f.Port <= 0 || f.Port > 65535 {
			errs = append(errs, fmt.Errorf("proxy.forwards[%d]: bad port %d", i, f.Port))
		}
		if ports[f.Port] {
			errs = append(errs, fmt.Errorf("proxy.forwards[%d]: duplicate port %d", i, f.Port))
		}
		ports[f.Port] = true
		if f.Default == "" && len(f.Targets) == 0 {
			errs = append(errs, fmt.Errorf("proxy.forwards[%d]: needs default or targets", i))
		}
		if f.TargetPort == 0 {
			c.Proxy.Forwards[i].TargetPort = f.Port
		}
		if f.HintTTL <= 0 {
			c.Proxy.Forwards[i].HintTTL = 24 * time.Hour
		}
	}
	for name, addr := range c.Proxy.Exits {
		if _, _, err := splitHostPortDefault(addr, "443"); err != nil || name == "" {
			errs = append(errs, fmt.Errorf("proxy.exits[%s]: bad address %q", name, addr))
		}
	}
	for _, s := range c.Proxy.Lists {
		if s.Via != "" {
			if _, ok := c.Proxy.Exits[s.Via]; !ok {
				errs = append(errs, fmt.Errorf("proxy.lists %s: via %q is not defined in proxy.exits", s, s.Via))
			}
		}
	}
	switch c.Proxy.IPv6Egress {
	case "", "auto", "on", "off":
	default:
		errs = append(errs, fmt.Errorf("proxy.ipv6_egress must be auto, on or off"))
	}
	for i, h := range c.Hosts {
		if h.Name == "" || len(h.IPs) == 0 {
			errs = append(errs, fmt.Errorf("hosts[%d]: needs name and ips", i))
		}
		for _, ip := range h.IPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				errs = append(errs, fmt.Errorf("hosts[%d]: %w", i, err))
			}
		}
	}
	if c.Cache.Size <= 0 {
		c.Cache.Size = 100000
	}
	if c.Cache.MaxTTL <= 0 {
		c.Cache.MaxTTL = 24 * time.Hour
	}
	if c.Lists.Refresh > 0 && c.Lists.Refresh < 10*time.Minute {
		c.Lists.Refresh = 10 * time.Minute
	}
	return errors.Join(errs...)
}

func (c *Config) ProxyIPv6Egress() bool {
	switch c.Proxy.IPv6Egress {
	case "on":
		return true
	case "off":
		return false
	default:
		return c.PublicIPv6 != ""
	}
}

func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func splitHostPortDefault(addr, port string) (string, string, error) {
	if addr == "" {
		return "", "", errors.New("empty address")
	}
	if !strings.Contains(addr, ":") || (strings.Count(addr, ":") > 1 && !strings.HasPrefix(addr, "[")) {
		return addr, port, nil
	}
	i := strings.LastIndex(addr, ":")
	h, p := strings.Trim(addr[:i], "[]"), addr[i+1:]
	if h == "" || p == "" {
		return "", "", fmt.Errorf("bad address %q", addr)
	}
	return h, p, nil
}

func HostPort(addr, port string) string {
	h, p, err := splitHostPortDefault(addr, port)
	if err != nil {
		return addr
	}
	if strings.Contains(h, ":") {
		return "[" + h + "]:" + p
	}
	return h + ":" + p
}
