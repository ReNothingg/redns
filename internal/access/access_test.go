package access

import (
	"net/netip"
	"testing"
	"time"

	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/state"
)

const tok = "abcdefghijkl0123"

func newTest(mode string) (*Access, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := New("dns.example.com", config.Access{
		Mode:       mode,
		Tokens:     []config.Token{{Name: "phone", Token: tok}},
		AllowCIDRs: []string{"198.51.100.0/24"},
		AuthTTL:    time.Hour,
	}, state.Data{})
	a.now = func() time.Time { return now }
	return a, &now
}

func TestPrivateAuthorization(t *testing.T) {
	a, now := newTest("private")
	client := netip.MustParseAddr("203.0.113.9")
	if a.Allowed(client) {
		t.Fatal("unknown client must not be allowed")
	}
	if !a.Allowed(netip.MustParseAddr("198.51.100.77")) {
		t.Fatal("allow_cidrs client must be allowed")
	}
	if !a.Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback must be allowed")
	}
	got, ok := a.ValidToken(tok)
	if !ok {
		t.Fatal("token not recognized")
	}
	a.Authorize(client, got)
	if !a.Allowed(client) {
		t.Fatal("authorized client must be allowed")
	}
	if !a.Allowed(netip.MustParseAddr("::ffff:203.0.113.9")) {
		t.Fatal("v4-mapped address must match")
	}
	*now = now.Add(2 * time.Hour)
	if a.Allowed(client) {
		t.Fatal("authorization must expire")
	}
}

func TestIPv6Slash64(t *testing.T) {
	a, _ := newTest("private")
	a.Authorize(netip.MustParseAddr("2001:db8:1:2::aaaa"), tok)
	if !a.Allowed(netip.MustParseAddr("2001:db8:1:2:ffff::1")) {
		t.Fatal("same /64 must be allowed")
	}
	if a.Allowed(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("other /64 must not be allowed")
	}
}

func TestRevokeOnReload(t *testing.T) {
	a, _ := newTest("private")
	client := netip.MustParseAddr("203.0.113.9")
	a.Authorize(client, tok)
	a.Update(config.Access{Mode: "private", Tokens: []config.Token{{Name: "phone", Token: "zzzzzzzzzzzz9999"}}, AuthTTL: time.Hour}, state.Data{})
	if a.Allowed(client) {
		t.Fatal("client authorized by a removed token must lose access")
	}
}

func TestServerNames(t *testing.T) {
	a, _ := newTest("private")
	if _, ok := a.TokenFromServerName(tok + ".dns.example.com"); !ok {
		t.Fatal("token SNI not recognized")
	}
	if _, ok := a.TokenFromServerName("nope12345678.dns.example.com"); ok {
		t.Fatal("bad token accepted")
	}
	if _, ok := a.TokenFromServerName(tok + ".evil.com"); ok {
		t.Fatal("foreign host accepted")
	}
	for name, want := range map[string]bool{
		"dns.example.com":         true,
		"DNS.example.com.":        true,
		"x.dns.example.com":       true,
		"a.b.dns.example.com":     false,
		"chatgpt.com":             false,
		"dns.example.com.evil.io": false,
	} {
		if got := a.IsOwnName(name); got != want {
			t.Errorf("IsOwnName(%q) = %v", name, got)
		}
	}
}

func TestPublicMode(t *testing.T) {
	a, _ := newTest("public")
	if !a.Allowed(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("public mode allows everyone")
	}
}

func TestBansAndPanelTokens(t *testing.T) {
	a, _ := newTest("private")
	cfg := config.Access{Mode: "private", Tokens: []config.Token{{Name: "phone", Token: tok}}, AuthTTL: time.Hour}
	bad := netip.MustParseAddr("203.0.113.50")
	strict := true
	a.Update(cfg, state.Data{
		Bans:        []state.Ban{{Prefix: "203.0.113.0/24"}, {Prefix: "2001:db8:5::/64"}},
		Tokens:      []state.Token{{Name: "laptop", Token: "laptoptoken12345"}},
		Revoked:     []string{tok},
		StrictProxy: &strict,
	})
	if !a.Banned(bad) || a.Allowed(bad) || a.ProxyAllowed(bad) {
		t.Fatal("banned IPv4 must be refused everywhere")
	}
	if !a.Banned(netip.MustParseAddr("2001:db8:5::77")) {
		t.Fatal("banned IPv6 /64")
	}
	a.Authorize(bad, "laptoptoken12345")
	if c, ok := a.Lookup(bad); ok && !c.AuthUntil.IsZero() {
		t.Fatal("banned client must not be authorized")
	}
	if _, ok := a.ValidToken(tok); ok {
		t.Fatal("revoked config token must be invalid")
	}
	if _, ok := a.ValidToken("laptoptoken12345"); !ok {
		t.Fatal("panel token must be valid")
	}
	if !a.Strict() {
		t.Fatal("state override must enable strict proxy")
	}
	good := netip.MustParseAddr("198.51.100.9")
	if a.ProxyAllowed(good) {
		t.Fatal("strict proxy refuses unknown IPs")
	}
	a.Authorize(good, "laptoptoken12345")
	if !a.ProxyAllowed(good) {
		t.Fatal("authorized IP may use the strict proxy")
	}
	if n := a.Deauthorize(netip.MustParsePrefix("198.51.100.0/24")); n != 1 || a.ProxyAllowed(good) {
		t.Fatal("deauthorize must drop the authorization")
	}
	devs := a.Devices()
	if len(devs) != 1 || devs[0].Name != "laptop" || devs[0].Source != "panel" {
		t.Fatalf("devices = %+v", devs)
	}
}
