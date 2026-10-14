package lists

import (
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in   string
		want []Rule
	}{
		{"chatgpt.com", []Rule{{Kind: Suffix, Value: "chatgpt.com"}}},
		{"  OpenAI.COM.  ", []Rule{{Kind: Suffix, Value: "openai.com"}}},
		{"*.claude.ai", []Rule{{Kind: Suffix, Value: "claude.ai"}}},
		{".anthropic.com", []Rule{{Kind: Suffix, Value: "anthropic.com"}}},
		{"=api.github.com", []Rule{{Kind: Exact, Value: "api.github.com"}}},
		{"full:www.tiktok.com", []Rule{{Kind: Exact, Value: "www.tiktok.com"}}},
		{"domain:x.ai @ads", []Rule{{Kind: Suffix, Value: "x.ai"}}},
		{"keyword:spotify", []Rule{{Kind: Keyword, Value: "spotify"}}},
		{`regexp:^ap-[a-z0-9]+\.spotify\.com$`, []Rule{{Kind: Regexp, Value: `^ap-[a-z0-9]+\.spotify\.com$`}}},
		{"0.0.0.0 ads.example.com tracker.example.com", []Rule{{Kind: Exact, Value: "ads.example.com"}, {Kind: Exact, Value: "tracker.example.com"}}},
		{":: ads6.example.com", []Rule{{Kind: Exact, Value: "ads6.example.com"}}},
		{"127.0.0.1 localhost", nil},
		{"||doubleclick.net^", []Rule{{Kind: Suffix, Value: "doubleclick.net"}}},
		{"||ads.example.org^$important", []Rule{{Kind: Suffix, Value: "ads.example.org"}}},
		{"@@||allowed.example.org^", []Rule{{Kind: Suffix, Value: "allowed.example.org", Exception: true}}},
		{"|exact.example.org^", []Rule{{Kind: Exact, Value: "exact.example.org"}}},
		{"||example.org^$dnstype=AAAA", nil},
		{"||ads*.example.org^", nil},
		{"/banner[0-9]+/", nil},
		{"example.com##.banner", nil},
		{"# comment", nil},
		{"! adblock comment", nil},
		{"com", nil},
		{"bad..name.com", nil},
		{"name.com # trailing comment", []Rule{{Kind: Suffix, Value: "name.com"}}},
	}
	for _, c := range cases {
		got := ParseLine(c.in)
		if len(got) != len(c.want) {
			t.Errorf("ParseLine(%q) = %+v, want %+v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseLine(%q)[%d] = %+v, want %+v", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestMatch(t *testing.T) {
	r := NewRules()
	src := `
openai.com
full:www.tiktok.com
regexp:^ap-[a-z0-9]+\.spotify\.com$
`
	if err := Parse(strings.NewReader(src), func(rule Rule) { r.Add(rule, "") }); err != nil {
		t.Fatal(err)
	}
	r.Add(Rule{Kind: Suffix, Value: "grok.com"}, "us")
	r.Add(Rule{Kind: Suffix, Value: "grok.com"}, "eu")

	for name, want := range map[string]bool{
		"openai.com":          true,
		"api.openai.com":      true,
		"a.b.c.openai.com":    true,
		"notopenai.com":       false,
		"openai.com.evil.net": false,
		"www.tiktok.com":      true,
		"m.tiktok.com":        false,
		"tiktok.com":          false,
		"ap-gew4.spotify.com": true,
		"api.spotify.com":     false,
		"":                    false,
	} {
		if _, got := r.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
	if tag, _ := r.Match("assets.grok.com"); tag != "us" {
		t.Errorf("tag = %q, want us", tag)
	}
	if r.Len() != 4 {
		t.Errorf("Len = %d, want 4", r.Len())
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("ChatGPT.COM."); got != "chatgpt.com" {
		t.Fatal(got)
	}
	if got := Normalize("x.ai"); got != "x.ai" {
		t.Fatal(got)
	}
}
