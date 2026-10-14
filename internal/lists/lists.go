package lists

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

type Kind uint8

const (
	Suffix Kind = iota
	Exact
	Keyword
	Regexp
)

type Rule struct {
	Kind  Kind
	Value string

	Exception bool
}

type rx struct {
	re  *regexp.Regexp
	tag string
}

type kw struct {
	s   string
	tag string
}

type Rules struct {
	exact    map[string]string
	suffix   map[string]string
	keywords []kw
	regexps  []rx
}

func NewRules() *Rules {
	return &Rules{exact: map[string]string{}, suffix: map[string]string{}}
}

func (r *Rules) Add(rule Rule, tag string) {
	switch rule.Kind {
	case Exact:
		if _, ok := r.exact[rule.Value]; !ok {
			r.exact[rule.Value] = tag
		}
	case Suffix:
		if _, ok := r.suffix[rule.Value]; !ok {
			r.suffix[rule.Value] = tag
		}
	case Keyword:
		r.keywords = append(r.keywords, kw{rule.Value, tag})
	case Regexp:
		if re, err := regexp.Compile(rule.Value); err == nil {
			r.regexps = append(r.regexps, rx{re, tag})
		}
	}
}

func (r *Rules) Len() int {
	if r == nil {
		return 0
	}
	return len(r.exact) + len(r.suffix) + len(r.keywords) + len(r.regexps)
}

func (r *Rules) Match(name string) (string, bool) {
	if r == nil || name == "" {
		return "", false
	}
	if tag, ok := r.exact[name]; ok {
		return tag, true
	}
	for s := name; ; {
		if tag, ok := r.suffix[s]; ok {
			return tag, true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	for _, k := range r.keywords {
		if strings.Contains(name, k.s) {
			return k.tag, true
		}
	}
	for _, x := range r.regexps {
		if x.re.MatchString(name) {
			return x.tag, true
		}
	}
	return "", false
}

func Normalize(name string) string {
	name = strings.TrimSuffix(name, ".")
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(name)
		}
	}
	return name
}

func Parse(rd io.Reader, fn func(Rule)) error {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		for _, r := range ParseLine(sc.Text()) {
			fn(r)
		}
	}
	return sc.Err()
}

var hostsIPs = map[string]bool{
	"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true, "0": true,
	"::0": true, "0:0:0:0:0:0:0:0": true, "255.255.255.255": true,
}

func ParseLine(line string) []Rule {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' || strings.HasPrefix(line, "//") {
		return nil
	}

	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "|") ||
		strings.HasSuffix(line, "^") || strings.Contains(line, "^$") {
		if r, ok := parseAdblock(line); ok {
			return []Rule{r}
		}
		return nil
	}
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, "\t#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	if k, v, ok := strings.Cut(line, ":"); ok && (k == "full" || k == "domain" || k == "keyword" || k == "regexp" || k == "include") {

		if i := strings.IndexAny(v, " \t"); i >= 0 {
			v = v[:i]
		}
		switch k {
		case "full":
			if d, ok := cleanDomain(v); ok {
				return []Rule{{Kind: Exact, Value: d}}
			}
		case "domain":
			if d, ok := cleanDomain(v); ok {
				return []Rule{{Kind: Suffix, Value: d}}
			}
		case "keyword":
			v = strings.ToLower(v)
			if v != "" {
				return []Rule{{Kind: Keyword, Value: v}}
			}
		case "regexp":
			if _, err := regexp.Compile(v); err == nil && v != "" {
				return []Rule{{Kind: Regexp, Value: v}}
			}
		}
		return nil
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 && hostsIPs[fields[0]] {
		var out []Rule
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break
			}
			if d, ok := cleanDomain(f); ok {
				out = append(out, Rule{Kind: Exact, Value: d})
			}
		}
		return out
	}
	if len(fields) != 1 {
		return nil
	}
	v := fields[0]
	switch {
	case strings.HasPrefix(v, "*."):
		v = v[2:]
	case strings.HasPrefix(v, "."):
		v = v[1:]
	case strings.HasPrefix(v, "="):
		if d, ok := cleanDomain(v[1:]); ok {
			return []Rule{{Kind: Exact, Value: d}}
		}
		return nil
	}
	if d, ok := cleanDomain(v); ok {
		return []Rule{{Kind: Suffix, Value: d}}
	}
	return nil
}

func parseAdblock(line string) (Rule, bool) {
	var r Rule
	if strings.HasPrefix(line, "@@") {
		r.Exception = true
		line = line[2:]
	}
	if i := strings.IndexByte(line, '$'); i >= 0 {
		for _, m := range strings.Split(line[i+1:], ",") {
			switch m {
			case "important", "all", "third-party", "3p", "document", "doc", "popup":
			default:
				return r, false
			}
		}
		line = line[:i]
	}
	switch {
	case strings.HasPrefix(line, "||"):
		r.Kind = Suffix
		line = line[2:]
	case strings.HasPrefix(line, "|"):
		r.Kind = Exact
		line = line[1:]
	default:
		r.Kind = Suffix
	}
	line = strings.TrimSuffix(line, "|")
	line = strings.TrimSuffix(line, "^")
	if strings.ContainsAny(line, "/*?=&:") {
		return r, false
	}
	d, ok := cleanDomain(line)
	if !ok {
		return r, false
	}
	r.Value = d
	return r, true
}

func cleanDomain(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	prevDot := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			prevDot = false
		case c == '.':
			if prevDot {
				return "", false
			}
			prevDot = true
		default:
			return "", false
		}
	}
	if prevDot {
		return "", false
	}
	return s, true
}
