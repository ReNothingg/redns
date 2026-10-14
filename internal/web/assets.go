package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

//go:embed assets templates
var files embed.FS

var (
	setupTmpl    = template.Must(template.ParseFS(files, "templates/setup.html"))
	adminTmpl    = template.Must(template.ParseFS(files, "templates/admin.html"))
	icons        = sprite()
	styles       = map[string][]byte{"css/admin.css": bundle("css/admin.css"), "css/setup.css": bundle("css/setup.css")}
	assetVersion = version()
)

var importRule = regexp.MustCompile(`^@import "([^"]+)";$`)

func bundle(entry string) []byte {
	raw, err := fs.ReadFile(files, "assets/"+entry)
	if err != nil {
		panic(err)
	}
	var b bytes.Buffer
	for _, line := range strings.Split(string(raw), "\n") {
		if m := importRule.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			b.Write(bundle(path.Join(path.Dir(entry), m[1])))
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func sprite() template.HTML {
	entries, err := fs.ReadDir(files, "assets/icons")
	if err != nil {
		panic(err)
	}
	var b strings.Builder
	b.WriteString(`<svg class="sprite" aria-hidden="true"><defs>`)
	for _, e := range entries {
		raw, err := fs.ReadFile(files, "assets/icons/"+e.Name())
		if err != nil {
			panic(err)
		}
		svg := strings.TrimSpace(string(raw))
		svg = strings.Replace(svg, ` xmlns="http://www.w3.org/2000/svg"`, "", 1)
		svg = strings.TrimSuffix(strings.TrimPrefix(svg, "<svg"), "</svg>")
		b.WriteString(`<symbol id="i-` + strings.TrimSuffix(e.Name(), ".svg") + `"` + svg + `</symbol>`)
	}
	b.WriteString(`</defs></svg>`)
	return template.HTML(b.String())
}

func version() string {
	h := sha256.New()
	_ = fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			raw, _ := files.ReadFile(p)
			h.Write([]byte(p))
			h.Write(raw)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func staticFiles() http.Handler {
	static, _ := fs.Sub(files, "assets")
	server := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "public, max-age=86400")
		if css, ok := styles[r.URL.Path]; ok {
			rw.Header().Set("Content-Type", "text/css; charset=utf-8")
			_, _ = rw.Write(css)
			return
		}
		server.ServeHTTP(rw, r)
	})
}
