package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/renothingg/redns/internal/app"
	"github.com/renothingg/redns/internal/config"
	"github.com/renothingg/redns/internal/lists"
	"github.com/renothingg/redns/internal/stats"
	"github.com/renothingg/redns/internal/web"
)

var version = "dev"

const defaultConfig = "/etc/redns/config.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `ReDNS %s — smart DNS + SNI proxy

Usage:
  redns run      [-c config]          start the server
  redns check    [-c config]          validate config and load all lists
  redns token                         print a new random access token
  redns passwd   [-c config] [-q]     set a new random admin panel password
  redns profile  [-c config] -token T [-only doh|dot]   print an Apple .mobileconfig
  redns stats    [-admin addr]        counters, top proxied names
  redns log      [-admin addr] [-n N] [-f] [filter]   recent DNS queries
  redns clients  [-admin addr]        known/authorized clients
  redns lists    [-admin addr]        loaded lists and rule counts
  redns why      [-admin addr] name   which rule handles a name
  redns reload   [-admin addr]        reload lists, tokens, allow lists
  redns version
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "check":
		err = cmdCheck(args)
	case "token":
		fmt.Println(newToken())
	case "passwd":
		err = cmdPasswd(args)
	case "profile":
		err = cmdProfile(args)
	case "stats", "log", "clients", "lists", "why", "reload":
		err = cmdAdmin(cmd, args)
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("c", defaultConfig, "config file")
}

func setupLogging(level string) {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: l,

		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 && os.Getenv("JOURNAL_STREAM") != "" {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := configFlag(fs)
	_ = fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	setupLogging(cfg.Log.Level)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	a, err := app.New(startCtx, cfg, version)
	cancel()
	if err != nil {
		return err
	}
	if err := a.Start(ctx); err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for {
		select {
		case <-hup:
			if err := a.Reload(ctx); err != nil {
				slog.Error("reload failed, keeping previous config", "err", err)
			}
		case <-ctx.Done():
			slog.Info("shutting down")
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			a.Shutdown(sctx)
			cancel()
			return nil
		}
	}
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := configFlag(fs)
	_ = fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pol, infos, err := app.BuildPolicy(ctx, cfg, lists.NewFetcher(cfg.Resolve(cfg.Lists.CacheDir)))
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tRULES\tSOURCE\tNOTE")
	for _, i := range infos {
		note := ""
		if i.Stale {
			note = "cached copy"
		}
		if i.Error != "" {
			note = i.Error
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", i.Kind, i.Rules, i.Source, note)
	}
	tw.Flush()
	fmt.Printf("\nconfig OK: host=%s mode=%s proxy_rules=%d block_rules=%d tokens=%d\n",
		cfg.Hostname, cfg.Access.Mode, pol.Proxy.Len(), pol.Block.Len(), len(cfg.Access.Tokens))
	return nil
}

func newToken() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newPassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

var hashLine = regexp.MustCompile(`(?m)^([ \t]*password_hash:).*$`)
var adminLine = regexp.MustCompile(`(?m)^admin:[ \t]*$`)

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	path := configFlag(fs)
	quiet := fs.Bool("q", false, "print only the password")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	st, err := os.Stat(*path)
	if err != nil {
		return err
	}
	pw := newPassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	value := ` "` + string(hash) + `"`
	switch {
	case hashLine.Match(raw):
		raw = hashLine.ReplaceAllFunc(raw, func(m []byte) []byte {
			return append(hashLine.FindSubmatch(m)[1], value...)
		})
	case adminLine.Match(raw):
		loc := adminLine.FindIndex(raw)
		raw = append(raw[:loc[1]:loc[1]], append([]byte("\n  password_hash:"+value), raw[loc[1]:]...)...)
	default:
		raw = append(raw, []byte("\nadmin:\n  password_hash:"+value+"\n")...)
	}
	tmp := *path + ".tmp"
	if err := os.WriteFile(tmp, raw, st.Mode().Perm()); err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmp, int(sys.Uid), int(sys.Gid))
	}
	if err := os.Rename(tmp, *path); err != nil {
		return err
	}
	if *quiet {
		fmt.Println(pw)
		return nil
	}
	if err := exec.Command("systemctl", "reload", "redns").Run(); err != nil {
		fmt.Printf("Новый пароль админки: %s\nЧтобы он заработал: sudo systemctl reload redns\n", pw)
		return nil
	}
	fmt.Printf("Новый пароль админки: %s\nУже действует, старый больше не подходит.\n", pw)
	return nil
}

func cmdProfile(args []string) error {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	path := configFlag(fs)
	tokenName := fs.String("token", "", "token name or value (private mode)")
	only := fs.String("only", "", "doh or dot; both by default")
	_ = fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	tok, label := "", ""
	for _, t := range cfg.Access.Tokens {
		if t.Name == *tokenName || t.Token == *tokenName {
			tok, label = t.Token, t.Name
		}
	}
	if *tokenName != "" && tok == "" {
		return fmt.Errorf("token %q not found in config", *tokenName)
	}
	if cfg.Access.Mode == "private" && tok == "" {
		return fmt.Errorf("private mode: pass -token <name>")
	}
	p := web.ProfileParams{
		Host: cfg.Hostname, Label: label, Only: *only, Consent: web.Agreement(cfg.Hostname),
		DoHURL: "https://" + cfg.Hostname + "/dns-query", DoTName: cfg.Hostname,
	}
	if tok != "" {
		p.DoHURL += "/" + tok
	}
	if cfg.Access.Mode == "private" {
		p.Only = "doh"
	}
	for _, a := range []string{cfg.PublicIPv4, cfg.PublicIPv6} {
		if a != "" {
			p.Addresses = append(p.Addresses, a)
		}
	}
	_, err = os.Stdout.Write(web.Profile(p))
	return err
}

func adminGet(addr, path string, out any) error {
	resp, err := http.Get("http://" + addr + path)
	if err != nil {
		return fmt.Errorf("%w (is redns running? admin API listens on %s)", err, addr)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func cmdAdmin(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	addr := fs.String("admin", "127.0.0.1:8053", "admin API address")
	n := fs.Int("n", 50, "number of log entries")
	follow := fs.Bool("f", false, "follow the query log")
	_ = fs.Parse(args)
	switch cmd {
	case "stats", "clients", "lists":
		var v any
		if err := adminGet(*addr, "/"+cmd, &v); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	case "why":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: redns why <name>")
		}
		var v map[string]string
		if err := adminGet(*addr, "/check?name="+url.QueryEscape(fs.Arg(0)), &v); err != nil {
			return err
		}
		fmt.Printf("%s → %s", v["name"], v["action"])
		if v["exit"] != "" {
			fmt.Printf(" via %s", v["exit"])
		}
		fmt.Println()
	case "reload":
		resp, err := http.Post("http://"+*addr+"/reload", "text/plain", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Println(strings.TrimSpace(string(body)))
	case "log":
		filter := url.QueryEscape(fs.Arg(0))
		var lastSeq uint64
		var lastTime time.Time
		for {
			var v struct {
				Seq     uint64        `json:"seq"`
				Entries []stats.Entry `json:"entries"`
			}
			if err := adminGet(*addr, fmt.Sprintf("/querylog?n=%d&q=%s", *n, filter), &v); err != nil {
				return err
			}
			if v.Seq != lastSeq {
				for _, e := range v.Entries {
					if !e.Time.After(lastTime) {
						continue
					}
					fmt.Printf("%s  %-15s %-4s %-8s %-6s %-40s %s %s\n", e.Time.Format("15:04:05"), e.Client, e.Proto,
						e.Action, e.Type, e.Name, e.Rcode, e.Answer)
					lastTime = e.Time
				}
				lastSeq = v.Seq
			}
			if !*follow {
				return nil
			}
			time.Sleep(time.Second)
		}
	}
	return nil
}
