package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"

	"github.com/renothingg/redns/internal/config"
)

const renewBefore = 30 * 24 * time.Hour

type wildcard struct {
	host       string
	ipv4, ipv6 string
	dir        string
	email      string
	directory  string
	cf         *cloudflare

	mu   sync.RWMutex
	cert *tls.Certificate
}

func newWildcard(cfg *config.Config) *wildcard {
	dir := cfg.TLS.ACMEDirectory
	if dir == "" {
		dir = acme.LetsEncryptURL
	}
	return &wildcard{
		host: cfg.Hostname, ipv4: cfg.PublicIPv4, ipv6: cfg.PublicIPv6,
		dir: cfg.Resolve(cfg.TLS.CacheDir), email: cfg.TLS.Email, directory: dir,
		cf: newCloudflare(cfg.TLS.Cloudflare),
	}
}

func (w *wildcard) get(name string) *tls.Certificate {
	label, rest, ok := strings.Cut(name, ".")
	if !ok || label == "" || rest != w.host {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cert
}

func (w *wildcard) ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cert != nil
}

func (w *wildcard) fresh() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cert != nil && time.Until(w.cert.Leaf.NotAfter) > renewBefore
}

func (w *wildcard) path(name string) string { return filepath.Join(w.dir, name) }

func (w *wildcard) load() error {
	c, err := tls.LoadX509KeyPair(w.path("wildcard.crt"), w.path("wildcard.key"))
	if err != nil {
		return err
	}
	if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
		return err
	}
	w.mu.Lock()
	w.cert = &c
	w.mu.Unlock()
	return nil
}

func (w *wildcard) run(ctx context.Context) {
	if w.load() == nil {
		slog.Info("wildcard certificate loaded", "host", "*."+w.host)
	}
	for {
		wait := 12 * time.Hour
		if err := w.ensureRecords(ctx); err != nil {
			slog.Error("wildcard DNS record", "err", err)
			wait = time.Hour
		}
		if !w.fresh() {
			if err := w.issue(ctx); err != nil {
				slog.Error("wildcard certificate not issued", "err", err)
				wait = time.Hour
			} else {
				slog.Info("wildcard certificate issued", "host", "*."+w.host)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (w *wildcard) ensureRecords(ctx context.Context) error {
	z, err := w.cf.zone(ctx, w.host)
	if err != nil {
		return err
	}
	name := "*." + w.host
	for _, r := range []struct{ typ, ip string }{{"A", w.ipv4}, {"AAAA", w.ipv6}} {
		if r.ip == "" {
			continue
		}
		recs, err := w.cf.records(ctx, z.ID, r.typ, name)
		if err != nil {
			return err
		}
		if len(recs) > 0 {
			continue
		}
		if _, err := w.cf.create(ctx, z.ID, cfRecord{Type: r.typ, Name: name, Content: r.ip, TTL: 1}); err != nil {
			return err
		}
		slog.Info("DNS record created", "name", name, "type", r.typ, "ip", r.ip)
	}
	return nil
}

func (w *wildcard) accountKey() (*ecdsa.PrivateKey, error) {
	p := w.path("dns01-account.key")
	if raw, err := os.ReadFile(p); err == nil {
		if b, _ := pem.Decode(raw); b != nil {
			return x509.ParseECPrivateKey(b.Bytes)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

func (w *wildcard) issue(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	z, err := w.cf.zone(ctx, w.host)
	if err != nil {
		return err
	}
	key, err := w.accountKey()
	if err != nil {
		return err
	}
	client := &acme.Client{Key: key, DirectoryURL: w.directory}
	acct := &acme.Account{}
	if w.email != "" {
		acct.Contact = []string{"mailto:" + w.email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return err
	}
	names := []string{"*." + w.host, w.host}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return err
	}
	var created []string
	defer func() {
		for _, id := range created {
			_ = w.cf.remove(context.Background(), z.ID, id)
		}
	}()
	var pending []*acme.Challenge
	var values []string
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return errors.New("acme: no dns-01 challenge offered")
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		id, err := w.cf.create(ctx, z.ID, cfRecord{Type: "TXT", Name: "_acme-challenge." + authz.Identifier.Value, Content: value, TTL: 60})
		if err != nil {
			return err
		}
		created = append(created, id)
		pending = append(pending, chal)
		values = append(values, value)
	}
	if err := waitTXT(ctx, z.NameServers, "_acme-challenge."+w.host, values); err != nil {
		return err
	}
	for _, c := range pending {
		if _, err := client.Accept(ctx, c); err != nil {
			return err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return err
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, certKey)
	if err != nil {
		return err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(w.path("wildcard.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(w.path("wildcard.crt"), certPEM, 0o600); err != nil {
		return err
	}
	return w.load()
}

func waitTXT(ctx context.Context, servers []string, name string, want []string) error {
	if len(want) == 0 {
		return nil
	}
	addrs := make([]string, len(servers))
	for i, s := range servers {
		addrs[i] = net.JoinHostPort(s, "53")
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if hasTXT(addrs, name, want) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TXT %s не появилась у NS Cloudflare за 3 минуты", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func hasTXT(addrs []string, name string, want []string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.RecursionDesired = false
	c := &dns.Client{Timeout: 5 * time.Second}
	for _, a := range addrs {
		r, _, err := c.Exchange(m, a)
		if err != nil || r == nil {
			continue
		}
		got := map[string]bool{}
		for _, rr := range r.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				got[strings.Join(t.Txt, "")] = true
			}
		}
		for _, v := range want {
			if !got[v] {
				return false
			}
		}
		return true
	}
	return false
}
