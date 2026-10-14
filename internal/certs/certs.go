package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/renothingg/redns/internal/access"
	"github.com/renothingg/redns/internal/config"
)

type Manager struct {
	host   string
	access *access.Access
	acme   *autocert.Manager
	guard  *issueGuard
	wild   *wildcard

	certFile, keyFile string
	mu                sync.Mutex
	static            *tls.Certificate
	staticMod         time.Time
	staticChecked     time.Time
}

func New(cfg *config.Config, acc *access.Access) (*Manager, error) {
	m := &Manager{host: cfg.Hostname, access: acc}
	switch {
	case cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "":
		m.certFile, m.keyFile = cfg.Resolve(cfg.TLS.CertFile), cfg.Resolve(cfg.TLS.KeyFile)
		if _, err := m.loadStatic(); err != nil {
			return nil, err
		}
	case cfg.TLS.SelfSigned:
		c, err := SelfSigned(cfg.Hostname)
		if err != nil {
			return nil, err
		}
		m.static = c
	case cfg.TLS.ACME:
		if err := os.MkdirAll(cfg.Resolve(cfg.TLS.CacheDir), 0o700); err != nil {
			return nil, err
		}
		m.acme = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.Resolve(cfg.TLS.CacheDir)),
			HostPolicy: m.hostPolicy,
			Email:      cfg.TLS.Email,
		}
		if cfg.TLS.ACMEDirectory != "" {
			m.acme.Client = &acme.Client{DirectoryURL: cfg.TLS.ACMEDirectory}
		}
		m.guard = newIssueGuard(cfg.PublicIPv4, cfg.PublicIPv6)
		if cfg.TLS.Cloudflare != "" {
			m.wild = newWildcard(cfg)
		}
	default:
		return nil, errors.New("no TLS certificate source configured")
	}
	return m, nil
}

func (m *Manager) hostPolicy(_ context.Context, host string) error {
	if host == m.host {
		return nil
	}
	return fmt.Errorf("host %q not allowed", host)
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.acme == nil {
		if m.certFile != "" {
			return m.loadStatic()
		}
		return m.static, nil
	}
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if m.wild != nil {
		if c := m.wild.get(name); c != nil {
			return c, nil
		}
	}
	if m.hostPolicy(context.Background(), name) != nil {

		h := *hello
		h.ServerName = m.host
		return m.acmeCert(&h)
	}
	return m.acmeCert(hello)
}

func (m *Manager) acmeCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, p := range hello.SupportedProtos {
		if p == acme.ALPNProto {
			return m.acme.GetCertificate(hello)
		}
	}
	name := strings.ToLower(hello.ServerName)
	if !m.guard.isReady(name) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, cacheErr := m.acme.Cache.Get(ctx, name)
		cancel()
		if cacheErr == nil {
			m.guard.markReady(name)
		} else if err := m.guard.check(name); err != nil {
			return nil, err
		}
	}
	c, err := m.acme.GetCertificate(hello)
	if err != nil {
		m.guard.failed(name, err)
		return nil, err
	}
	m.guard.markReady(name)
	return c, nil
}

func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	if m.acme == nil {
		return fallback
	}
	return m.acme.HTTPHandler(fallback)
}

func (m *Manager) KeyedDoT() bool { return m.wild != nil && m.wild.ready() }

func (m *Manager) Warm(ctx context.Context) {
	if m.acme == nil {
		return
	}
	if m.wild != nil {
		go m.wild.run(ctx)
	}
	var lastErr string
	var lastLog time.Time
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-time.After(20 * time.Second):
			}
		}
		_, err := m.acmeCert(&tls.ClientHelloInfo{
			ServerName:        m.host,
			CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
			SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:   []tls.CurveID{tls.CurveP256},
			SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		})
		if err == nil {
			slog.Info("TLS certificate ready", "host", m.host)
			return
		}
		if err.Error() != lastErr || time.Since(lastLog) > 10*time.Minute {
			lastErr, lastLog = err.Error(), time.Now()
			slog.Error("TLS certificate not issued yet", "host", m.host, "err", err)
		}
	}
}

func (m *Manager) loadStatic() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.static != nil && time.Since(m.staticChecked) < time.Minute {
		return m.static, nil
	}
	m.staticChecked = time.Now()
	st, err := os.Stat(m.certFile)
	if err != nil {
		if m.static != nil {
			return m.static, nil
		}
		return nil, err
	}
	if m.static != nil && st.ModTime().Equal(m.staticMod) {
		return m.static, nil
	}
	c, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		if m.static != nil {
			return m.static, nil
		}
		return nil, err
	}
	m.static, m.staticMod = &c, st.ModTime()
	return m.static, nil
}

func SelfSigned(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host, "*." + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
