package dnsx

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"
)

type Fingerprints struct {
	mu sync.Mutex
	m  map[string]fpEntry
}

type fpEntry struct {
	fp string
	at time.Time
}

const maxFingerprints = 100000

var volatileExt = map[uint16]bool{21: true, 41: true, 42: true}

func NewFingerprints() *Fingerprints {
	return &Fingerprints{m: map[string]fpEntry{}}
}

func (f *Fingerprints) Wrap(cfg *tls.Config) *tls.Config {
	c := cfg.Clone()
	prev := c.GetConfigForClient
	c.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if h.Conn != nil && h.Conn.RemoteAddr() != nil && h.Conn.LocalAddr() != nil {
			f.put(h.Conn.LocalAddr().String()+"|"+h.Conn.RemoteAddr().String(), helloFingerprint(h))
		}
		if prev != nil {
			return prev(h)
		}
		return nil, nil
	}
	return c
}

func (f *Fingerprints) put(addr, fp string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[addr]; !ok && len(f.m) >= maxFingerprints {
		for k := range f.m {
			delete(f.m, k)
			if len(f.m) < maxFingerprints*9/10 {
				break
			}
		}
	}
	f.m[addr] = fpEntry{fp: fp, at: time.Now()}
}

func (f *Fingerprints) Get(addr string) string {
	if f == nil {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[addr]
	if !ok {
		return ""
	}
	e.at = time.Now()
	f.m[addr] = e
	return e.fp
}

func (f *Fingerprints) GC() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, e := range f.m {
		if time.Since(e.at) > 2*time.Hour {
			delete(f.m, k)
		}
	}
}

func helloFingerprint(h *tls.ClientHelloInfo) string {
	sum := sha256.New()
	write := func(tag string, vals []uint16) {
		v := make([]uint16, 0, len(vals))
		for _, x := range vals {
			if x&0x0f0f == 0x0a0a || (tag == "e" && volatileExt[x]) {
				continue
			}
			v = append(v, x)
		}
		slices.Sort(v)
		fmt.Fprint(sum, tag, v)
	}
	curves := make([]uint16, len(h.SupportedCurves))
	for i, c := range h.SupportedCurves {
		curves[i] = uint16(c)
	}
	sigs := make([]uint16, len(h.SignatureSchemes))
	for i, s := range h.SignatureSchemes {
		sigs[i] = uint16(s)
	}
	write("v", h.SupportedVersions)
	write("c", h.CipherSuites)
	write("e", h.Extensions)
	write("g", curves)
	write("s", sigs)
	fmt.Fprint(sum, "a", h.SupportedProtos)
	return hex.EncodeToString(sum.Sum(nil))[:12]
}
