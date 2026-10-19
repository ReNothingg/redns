package asn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

const URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

const maxUnpacked = 256 << 20

type Info struct {
	ASN     uint32
	Name    string
	Country string
}

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

func (a u128) next() u128 {
	if a.lo == ^uint64(0) {
		return u128{a.hi + 1, 0}
	}
	return u128{a.hi, a.lo + 1}
}

type span[T any] struct {
	lo, hi T
	asn    uint32
}

type table struct {
	v4    []span[uint32]
	v6    []span[u128]
	names map[uint32]Info
}

func key4(ip netip.Addr) uint32 {
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])
}

func key6(ip netip.Addr) u128 {
	b := ip.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func find[T any](s []span[T], k T, less func(a, b T) bool) (uint32, bool) {
	i := sort.Search(len(s), func(i int) bool { return !less(s[i].hi, k) })
	if i == len(s) || less(k, s[i].lo) {
		return 0, false
	}
	return s[i].asn, true
}

func merge[T comparable](s []span[T], less func(a, b T) bool, next func(T) T) []span[T] {
	sort.Slice(s, func(i, j int) bool { return less(s[i].lo, s[j].lo) })
	out := s[:0]
	for _, x := range s {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if !less(last.hi, x.lo) {
				continue
			}
			if last.asn == x.asn && next(last.hi) == x.lo {
				last.hi = x.hi
				continue
			}
		}
		out = append(out, x)
	}
	return append([]span[T](nil), out...)
}

func less4(a, b uint32) bool { return a < b }
func next4(a uint32) uint32  { return a + 1 }
func less6(a, b u128) bool   { return a.less(b) }
func next6(a u128) u128      { return a.next() }

type DB struct {
	t atomic.Pointer[table]
}

func (d *DB) Ready() bool { return d != nil && d.t.Load() != nil }

func (d *DB) Len() int {
	if !d.Ready() {
		return 0
	}
	t := d.t.Load()
	return len(t.v4) + len(t.v6)
}

func (d *DB) Lookup(ip netip.Addr) (Info, bool) {
	if !d.Ready() || !ip.IsValid() {
		return Info{}, false
	}
	t := d.t.Load()
	ip = ip.Unmap()
	var (
		asn uint32
		ok  bool
	)
	if ip.Is4() {
		asn, ok = find(t.v4, key4(ip), less4)
	} else {
		asn, ok = find(t.v6, key6(ip), less6)
	}
	if !ok {
		return Info{}, false
	}
	return t.names[asn], true
}

func (d *DB) Load(gz []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	defer zr.Close()
	t, err := parse(io.LimitReader(zr, maxUnpacked))
	if err != nil {
		return err
	}
	d.t.Store(t)
	return nil
}

func parse(r io.Reader) (*table, error) {
	t := &table{names: map[uint32]Info{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 5)
		if len(f) < 5 {
			continue
		}
		n, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil || n == 0 {
			continue
		}
		lo, err1 := netip.ParseAddr(f[0])
		hi, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() || hi.Less(lo) {
			continue
		}
		asn := uint32(n)
		if _, ok := t.names[asn]; !ok {
			t.names[asn] = Info{ASN: asn, Name: pretty(f[4]), Country: country(f[3])}
		}
		if lo.Is4() {
			t.v4 = append(t.v4, span[uint32]{key4(lo), key4(hi), asn})
		} else {
			t.v6 = append(t.v6, span[u128]{key6(lo), key6(hi), asn})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t.v4) == 0 {
		return nil, errors.New("asn: empty table")
	}
	t.v4, t.v6 = merge(t.v4, less4, next4), merge(t.v6, less6, next6)
	return t, nil
}

func country(cc string) string {
	if len(cc) != 2 {
		return ""
	}
	return strings.ToUpper(cc)
}

func pretty(desc string) string {
	desc = strings.TrimSpace(desc)
	if _, org, ok := strings.Cut(desc, " - "); ok && strings.TrimSpace(org) != "" {
		return strings.TrimSpace(org)
	}
	if first, rest, ok := strings.Cut(desc, " "); ok && strings.HasSuffix(strings.ToUpper(first), "-AS") && strings.TrimSpace(rest) != "" {
		return strings.TrimSpace(rest)
	}
	return desc
}

func (i Info) Label() string {
	if i.ASN == 0 {
		return ""
	}
	s := i.Name
	if s == "" {
		s = "AS" + strconv.FormatUint(uint64(i.ASN), 10)
	}
	if i.Country != "" {
		s += " · " + i.Country
	}
	return s
}
