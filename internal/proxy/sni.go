package proxy

import (
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const (
	recordTypeHandshake     = 22
	handshakeClientHello    = 1
	maxClientHelloSize      = 64 << 10
	extServerName           = 0
	extALPN                 = 16
	extEncryptedClientHello = 0xfe0d
)

var (
	ErrNotTLS   = errors.New("not a TLS handshake")
	ErrBadHello = errors.New("malformed ClientHello")
)

type Hello struct {
	ServerName string
	ALPN       []string
	ECH        bool
}

func ReadClientHello(r io.Reader) (raw []byte, h *Hello, err error) {
	var hs []byte
	var hdr [5]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return raw, nil, err
		}
		raw = append(raw, hdr[:]...)
		if hdr[0] != recordTypeHandshake || hdr[1] != 3 {
			return raw, nil, ErrNotTLS
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > 16384+2048 {
			return raw, nil, ErrBadHello
		}
		start := len(raw)
		raw = append(raw, make([]byte, n)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return raw, nil, err
		}
		hs = append(hs, raw[start:]...)
		if len(hs) < 4 {
			continue
		}
		if hs[0] != handshakeClientHello {
			return raw, nil, ErrBadHello
		}
		msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if msgLen > maxClientHelloSize {
			return raw, nil, ErrBadHello
		}
		if len(hs) >= 4+msgLen {
			h, err := ParseClientHello(hs[4 : 4+msgLen])
			return raw, h, err
		}
	}
}

func ParseClientHello(body []byte) (*Hello, error) {
	s := cryptobyte.String(body)
	var (
		version             uint16
		random, sid, cs, cm cryptobyte.String
	)
	if !s.ReadUint16(&version) || !s.ReadBytes((*[]byte)(&random), 32) ||
		!s.ReadUint8LengthPrefixed(&sid) || !s.ReadUint16LengthPrefixed(&cs) ||
		!s.ReadUint8LengthPrefixed(&cm) {
		return nil, ErrBadHello
	}
	h := &Hello{}
	if s.Empty() {
		return h, nil
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		return nil, ErrBadHello
	}
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, ErrBadHello
		}
		switch typ {
		case extServerName:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) {
				return nil, ErrBadHello
			}
			for !list.Empty() {
				var nameType uint8
				var name cryptobyte.String
				if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
					return nil, ErrBadHello
				}
				if nameType == 0 && h.ServerName == "" {
					h.ServerName = string(name)
				}
			}
		case extALPN:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) {
				return nil, ErrBadHello
			}
			for !list.Empty() {
				var proto cryptobyte.String
				if !list.ReadUint8LengthPrefixed(&proto) {
					return nil, ErrBadHello
				}
				h.ALPN = append(h.ALPN, string(proto))
			}
		case extEncryptedClientHello:
			h.ECH = true
		}
	}
	return h, nil
}
