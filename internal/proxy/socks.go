package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func socksConnect(ctx context.Context, c net.Conn, host string, port int) error {
	if len(host) == 0 || len(host) > 255 {
		return errors.New("socks5: bad host")
	}
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	} else {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	defer c.SetDeadline(time.Time{})

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		return err
	}
	if hello[0] != 5 || hello[1] != 0 {
		return fmt.Errorf("socks5: auth method %d not supported", hello[1])
	}

	req := make([]byte, 0, 7+len(host))
	req = append(req, 5, 1, 0, 3, byte(len(host)))
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[0] != 5 {
		return errors.New("socks5: bad reply")
	}
	if head[1] != 0 {
		return fmt.Errorf("socks5: connect failed, code %d", head[1])
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("socks5: bad address type")
	}
	_, err := io.CopyN(io.Discard, c, int64(skip+2))
	return err
}
