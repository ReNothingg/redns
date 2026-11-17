//go:build !linux

package proxy

import (
	"net"
	"time"
)

func idleFor(net.Conn) (time.Duration, bool) { return 0, false }
