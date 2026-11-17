package proxy

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func idleFor(c net.Conn) (time.Duration, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var ms uint32
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		var info *unix.TCPInfo
		if info, gerr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); gerr == nil {
			ms = min(info.Last_data_recv, info.Last_data_sent)
		}
	}); err != nil || gerr != nil {
		return 0, false
	}
	return time.Duration(ms) * time.Millisecond, true
}
