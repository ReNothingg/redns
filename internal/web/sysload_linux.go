//go:build linux

package web

import "syscall"

func systemLoad() (float64, bool) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, false
	}
	return float64(si.Loads[0]) / 65536, true
}
