//go:build !linux

package web

func systemLoad() (float64, bool) { return 0, false }
