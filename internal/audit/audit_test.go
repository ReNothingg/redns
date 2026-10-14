package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	l.Info("login_ok", "203.0.113.1", "")
	l.Warn("login_fail", "198.51.100.9", "")
	l.Info("device_add", "203.0.113.1", "Саша · Android")
	l.Info("ban_add", "203.0.113.1", "198.51.100.0/24")

	got := l.Recent(10, "")
	if len(got) != 3 || got[0].Action != "ban_add" || got[2].Action != "login_fail" {
		t.Fatalf("ring = %+v", got)
	}
	if f := l.Recent(10, "саша"); len(f) != 1 || f[0].Action != "device_add" {
		t.Fatalf("filter = %+v", f)
	}

	again, err := Open(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if r := again.Recent(10, ""); len(r) != 3 || r[0].Detail != "198.51.100.0/24" {
		t.Fatalf("reloaded = %+v", r)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("audit log must be private, mode %v", st.Mode().Perm())
	}
}

func TestCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path, 5)
	l.size = compactAt
	l.Info("x", "", strings.Repeat("a", 10))
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "\n"); n != 1 {
		t.Fatalf("compacted file has %d lines", n)
	}
}

func TestNilLogIsSafe(t *testing.T) {
	var l *Log
	l.Info("x", "", "")
	if l.Recent(5, "") != nil {
		t.Fatal("nil log returns entries")
	}
}
