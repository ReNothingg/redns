package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Action string    `json:"action"`
	IP     string    `json:"ip,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

const compactAt = 2 << 20

type Log struct {
	path string
	max  int
	mu   sync.Mutex
	ring []Entry
	size int64
	now  func() time.Time
}

func Open(path string, max int) (*Log, error) {
	l := &Log{path: path, max: max, now: time.Now}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			l.push(e)
		}
		l.size += int64(len(sc.Bytes())) + 1
	}
	return l, nil
}

func (l *Log) push(e Entry) {
	l.ring = append(l.ring, e)
	if len(l.ring) > l.max {
		l.ring = l.ring[len(l.ring)-l.max:]
	}
}

func (l *Log) Info(action, ip, detail string) { l.add("info", action, ip, detail) }
func (l *Log) Warn(action, ip, detail string) { l.add("warn", action, ip, detail) }

func (l *Log) add(level, action, ip, detail string) {
	if l == nil {
		return
	}
	e := Entry{Time: l.now().UTC(), Level: level, Action: action, IP: ip, Detail: detail}
	raw, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.push(e)
	if l.path == "" {
		return
	}
	if l.size+int64(len(raw))+1 > compactAt {
		l.compact()
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	n, _ := f.Write(append(raw, '\n'))
	f.Close()
	l.size += int64(n)
}

func (l *Log) compact() {
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".audit-*")
	if err != nil {
		return
	}
	w := bufio.NewWriter(tmp)
	var size int64
	for _, e := range l.ring {
		raw, _ := json.Marshal(e)
		n, _ := w.Write(append(raw, '\n'))
		size += int64(n)
	}
	if w.Flush() != nil || tmp.Close() != nil || os.Rename(tmp.Name(), l.path) != nil {
		os.Remove(tmp.Name())
		return
	}
	l.size = size
}

func (l *Log) Recent(n int, q string) []Entry {
	if l == nil {
		return nil
	}
	q = strings.ToLower(q)
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, min(n, len(l.ring)))
	for i := len(l.ring) - 1; i >= 0 && len(out) < n; i-- {
		e := l.ring[i]
		if q != "" && !strings.Contains(strings.ToLower(e.Action+" "+e.IP+" "+e.Detail), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}
