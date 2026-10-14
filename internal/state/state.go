package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Token struct {
	Name    string    `json:"name"`
	Owner   string    `json:"owner,omitempty"`
	Kind    string    `json:"kind,omitempty"`
	Token   string    `json:"token"`
	Created time.Time `json:"created"`
}

type Ban struct {
	Prefix  string    `json:"prefix"`
	Reason  string    `json:"reason,omitempty"`
	Created time.Time `json:"created"`
}

type Data struct {
	Tokens      []Token  `json:"tokens"`
	Revoked     []string `json:"revoked"`
	Bans        []Ban    `json:"bans"`
	StrictProxy *bool    `json:"strict_proxy,omitempty"`
}

type Store struct {
	path string
	mu   sync.Mutex
	d    Data
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.d); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Get() Data {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.d)
}

func (s *Store) Update(fn func(*Data) error) (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.d)
	if err := fn(&next); err != nil {
		return clone(s.d), err
	}
	if err := s.save(next); err != nil {
		return clone(s.d), err
	}
	s.d = next
	return clone(next), nil
}

func (s *Store) save(d Data) error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func clone(d Data) Data {
	out := Data{
		Tokens:  append([]Token(nil), d.Tokens...),
		Revoked: append([]string(nil), d.Revoked...),
		Bans:    append([]Ban(nil), d.Bans...),
	}
	if d.StrictProxy != nil {
		v := *d.StrictProxy
		out.StrictProxy = &v
	}
	return out
}
