package lists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const maxListSize = 64 << 20

type Fetcher struct {
	CacheDir string
	Client   *http.Client
}

func NewFetcher(cacheDir string) *Fetcher {
	return &Fetcher{
		CacheDir: cacheDir,
		Client:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (f *Fetcher) cachePath(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(f.CacheDir, hex.EncodeToString(sum[:12])+".txt")
}

func (f *Fetcher) Fetch(ctx context.Context, url string) (body []byte, stale bool, err error) {
	body, err = f.download(ctx, url)
	if err == nil {
		if f.CacheDir != "" {
			_ = writeAtomic(f.cachePath(url), body)
		}
		return body, false, nil
	}
	if f.CacheDir != "" {
		if cached, cerr := os.ReadFile(f.cachePath(url)); cerr == nil {
			return cached, true, nil
		}
	}
	return nil, false, err
}

func (f *Fetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "redns-list-fetcher/1")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListSize {
		return nil, errors.New("list is too large")
	}
	return body, nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
