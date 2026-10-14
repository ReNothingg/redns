package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type cloudflare struct {
	token string
	base  string
	hc    *http.Client
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type cfZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
}

func newCloudflare(token string) *cloudflare {
	return &cloudflare{token: token, base: "https://api.cloudflare.com/client/v4", hc: &http.Client{Timeout: 20 * time.Second}}
}

func (c *cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare: %s: %w", resp.Status, err)
	}
	if !env.Success {
		msgs := []string{}
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare: %s", strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (c *cloudflare) zone(ctx context.Context, host string) (cfZone, error) {
	for name := host; strings.Contains(name, "."); name = name[strings.Index(name, ".")+1:] {
		var zones []cfZone
		if err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil, &zones); err != nil {
			return cfZone{}, err
		}
		if len(zones) > 0 {
			return zones[0], nil
		}
	}
	return cfZone{}, fmt.Errorf("cloudflare: зона для %s не найдена, у токена нет к ней доступа", host)
}

func (c *cloudflare) records(ctx context.Context, zone, typ, name string) ([]cfRecord, error) {
	var out []cfRecord
	err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?type="+typ+"&name="+url.QueryEscape(name), nil, &out)
	return out, err
}

func (c *cloudflare) create(ctx context.Context, zone string, r cfRecord) (string, error) {
	var out cfRecord
	if err := c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", r, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("cloudflare: record created without id")
	}
	return out.ID, nil
}

func (c *cloudflare) remove(ctx context.Context, zone, id string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil)
}

func CheckCloudflare(ctx context.Context, token, host string) (string, error) {
	z, err := newCloudflare(token).zone(ctx, host)
	if err != nil {
		return "", err
	}
	return z.Name, nil
}
