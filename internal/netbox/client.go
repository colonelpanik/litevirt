package netbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is everything the client needs. The token is read from a FILE, never
// held inline in cluster config, so it never lands in a replicated row.
type Config struct {
	BaseURL   string
	TokenPath string
	Timeout   time.Duration
}

// Client is a NetBox REST client.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New reads the token and returns a ready client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("netbox: base URL is required")
	}
	raw, err := os.ReadFile(cfg.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("netbox: read token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, fmt.Errorf("netbox: token file %s is empty", cfg.TokenPath)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		base:  strings.TrimRight(cfg.BaseURL, "/"),
		token: token,
		http:  &http.Client{Timeout: timeout},
	}, nil
}

// do issues one request and decodes a 2xx body into out. A non-2xx becomes an
// *APIError so Classify can branch on it.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("netbox: marshal request: %w", err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return fmt.Errorf("netbox: build request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("netbox: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	if readErr != nil {
		return fmt.Errorf("netbox: read response: %w", readErr)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("netbox: decode response: %w", err)
	}
	return nil
}

// pageSize is the per-request page size asked of every list endpoint. NetBox
// paginates at 50 by default and caps the value server-side, so this is a hint,
// never a promise that one request returns everything.
const pageSize = 200

// pageOf is one page of any NetBox list response: the rows in their raw
// per-endpoint shape, plus the URL of the next page ("" on the last one).
type pageOf[J any] struct {
	Results []J    `json:"results"`
	Next    string `json:"next"`
}

// paginate walks EVERY page of a list endpoint and maps each raw row with
// convert.
//
// It exists so that no caller can accidentally read only the first page: a
// truncated list makes the full sweep believe live objects have vanished, and
// the sweep then deletes them. Every list operation in this package goes
// through here rather than issuing its own loop.
func paginate[J, T any](ctx context.Context, c *Client, path string, q url.Values, convert func(J) T) ([]T, error) {
	var res []T
	offset := 0
	for {
		page := url.Values{}
		for k, v := range q {
			page[k] = v
		}
		page.Set("limit", strconv.Itoa(pageSize))
		page.Set("offset", strconv.Itoa(offset))

		var out pageOf[J]
		if err := c.do(ctx, http.MethodGet, path+"?"+page.Encode(), nil, &out); err != nil {
			return nil, err
		}
		for _, r := range out.Results {
			res = append(res, convert(r))
		}
		if out.Next == "" {
			return res, nil
		}
		offset += len(out.Results)
		if len(out.Results) == 0 {
			return res, nil // defensive: a Next that never drains
		}
	}
}

// Prefix is one ipam.prefix. VRFID is 0 for a global-table prefix, which bind
// validation refuses (uniqueness is not verifiable through supported APIs).
type Prefix struct {
	ID     int
	Prefix string
	VRFID  int
}

type prefixJSON struct {
	ID     int    `json:"id"`
	Prefix string `json:"prefix"`
	VRF    *struct {
		ID int `json:"id"`
	} `json:"vrf"`
}

// GetPrefix reads one prefix by id.
func (c *Client) GetPrefix(ctx context.Context, id int) (Prefix, error) {
	var p prefixJSON
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/ipam/prefixes/%d/", id), nil, &p); err != nil {
		return Prefix{}, err
	}
	out := Prefix{ID: p.ID, Prefix: p.Prefix}
	if p.VRF != nil {
		out.VRFID = p.VRF.ID
	}
	return out, nil
}

// VRFEnforcesUnique reports the VRF's enforce_unique flag. This is the ONLY
// uniqueness signal available through supported APIs — the global
// ENFORCE_GLOBAL_UNIQUE setting is not exposed by the status endpoint, which is
// why bind validation requires a VRF.
func (c *Client) VRFEnforcesUnique(ctx context.Context, vrfID int) (bool, error) {
	var v struct {
		EnforceUnique bool `json:"enforce_unique"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/ipam/vrfs/%d/", vrfID), nil, &v); err != nil {
		return false, err
	}
	return v.EnforceUnique, nil
}
