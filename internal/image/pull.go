package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Defaults for PullOptions when a field is left zero. Generous so real cloud
// images pull fine; they exist only to bound a pathological/hostile source.
const (
	DefaultMaxImageBytes   int64 = 64 << 30 // 64 GiB
	DefaultPullTimeout           = 30 * time.Minute
)

// PullOptions bounds an image pull: which URL schemes are allowed, an overall
// timeout, and a hard byte ceiling. The single enforcement point for both
// SSRF-via-redirect (scheme allowlist, re-checked on every redirect) and
// disk-fill (LimitReader + fail, never silent truncation).
type PullOptions struct {
	Timeout  time.Duration
	MaxBytes int64
	Schemes  []string // allowed URL schemes; nil → http/https
}

func (o PullOptions) withDefaults() PullOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultPullTimeout
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxImageBytes
	}
	if len(o.Schemes) == 0 {
		o.Schemes = []string{"http", "https"}
	}
	return o
}

func (o PullOptions) schemeAllowed(s string) bool {
	for _, a := range o.Schemes {
		if strings.EqualFold(s, a) {
			return true
		}
	}
	return false
}

// PullProgress reports download progress.
type PullProgress struct {
	BytesDownloaded int64
	TotalBytes      int64
	ProgressPct     float32
	Status          string
	Error           string
}

// Pull downloads an image from a URL to the local store under PullOptions: only
// allowed schemes (rejecting file:// and redirect-to-file://), a client timeout,
// and a hard size ceiling enforced via LimitReader (an oversized source FAILS
// rather than being silently truncated).
func Pull(store *Store, name, rawURL, checksum string, opts PullOptions, progressCh chan<- PullProgress) error {
	defer close(progressCh)
	opts = opts.withDefaults()

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if !opts.schemeAllowed(u.Scheme) {
		return fmt.Errorf("disallowed image URL scheme %q (allowed: %s)", u.Scheme, strings.Join(opts.Schemes, ", "))
	}

	destPath, err := store.SafeImagePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("create image dir: %w", err)
	}

	progressCh <- PullProgress{Status: "downloading"}

	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !opts.schemeAllowed(req.URL.Scheme) {
				return fmt.Errorf("redirect to disallowed scheme %q", req.URL.Scheme)
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	// Cap the body at MaxBytes+1 so reaching the extra byte means "too big".
	body := io.LimitReader(resp.Body, opts.MaxBytes+1)

	tmpPath := destPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(tmpPath) // clean up on error
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)

	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, err := writer.Write(buf[:n]); err != nil {
				return fmt.Errorf("write: %w", err)
			}
			downloaded += int64(n)
			if downloaded > opts.MaxBytes {
				return fmt.Errorf("image exceeds the %d-byte ceiling", opts.MaxBytes)
			}
			var pct float32
			if resp.ContentLength > 0 {
				pct = float32(downloaded) / float32(resp.ContentLength) * 100
			}
			progressCh <- PullProgress{
				BytesDownloaded: downloaded,
				TotalBytes:      resp.ContentLength,
				ProgressPct:     pct,
				Status:          "downloading",
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	}

	f.Close()

	// Verify checksum if provided
	if checksum != "" {
		progressCh <- PullProgress{Status: "verifying checksum"}
		got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
		expected := checksum
		if !strings.HasPrefix(expected, "sha256:") {
			expected = "sha256:" + expected
		}
		if got != expected {
			os.Remove(tmpPath) // explicit cleanup on checksum failure (#28)
			return fmt.Errorf("checksum mismatch: got %s, expected %s", got, expected)
		}
	}

	// Move to final location
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	progressCh <- PullProgress{
		BytesDownloaded: downloaded,
		TotalBytes:      downloaded,
		ProgressPct:     100,
		Status:          "complete",
	}

	return nil
}
