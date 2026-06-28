package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Defaults for PullOptions when a field is left zero. Generous so real cloud
// images pull fine; they exist only to bound a pathological/hostile source.
const (
	DefaultMaxImageBytes int64 = 64 << 30 // 64 GiB
	DefaultPullTimeout         = 30 * time.Minute
)

// PullOptions bounds an image pull: which URL schemes are allowed, an overall
// timeout, and a hard byte ceiling. The single enforcement point for both
// SSRF-via-redirect (scheme allowlist, re-checked on every redirect) and
// disk-fill (LimitReader + fail, never silent truncation).
type PullOptions struct {
	Timeout  time.Duration
	MaxBytes int64
	Schemes  []string // allowed URL schemes; nil → http/https
	// BlockedCIDRs is an OPT-IN connect-time deny list (nil → no network guard,
	// env proxies honored — the default). When set, the pull dials directly (no
	// proxy) and rejects any connection whose RESOLVED destination IP falls in a
	// blocked prefix — DNS-rebinding- and redirect-safe, since every connection
	// (incl. redirect targets) is checked after resolution.
	BlockedCIDRs []netip.Prefix
}

// well-known prefix sets for the convenience config booleans.
var (
	metadataCIDRs = []string{"169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128"}
	privateCIDRs  = []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
		"127.0.0.0/8", "::1/128", // loopback
		"100.64.0.0/10", // CGNAT (RFC6598)
		"fc00::/7",      // ULA
	}
)

// ParseBlockPolicy resolves explicit CIDR strings + the convenience booleans into
// a deduplicated, canonicalized prefix list. It returns an error on ANY invalid
// CIDR — callers should fail config load rather than silently drop a deny policy.
// `block_private` is a superset of `block_metadata` (it also blocks link-local),
// and the merged set is deduped so the result is stable regardless of which knobs
// are enabled.
func ParseBlockPolicy(cidrs []string, blockMetadata, blockPrivate bool) ([]netip.Prefix, error) {
	raw := append([]string(nil), cidrs...)
	if blockPrivate {
		raw = append(raw, privateCIDRs...)
		raw = append(raw, metadataCIDRs...) // private subsumes link-local/metadata
	} else if blockMetadata {
		raw = append(raw, metadataCIDRs...)
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("invalid blocked CIDR %q: %w", s, err)
		}
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// blocked reports whether ip falls in any denied prefix. The IP is Unmap'd first
// so an IPv4-mapped IPv6 literal (::ffff:a.b.c.d) can't bypass an IPv4 prefix.
func (o PullOptions) blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range o.BlockedCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// httpClient builds the pull's HTTP client. With no deny policy it uses default
// transport semantics (env proxies honored). With BlockedCIDRs set it clones
// http.DefaultTransport (keeping TLS-handshake/keepalive/HTTP-2 defaults), sets
// Proxy=nil (direct-only, so every connection is inspectable), and installs a
// dialer whose Control hook runs AFTER DNS resolution with the resolved ip:port —
// rejecting blocked destinations on every connection (DNS-rebinding- and
// redirect-safe). Fails CLOSED on an unparseable address; errors name only the
// IP/host:port, never the raw URL (which may carry credentials).
func (o PullOptions) httpClient(checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	c := &http.Client{Timeout: o.Timeout, CheckRedirect: checkRedirect}
	if len(o.BlockedCIDRs) == 0 {
		return c
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("image pull: cannot parse dial address %q; failing closed under the deny policy", address)
			}
			if o.blocked(ap.Addr()) {
				return fmt.Errorf("image pull blocked: destination %s is in a denied range", ap)
			}
			return nil
		},
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = dialer.DialContext
	c.Transport = tr
	return c
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

	client := opts.httpClient(func(req *http.Request, via []*http.Request) error {
		if !opts.schemeAllowed(req.URL.Scheme) {
			return fmt.Errorf("redirect to disallowed scheme %q", req.URL.Scheme)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	})
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
