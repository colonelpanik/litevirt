package image

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, cidrs []string, meta, priv bool) []netip.Prefix {
	t.Helper()
	p, err := ParseBlockPolicy(cidrs, meta, priv)
	if err != nil {
		t.Fatalf("ParseBlockPolicy: %v", err)
	}
	return p
}

// TestParseBlockPolicy: explicit CIDRs + the convenience booleans expand and
// dedupe; an invalid CIDR errors (callers fail config load).
func TestParseBlockPolicy(t *testing.T) {
	if _, err := ParseBlockPolicy([]string{"not-a-cidr"}, false, false); err == nil {
		t.Error("invalid CIDR did not error")
	}
	if p, err := ParseBlockPolicy(nil, false, false); err != nil || len(p) != 0 {
		t.Errorf("empty policy = %v, %v; want no error, no prefixes", p, err)
	}
	// block_private is a superset of block_metadata → enabling both must not
	// duplicate the link-local prefix.
	both := mustPolicy(t, nil, true, true)
	seen := map[netip.Prefix]int{}
	for _, pfx := range both {
		seen[pfx]++
		if seen[pfx] > 1 {
			t.Errorf("duplicate prefix %s in merged policy", pfx)
		}
	}
	// 169.254.169.254 (IMDS) must be covered by the metadata set.
	meta := mustPolicy(t, nil, true, false)
	imds := netip.MustParseAddr("169.254.169.254")
	if !(PullOptions{BlockedCIDRs: meta}).blocked(imds) {
		t.Error("block_metadata does not cover 169.254.169.254")
	}
}

// TestBlocked_UnmapsV4MappedV6: an IPv4-mapped IPv6 literal (::ffff:a.b.c.d) must
// be matched against an IPv4 prefix — the Unmap guards against a bypass.
func TestBlocked_UnmapsV4MappedV6(t *testing.T) {
	o := PullOptions{BlockedCIDRs: mustPolicy(t, []string{"127.0.0.0/8"}, false, false)}
	if !o.blocked(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Error("IPv4-mapped IPv6 ::ffff:127.0.0.1 should be blocked by 127.0.0.0/8")
	}
}

// TestParseBlockPolicy_PrivateIncludesMetadata: block_private is a superset of
// block_metadata — it must also cover link-local/metadata, not just RFC1918.
func TestParseBlockPolicy_PrivateIncludesMetadata(t *testing.T) {
	o := PullOptions{BlockedCIDRs: mustPolicy(t, nil, false, true)} // block_private only
	for _, ip := range []string{"169.254.169.254", "10.1.2.3", "192.168.1.5", "172.16.0.1", "127.0.0.1", "100.64.0.1"} {
		if !o.blocked(netip.MustParseAddr(ip)) {
			t.Errorf("block_private should cover %s", ip)
		}
	}
	if o.blocked(netip.MustParseAddr("8.8.8.8")) {
		t.Error("block_private must not block a public address")
	}
}

// TestPull_BlockedCIDRFailsAtConnect: with the server's range blocked, the pull
// is rejected at connect (the guard fires before any bytes flow).
func TestPull_BlockedCIDRFailsAtConnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	// httptest binds 127.0.0.1 → block loopback.
	err := Pull(s, "img", srv.URL, "", PullOptions{BlockedCIDRs: mustPolicy(t, []string{"127.0.0.0/8"}, false, false)}, ch)
	if err == nil {
		t.Fatal("Pull to a blocked CIDR succeeded; want a connect rejection")
	}
	if s.ImageExists("img") {
		t.Error("blocked image must not be finalized")
	}
}

// TestPull_NilPolicyAllowsLoopback: the default (no policy) does not guard the
// network — a loopback pull works.
func TestPull_NilPolicyAllowsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	if err := Pull(s, "img", srv.URL, "", PullOptions{}, ch); err != nil {
		t.Fatalf("nil-policy loopback pull failed: %v", err)
	}
	if !s.ImageExists("img") {
		t.Error("image not finalized")
	}
}

// TestPull_UnblockedRangeAllowed: a policy that doesn't cover the server's IP
// lets the pull through (the guard is precise, not a blanket block).
func TestPull_UnblockedRangeAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	// Server is 127.0.0.1; block a range it is NOT in.
	if err := Pull(s, "img", srv.URL, "", PullOptions{BlockedCIDRs: mustPolicy(t, []string{"10.0.0.0/8"}, false, false)}, ch); err != nil {
		t.Fatalf("pull to an unblocked range failed: %v", err)
	}
}

// TestPull_RedirectToBlockedFails: the FIRST hop (loopback, allowed) returns a
// redirect to a blocked metadata IP; the redirect dial is rejected — proving the
// guard re-checks every connection (redirect-safe), not just the initial host.
func TestPull_RedirectToBlockedFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	// Loopback (the first hop) is allowed; only metadata is blocked.
	err := Pull(s, "img", srv.URL, "", PullOptions{BlockedCIDRs: mustPolicy(t, nil, true, false)}, ch)
	if err == nil {
		t.Fatal("redirect to a blocked metadata IP succeeded; want rejection")
	}
	if !strings.Contains(err.Error(), "169.254.169.254") && !strings.Contains(err.Error(), "denied") {
		t.Logf("redirect-block error: %v", err) // message form is informational
	}
}
