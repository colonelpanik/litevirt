package metrics

import (
	"bytes"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
)

// TestClassifyMetricsBind pins how far each bind spelling reaches.
//
// The endpoint has no TLS and no authentication and serves the cluster's
// inventory plus litevirt_enforcement_* — a readout of which security
// kill-switches are off. Classification is what decides whether an operator is
// told, so a wrong answer here is silent in both directions: a missed wildcard
// leaves a real exposure unannounced, and a false positive is noise nobody can
// silence, which is how a startup warning becomes one everybody skips.
func TestClassifyMetricsBind(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		want metricsExposure
		why  string
	}{
		{"empty is the default", "", metricsBindWildcard,
			"the default binds every interface and is the case nobody chose"},
		{"IPv4 wildcard", "0.0.0.0", metricsBindWildcard, ""},
		// Both IPv6 wildcard spellings, and they are NOT interchangeable in the
		// original code: "::" produced ":::7444" and failed to listen at all,
		// while "[::]" bound every interface with no warning. String-matching
		// the spellings got this exactly backwards — it warned about the one
		// that could not work and stayed silent on the one that did.
		{"IPv6 wildcard, bare", "::", metricsBindWildcard,
			"this spelling could not even listen before; now it can"},
		{"IPv6 wildcard, bracketed", "[::]", metricsBindWildcard,
			"this one always listened on every interface and never warned"},
		{"loopback", "127.0.0.1", metricsBindRestricted, ""},
		{"IPv6 loopback", "::1", metricsBindRestricted, ""},
		{"RFC1918 management address", "10.13.200.5", metricsBindRestricted,
			"the recommended configuration must not warn"},
		{"RFC1918 /16", "192.168.1.10", metricsBindRestricted, ""},
		{"IPv6 ULA", "fc00::1", metricsBindRestricted, ""},
		{"link-local", "169.254.1.1", metricsBindRestricted, ""},
		// netip classifies a tailnet address exactly like 8.8.8.8 — not private,
		// global unicast — so without the CGNAT carve-out a restricted tailnet
		// bind would warn.
		{"CGNAT / tailnet", "100.101.102.103", metricsBindRestricted,
			"a tailnet bind is a deliberately restricted choice"},
		{"a public address", "203.0.113.5", metricsBindPublic,
			"as world-readable as the wildcard, and almost never deliberate here"},
		{"a public IPv6 address", "2606:4700::1111", metricsBindPublic, ""},
		// Not resolved on purpose: resolution can block at startup and can
		// disagree with what the listener does.
		{"a hostname is not classified", "metrics.internal", metricsBindRestricted,
			"a false warning an operator cannot silence is worse than silence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMetricsBind(tc.bind); got != tc.want {
				t.Errorf("classifyMetricsBind(%q) = %v, want %v — %s", tc.bind, got, tc.want, tc.why)
			}
		})
	}
}

// TestNormalizeBind_ProducesAListenableAddress is the half a classification test
// cannot reach: whether the address the listener is actually given works.
//
// The original code composed it with Sprintf("%s:%d"), so metrics_bind "::"
// became ":::7444" — "too many colons" — ListenAndServe failed, and Start only
// LOGGED that error, leaving the node with no metrics endpoint at all. A
// classification test alone would have called that bind a warned wildcard and
// never noticed it served nothing.
func TestNormalizeBind_ProducesAListenableAddress(t *testing.T) {
	for _, bind := range []string{"", "0.0.0.0", "::", "[::]", "127.0.0.1", "::1"} {
		t.Run("bind="+bind, func(t *testing.T) {
			addr := net.JoinHostPort(normalizeBind(bind), strconv.Itoa(0))
			l, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("metrics_bind %q composes to %q, which cannot listen: %v — the daemon "+
					"would log this and serve no metrics at all", bind, addr, err)
			}
			l.Close()
		})
	}
}

// TestWarnIfMetricsWorldReadable pins that the operator is actually told, and
// what they are told. A warning without the remedy leaves them to work out both
// what leaks and what to set, from one line among a great deal of startup output.
func TestWarnIfMetricsWorldReadable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bind     string
		wantWarn bool
		wantWord string // distinguishes the wildcard message from the public one
	}{
		{"the default warns", "", true, "EVERY interface"},
		{"a public address warns differently", "203.0.113.5", true, "PUBLIC"},
		{"loopback stays quiet", "127.0.0.1", false, ""},
		{"a management address stays quiet", "10.13.200.5", false, ""},
		{"a tailnet address stays quiet", "100.101.102.103", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			warnIfMetricsWorldReadable(tc.bind, 7444)

			got := buf.String()
			if warned := strings.Contains(got, "level=WARN"); warned != tc.wantWarn {
				t.Fatalf("warned = %v, want %v for metrics_bind=%q; log was %q",
					warned, tc.wantWarn, tc.bind, got)
			}
			if !tc.wantWarn {
				return
			}
			if !strings.Contains(got, tc.wantWord) {
				t.Errorf("warning does not say %q, so the two exposures read alike; got %q",
					tc.wantWord, got)
			}
			for _, want := range []string{"metrics_bind", "litevirt_enforcement", "7444"} {
				if !strings.Contains(got, want) {
					t.Errorf("warning does not mention %q; got %q", want, got)
				}
			}
		})
	}
}
