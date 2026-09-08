package metrics

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestWarnIfMetricsWorldReadable pins which binds count as exposed.
//
// The endpoint has no TLS and no authentication and serves the cluster's
// inventory plus litevirt_enforcement_* — a readout of which security
// kill-switches are off. The default binds every interface, and the daemon
// cannot tell a management network from a hostile one, so the warning is the
// only thing that makes the exposure visible to an operator who did not choose
// it deliberately.
//
// Both directions matter. A warning that stays silent on "" is useless; one
// that fires on a restricted bind is noise an operator cannot silence, and a
// warning nobody can act on is one everybody learns to skip.
func TestWarnIfMetricsWorldReadable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bind     string
		wantWarn bool
	}{
		{"empty is the default and binds everything", "", true},
		{"explicit all-interfaces IPv4", "0.0.0.0", true},
		{"explicit all-interfaces IPv6", "::", true},
		{"loopback is restricted", "127.0.0.1", false},
		{"a management address is restricted", "10.13.200.5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			warnIfMetricsWorldReadable(tc.bind, 7444)

			got := buf.String()
			if warned := strings.Contains(got, "level=WARN"); warned != tc.wantWarn {
				t.Errorf("warned = %v, want %v for metrics_bind=%q; log was %q",
					warned, tc.wantWarn, tc.bind, got)
			}
			if !tc.wantWarn {
				return
			}
			// The warning has to carry the remedy and the reason. "Metrics are
			// exposed" alone leaves an operator to work out both what leaks and
			// what to set, and this fires once at startup among a great deal of
			// other output.
			for _, want := range []string{"metrics_bind", "127.0.0.1", "litevirt_enforcement", "7444"} {
				if !strings.Contains(got, want) {
					t.Errorf("warning does not mention %q; got %q", want, got)
				}
			}
		})
	}
}
