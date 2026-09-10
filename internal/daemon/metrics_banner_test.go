package daemon

import (
	"testing"

	"github.com/litevirt/litevirt/internal/metrics"
)

// TestMetricsAddrForBanner pins that the startup banner reports the address the
// metrics listener actually binds.
//
// The banner hardcoded fmt.Sprintf("0.0.0.0:%d", MetricsPort) and never read
// MetricsBind — while the `ui` entry on the very next line did honour UIBind. So
// a host that had applied the hardening this repo now recommends got two startup
// lines asserting opposite things:
//
//	metrics server starting addr=127.0.0.1:7444
//	litevirtd starting ... metrics=0.0.0.0:7444
//
// The louder, more visible one was wrong, so the hardening read as ignored. The
// inverse is worse: an auditor reading the banner on a loopback-bound host keeps
// a firewall rule they believe is load-bearing.
func TestMetricsAddrForBanner(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		port int
		want string
	}{
		{"loopback is reported as loopback", "127.0.0.1", 7444, "127.0.0.1:7444"},
		{"the wildcard default", "", 7444, ":7444"},
		{"a management address", "10.13.200.5", 7444, "10.13.200.5:7444"},
		// Both IPv6 spellings normalise to one bracketed form, the same one the
		// listener gets.
		{"IPv6 wildcard, bare", "::", 7444, "[::]:7444"},
		{"IPv6 wildcard, bracketed", "[::]", 7444, "[::]:7444"},
		// port 0 disables the endpoint, so the banner must not advertise one.
		{"disabled", "", 0, "disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{cfg: &Config{MetricsBind: tc.bind, MetricsPort: tc.port}}
			if tc.port > 0 {
				// A real metrics.Server, unstarted: Addr() is pure, and using the
				// real type is what keeps the banner and the listener composing
				// the address the same single way.
				d.metrics = metrics.NewServer(tc.port, tc.bind, nil, nil, nil, "host-a")
			}
			if got := d.metricsAddrForBanner(); got != tc.want {
				t.Errorf("metricsAddrForBanner() = %q, want %q — the banner is the line an "+
					"operator checks to confirm the bind took effect", got, tc.want)
			}
		})
	}
}
