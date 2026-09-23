package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestSetEnforcement covers the two rollout-debugging gauges: config intent and
// latch state are reported independently (config-on-but-not-latched is the enable
// window / broken-Ping signal).
func TestSetEnforcement(t *testing.T) {
	m := newHAHealthMetrics(prometheus.NewRegistry())

	m.SetEnforcement("safe_fence_default_v1", true, false) // configured on, not yet latched
	m.SetEnforcement("lww_skew_guard_v1", false, false)    // off

	if got := testutil.ToFloat64(m.configEnabled.WithLabelValues("safe_fence_default_v1")); got != 1 {
		t.Errorf("config_enabled(safe_fence) = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.latched.WithLabelValues("safe_fence_default_v1")); got != 0 {
		t.Errorf("latched(safe_fence) = %v, want 0 (config-on-but-not-latched)", got)
	}
	if got := testutil.ToFloat64(m.configEnabled.WithLabelValues("lww_skew_guard_v1")); got != 0 {
		t.Errorf("config_enabled(lww) = %v, want 0", got)
	}

	m.SetEnforcement("safe_fence_default_v1", true, true) // now latched
	if got := testutil.ToFloat64(m.latched.WithLabelValues("safe_fence_default_v1")); got != 1 {
		t.Errorf("latched(safe_fence) = %v, want 1 after latch", got)
	}

	var nilM *HAHealthMetrics // nil-safe
	nilM.SetEnforcement("x", true, true)
}

// TestSetDegraded_SeparatesRegressionFromRollout pins the series that the other
// two gauges cannot express between them.
//
// config_enabled=1 AND latched=0 identifies a token still mid-rollout. It does
// NOT identify a token that latched and then regressed — a peer stopped
// advertising it — because the durable latch is one-way, so latched stays 1
// while the capability is no longer confirmed cluster-wide. That is the case
// where enforcement is silently held back, and it is the reason this exists.
func TestSetDegraded_SeparatesRegressionFromRollout(t *testing.T) {
	m := newHAHealthMetrics(prometheus.NewRegistry())

	// A regressed token: latched, configured on, and degraded anyway.
	m.SetEnforcement("lww_skew_guard_v1", true, true)
	m.SetDegraded("lww_skew_guard_v1", true)
	if got := testutil.ToFloat64(m.latched.WithLabelValues("lww_skew_guard_v1")); got != 1 {
		t.Fatalf("fixture: latched = %v, want 1 (a regression keeps its one-way latch)", got)
	}
	if got := testutil.ToFloat64(m.featureDegraded.WithLabelValues("lww_skew_guard_v1")); got != 1 {
		t.Errorf("a latched-then-regressed token reads degraded = %v; no combination of "+
			"config_enabled and latched can express it, so enforcement is held back invisibly", got)
	}

	// Recovery must return the series to 0 rather than leaving it pinned for the
	// life of the process — this is written every cycle for exactly that reason.
	m.SetDegraded("lww_skew_guard_v1", false)
	if got := testutil.ToFloat64(m.featureDegraded.WithLabelValues("lww_skew_guard_v1")); got != 0 {
		t.Errorf("degraded = %v after recovery, want 0", got)
	}
}
