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
