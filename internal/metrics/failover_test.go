package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/litevirt/litevirt/internal/failover"
)

// compile-time check: *FailoverMetrics satisfies the failover sink interface
// (the daemon relies on this when assigning fc.Metrics).
var _ failover.Metrics = (*FailoverMetrics)(nil)

// TestFailoverMetrics_Counts: the real Prometheus-backed impl increments the
// right series. Uses a private registry so repeated test runs don't panic on
// duplicate registration against the default registry.
func TestFailoverMetrics_Counts(t *testing.T) {
	m := newFailoverMetrics(prometheus.NewRegistry())

	m.Attempt(failover.PhaseFence, failover.ResultSuccess, "")
	m.Attempt(failover.PhaseFence, failover.ResultSuccess, "")
	m.Attempt(failover.PhaseSkip, failover.ResultSkipped, failover.ErrUpgrading)
	m.VMAction(failover.ActionReschedule, failover.ResultSuccess, "")
	m.ContainerAction(failover.ActionRelocate, failover.ResultError, failover.ErrRelocateFailed)

	if got := testutil.ToFloat64(m.attempts.WithLabelValues(failover.PhaseFence, failover.ResultSuccess, "")); got != 2 {
		t.Errorf("fence/success = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.attempts.WithLabelValues(failover.PhaseSkip, failover.ResultSkipped, failover.ErrUpgrading)); got != 1 {
		t.Errorf("skip/upgrading = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.vmActions.WithLabelValues(failover.ActionReschedule, failover.ResultSuccess, "")); got != 1 {
		t.Errorf("vm reschedule/success = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.containerActions.WithLabelValues(failover.ActionRelocate, failover.ResultError, failover.ErrRelocateFailed)); got != 1 {
		t.Errorf("ct relocate/error = %v, want 1", got)
	}
}
