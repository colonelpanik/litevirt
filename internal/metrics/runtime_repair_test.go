package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRuntimeRepairMetrics(t *testing.T) {
	m := newRuntimeRepairMetrics(prometheus.NewRegistry())
	m.OwnerAssert("vm", "asserted")
	m.OwnerAssert("vm", "asserted")
	m.OwnerAssert("ct", "rekeyed")
	m.OwnerAssert("vm", "split_brain")

	if got := testutil.ToFloat64(m.ownerAssert.WithLabelValues("vm", "asserted")); got != 2 {
		t.Errorf("vm/asserted = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.ownerAssert.WithLabelValues("ct", "rekeyed")); got != 1 {
		t.Errorf("ct/rekeyed = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ownerAssert.WithLabelValues("vm", "split_brain")); got != 1 {
		t.Errorf("vm/split_brain = %v, want 1", got)
	}
}
