package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// gaugeFor returns the litevirt_lb_keepalived_up_test value for label lb=<name>,
// and whether the series is present.
func gaugeFor(t *testing.T, reg *prometheus.Registry, lb string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "lb" && l.GetValue() == lb {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

// The keepalived-up gauge can be set per LB and dropped on teardown. Built on an
// isolated registry (test-suffixed name) so it doesn't collide with the global
// one NewLBMetrics uses.
func TestLBMetrics_KeepalivedUpSetAndDelete(t *testing.T) {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "litevirt_lb_keepalived_up_test",
		Help: "test",
	}, []string{"lb"})
	reg.MustRegister(g)
	m := &LBMetrics{KeepalivedUp: g}

	m.KeepalivedUp.WithLabelValues("app-lb").Set(1)
	if v, ok := gaugeFor(t, reg, "app-lb"); !ok || v != 1 {
		t.Errorf("gauge = %v (present=%v), want 1 (keepalived up)", v, ok)
	}
	m.KeepalivedUp.WithLabelValues("app-lb").Set(0)
	if v, _ := gaugeFor(t, reg, "app-lb"); v != 0 {
		t.Errorf("gauge = %v, want 0 (VIP down)", v)
	}
	if !m.KeepalivedUp.DeleteLabelValues("app-lb") {
		t.Error("DeleteLabelValues should drop the torn-down LB's series")
	}
	if _, ok := gaugeFor(t, reg, "app-lb"); ok {
		t.Error("series still present after delete")
	}
}
