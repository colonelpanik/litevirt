package metrics

import "github.com/prometheus/client_golang/prometheus"

// LBMetrics holds Prometheus gauges for load-balancer health. KeepalivedUp is
// the signal a dashboard/alert needs to catch an unassigned VIP — HAProxy binds
// the VIP non-locally even when keepalived is down, so "haproxy up" alone hides
// the failure.
type LBMetrics struct {
	KeepalivedUp *prometheus.GaugeVec // label: lb (1 = keepalived running / VIP assignable, 0 = down)
}

// NewLBMetrics creates and registers the LB metrics.
func NewLBMetrics() *LBMetrics {
	m := &LBMetrics{
		KeepalivedUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_lb_keepalived_up",
			Help: "Whether an LB's keepalived process is running on this host (1) or not (0); 0 means the VIP is not assigned.",
		}, []string{"lb"}),
	}
	prometheus.MustRegister(m.KeepalivedUp)
	return m
}
