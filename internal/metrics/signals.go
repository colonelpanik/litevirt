package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Signals the daemon deliberately refuses to die on.
//
// This one is lazily registered rather than constructed like the other metric
// sets, because the signal handler is installed in main BEFORE the daemon (and
// therefore the metrics server) exists. There is nothing to hand a *SignalMetrics
// to at that point, so the counter registers itself on first use.

var (
	signalOnce    sync.Once
	signalIgnored *prometheus.CounterVec
)

// SignalIgnored counts a signal the daemon received and deliberately dropped.
//
// Worth a counter and not just a log line: a node being HUP'd repeatedly by
// needrestart or unattended-upgrades is the condition that used to take it down,
// and it is invisible in the fleet's health otherwise — the daemon now survives,
// so nothing else changes. A rising count is how an operator learns something on
// the host keeps trying to bounce the orchestrator.
func SignalIgnored(signal string) {
	signalOnce.Do(func() {
		signalIgnored = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_signal_ignored_total",
			Help: "Signals the daemon received and deliberately did not act on, by signal. " +
				"Dying on these would look like a clean exit to systemd and leave the node down.",
		}, []string{"signal"})
		prometheus.DefaultRegisterer.MustRegister(signalIgnored)
	})
	signalIgnored.WithLabelValues(signal).Inc()
}
