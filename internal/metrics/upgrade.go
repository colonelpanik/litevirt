package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	upgradeWatchdogOnce  sync.Once
	upgradeWatchdogTotal *prometheus.CounterVec
)

// UpgradeWatchdogOutcome records a post-upgrade health-watchdog outcome:
//
//	confirmed | confirm_failed | rollback | giveup | no_old
//
// It registers lazily on the default registry on first use, so it works even
// when called before the metrics HTTP server is constructed — the watchdog arms
// very early in daemon startup (and may roll back + exit before that server runs).
func UpgradeWatchdogOutcome(outcome string) {
	upgradeWatchdogOnce.Do(func() {
		upgradeWatchdogTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_upgrade_watchdog_total",
			Help: "Post-upgrade health-watchdog outcomes (confirmed, confirm_failed, rollback, giveup, no_old).",
		}, []string{"outcome"})
		prometheus.DefaultRegisterer.MustRegister(upgradeWatchdogTotal)
	})
	upgradeWatchdogTotal.WithLabelValues(outcome).Inc()
}
