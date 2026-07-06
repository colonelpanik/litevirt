package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/litevirt/litevirt/internal/obs"
)

// telemetryMetricsOnce guards registration so multiple metrics.Server
// constructions (e.g. in tests) don't double-register and panic.
var telemetryMetricsOnce sync.Once

// registerTelemetryMetrics exposes the OTLP export-error count on Prometheus.
// This is "observability of the observability": a growing counter means the
// telemetry collector is unreachable/rejecting and traces/logs are being dropped
// (fail-open). Metrics themselves stay on Prometheus — obs never exports them —
// so this signal is always visible even when OTLP export is dead.
func registerTelemetryMetrics() {
	telemetryMetricsOnce.Do(func() {
		prometheus.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "litevirt_telemetry_export_errors_total",
			Help: "Cumulative OTLP telemetry export failures (spans/logs dropped, fail-open). Nonzero and growing means the collector is unreachable or rejecting data.",
		}, func() float64 { return float64(obs.ExportErrors()) }))
	})
}
