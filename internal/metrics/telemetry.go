package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/litevirt/litevirt/internal/obs"
)

// circuitStateValue encodes a circuit-breaker state string as a gauge value:
// 0 = closed (healthy), 1 = half-open (probing after cooldown), 2 = open
// (tripped, exports short-circuited), -1 = unknown. Mirrors provide-telemetry's
// resilience circuit breaker states.
func circuitStateValue(s string) float64 {
	switch s {
	case "closed":
		return 0
	case "half-open":
		return 1
	case "open":
		return 2
	default:
		return -1
	}
}

// telemetryCollector exposes OTLP export health (from obs.Health) on Prometheus.
// This is "observability of the observability": it stays on the Prometheus pull
// path so it remains visible even when OTLP export itself is dead (fail-open).
//
// Signal split (see internal/obs.Health): logs still use the vendor's fail-open
// resilience wrapper, so logs health is vendor-snapshot-sourced. Traces use an
// obs-owned TracerProvider, so trace export failures come from an otel error
// handler; traces drop/circuit state is unobservable and must not be faked.
type telemetryCollector struct {
	exportErrors *prometheus.Desc
	dropped      *prometheus.Desc
	retries      *prometheus.Desc
	circuitState *prometheus.Desc
}

func newTelemetryCollector() *telemetryCollector {
	return &telemetryCollector{
		exportErrors: prometheus.NewDesc(
			"litevirt_telemetry_export_errors_total",
			"Cumulative OTLP export failures (logs from vendor snapshot + traces from obs error handler; fail-open). Nonzero and growing means the collector is unreachable or rejecting.",
			nil, nil),
		dropped: prometheus.NewDesc(
			"litevirt_telemetry_dropped_total",
			"Cumulative log records shed because the async export queue was full (backpressure; logs only). Trace drops are unobservable with the obs-owned TracerProvider and are not counted here.",
			nil, nil),
		retries: prometheus.NewDesc(
			"litevirt_telemetry_export_retries_total",
			"Cumulative OTLP export retry attempts (logs+traces, vendor snapshot).",
			nil, nil),
		circuitState: prometheus.NewDesc(
			"litevirt_telemetry_circuit_state",
			"OTLP exporter circuit-breaker state per signal: 0=closed, 1=half-open, 2=open, -1=unknown. signal=\"traces\" is always -1 (unobservable with obs-owned TracerProvider).",
			[]string{"signal"}, nil),
	}
}

func (c *telemetryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.exportErrors
	ch <- c.dropped
	ch <- c.retries
	ch <- c.circuitState
}

func (c *telemetryCollector) Collect(ch chan<- prometheus.Metric) {
	h := obs.Health()
	ch <- prometheus.MustNewConstMetric(c.exportErrors, prometheus.CounterValue, float64(h.ExportFailures))
	ch <- prometheus.MustNewConstMetric(c.dropped, prometheus.CounterValue, float64(h.Dropped))
	ch <- prometheus.MustNewConstMetric(c.retries, prometheus.CounterValue, float64(h.Retries))
	ch <- prometheus.MustNewConstMetric(c.circuitState, prometheus.GaugeValue, circuitStateValue(h.LogsCircuit), "logs")
	ch <- prometheus.MustNewConstMetric(c.circuitState, prometheus.GaugeValue, circuitStateValue(h.TracesCircuit), "traces")
}

// telemetryMetricsOnce guards registration so multiple metrics.Server
// constructions (e.g. in tests) don't double-register on the default registry.
var telemetryMetricsOnce sync.Once

// registerTelemetryMetrics registers the telemetry health collector on the
// default Prometheus registry exactly once.
func registerTelemetryMetrics() {
	telemetryMetricsOnce.Do(func() {
		prometheus.MustRegister(newTelemetryCollector())
	})
}
