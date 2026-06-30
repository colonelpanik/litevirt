package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AntiEntropyMetrics times the anti-entropy dump/digest/merge phases and counts
// rows applied/skipped by merges. It structurally satisfies corrosion.SyncMetrics
// (the interface is defined in internal/corrosion), so the corrosion package
// never imports this one — avoiding the import cycle (metrics already imports
// corrosion). Registered on the default registry that promhttp serves on :7444.
type AntiEntropyMetrics struct {
	dumpSeconds          prometheus.Histogram
	digestSeconds        prometheus.Histogram
	mergeSeconds         prometheus.Histogram
	dumpBytes            prometheus.Histogram
	rowsMerged           prometheus.Counter
	rowsSkipped          prometheus.Counter
	tieBreaks            *prometheus.CounterVec
	tieUnresolved        *prometheus.CounterVec
	tombstoneTies        *prometheus.CounterVec
	tieUnresolvedCurrent prometheus.Gauge
}

// NewAntiEntropyMetrics registers the anti-entropy timing metrics on the default
// registry. Call once at daemon startup.
func NewAntiEntropyMetrics() *AntiEntropyMetrics {
	return newAntiEntropyMetrics(prometheus.DefaultRegisterer)
}

// newAntiEntropyMetrics is the test seam: tests pass a fresh prometheus.NewRegistry()
// so repeated construction across test funcs doesn't panic on duplicate registration.
func newAntiEntropyMetrics(reg prometheus.Registerer) *AntiEntropyMetrics {
	secs := func(name, help string) prometheus.Histogram {
		return prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: prometheus.ExponentialBuckets(0.001, 4, 8), // 1ms … ~16s
		})
	}
	m := &AntiEntropyMetrics{
		dumpSeconds:   secs("litevirt_antientropy_dump_seconds", "Wall time to build a full-state dump."),
		digestSeconds: secs("litevirt_antientropy_digest_seconds", "Wall time to compute the state digest (per cycle)."),
		mergeSeconds:  secs("litevirt_antientropy_merge_seconds", "Wall time to merge a received full-state dump."),
		dumpBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "litevirt_antientropy_dump_bytes",
			Help:    "Compressed size of a full-state dump, bytes.",
			Buckets: prometheus.ExponentialBuckets(1024, 4, 8), // 1 KiB … ~16 MiB
		}),
		rowsMerged: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_antientropy_rows_merged_total",
			Help: "Rows applied (INSERT OR REPLACE) by anti-entropy full-state merges.",
		}),
		rowsSkipped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_antientropy_rows_skipped_total",
			Help: "Rows skipped by anti-entropy merges (LWW kept local, or malformed).",
		}),
		tieBreaks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_lww_tie_break_total",
			Help: "Exact-timestamp ties a resolver converged, by table, resolver rule, and winner (local/incoming).",
		}, []string{"table", "resolver", "winner"}),
		tieUnresolved: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_lww_tie_unresolved_total",
			Help: "Distinct equal-timestamp ties with no safe winner (kept local; needs human/runtime repair), by table, path, and category.",
		}, []string{"table", "path", "category"}),
		tombstoneTies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_lww_tombstone_tie_total",
			Help: "Equal-timestamp ties settled by a one-sided soft-delete (a delete racing a write — benign), by table.",
		}, []string{"table"}),
		tieUnresolvedCurrent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_lww_tie_unresolved_current",
			Help: "Distinct unresolved ties this node is CURRENTLY tracking (a gauge — drops to 0 when repaired). Alert on this for 'something is divergent now'; the _total counter is monotonic and would page forever.",
		}),
	}
	reg.MustRegister(m.dumpSeconds, m.digestSeconds, m.mergeSeconds, m.dumpBytes, m.rowsMerged, m.rowsSkipped, m.tieBreaks, m.tieUnresolved, m.tombstoneTies, m.tieUnresolvedCurrent)
	return m
}

// ObserveDump records a full-state dump build. (Satisfies corrosion.SyncMetrics.)
func (m *AntiEntropyMetrics) ObserveDump(d time.Duration, bytes int) {
	m.dumpSeconds.Observe(d.Seconds())
	if bytes > 0 {
		m.dumpBytes.Observe(float64(bytes))
	}
}

// ObserveDigest records a state-digest computation.
func (m *AntiEntropyMetrics) ObserveDigest(d time.Duration) {
	m.digestSeconds.Observe(d.Seconds())
}

// ObserveMerge records a full-state merge and the rows it applied/skipped.
func (m *AntiEntropyMetrics) ObserveMerge(d time.Duration, merged, skipped int) {
	m.mergeSeconds.Observe(d.Seconds())
	if merged > 0 {
		m.rowsMerged.Add(float64(merged))
	}
	if skipped > 0 {
		m.rowsSkipped.Add(float64(skipped))
	}
}

// ObserveTieBreak records a converged equal-timestamp tie. (Satisfies corrosion.SyncMetrics.)
func (m *AntiEntropyMetrics) ObserveTieBreak(table, resolver, winner string) {
	m.tieBreaks.WithLabelValues(table, resolver, winner).Inc()
}

// ObserveTieUnresolved records a distinct unresolved equal-timestamp tie. (Satisfies corrosion.SyncMetrics.)
func (m *AntiEntropyMetrics) ObserveTieUnresolved(table, path, category string) {
	m.tieUnresolved.WithLabelValues(table, path, category).Inc()
}

// ObserveTombstoneTie records a tie settled by a one-sided soft-delete. (Satisfies corrosion.SyncMetrics.)
func (m *AntiEntropyMetrics) ObserveTombstoneTie(table string) {
	m.tombstoneTies.WithLabelValues(table).Inc()
}

// ObserveUnresolvedTieCurrent sets the current-unresolved-ties gauge. (Satisfies corrosion.SyncMetrics.)
func (m *AntiEntropyMetrics) ObserveUnresolvedTieCurrent(n int) {
	m.tieUnresolvedCurrent.Set(float64(n))
}
