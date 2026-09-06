package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/litevirt/litevirt/internal/netbox"
)

// NetBox IPAM observability.
//
// The counters live in package-level vars behind a sync.Once, the way the audit
// chain's do: the daemon constructs the sink once, but a test binary constructs
// it repeatedly, and prometheus.MustRegister panics on the second registration
// of the same name. Registration must never be a reason a process dies.
//
// NetBoxMetrics structurally satisfies grpcapi's unexported netboxMetrics sink
// and network's apiErrorCounter, so NEITHER package is imported here and this
// package is not imported by them for the sink's sake. internal/netbox is the
// one import, for the error class the API paths already classify.
var (
	netboxOnce              sync.Once
	netboxAPIErrors         *prometheus.CounterVec
	netboxAmbiguousClaims   prometheus.Counter
	netboxOrphansReclaimed  prometheus.Counter
	netboxSweepsSkipped     *prometheus.CounterVec
	netboxStuckLeases       prometheus.Counter
	netboxBindingsSuspended prometheus.Counter
	netboxDuplicateObjects  prometheus.Counter
)

func netboxInit() {
	netboxOnce.Do(func() {
		netboxAPIErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_netbox_api_errors_total",
			Help: "NetBox API failures by class: transport (no answer), client (4xx — NetBox " +
				"answered and said no), server (5xx — the write may or may not have committed).",
		}, []string{"class"})
		netboxAmbiguousClaims = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_netbox_ambiguous_claims_total",
			Help: "Address claims whose outcome was unknown and had to be resolved by lookup. " +
				"A rising count means responses are being lost between litevirt and NetBox.",
		})
		netboxOrphansReclaimed = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_netbox_orphans_reclaimed_total",
			Help: "NetBox IP objects deleted by the orphan sweep under a whole-cluster negative proof.",
		})
		netboxSweepsSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_netbox_sweeps_skipped_total",
			Help: "Reclamations the orphan sweep declined to perform, by bounded reason. " +
				"Every skip leaves the address allocated, which is always the safe direction.",
		}, []string{"reason"})
		netboxStuckLeases = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_netbox_stuck_leases_total",
			Help: "Addresses whose NetBox object was queued for release while a live local lease " +
				"still names them. Never resolved automatically — an operator must retire the lease.",
		})
		netboxBindingsSuspended = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_netbox_bindings_suspended_total",
			Help: "Bindings taken out of service by revalidation drift. Cumulative; the number " +
				"suspended RIGHT NOW is litevirt_netbox_bindings_suspended.",
		})
		netboxDuplicateObjects = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_netbox_duplicate_objects_total",
			Help: "NetBox objects found duplicated for one litevirt identity by the inventory mirror.",
		})
		prometheus.DefaultRegisterer.MustRegister(
			netboxAPIErrors, netboxAmbiguousClaims, netboxOrphansReclaimed,
			netboxSweepsSkipped, netboxStuckLeases, netboxBindingsSuspended,
			netboxDuplicateObjects,
		)
		// Materialise the three error classes at zero so a dashboard shows the
		// series before the first failure, and so rate() has a baseline.
		for _, class := range []string{"transport", "client", "server"} {
			netboxAPIErrors.WithLabelValues(class)
		}
	})
}

// NetBoxMetrics is the NetBox IPAM counter sink. It carries no state of its own
// — the counters are process-global — so copies and repeated constructions are
// all the same sink.
type NetBoxMetrics struct{}

// NewNetBoxMetrics registers the NetBox counters on the default registry (which
// promhttp serves at the metrics port) and returns the sink. Safe to call more
// than once.
func NewNetBoxMetrics() *NetBoxMetrics {
	netboxInit()
	return &NetBoxMetrics{}
}

// apiErrorClassLabel maps a class to its BOUNDED label. An unrecognised class
// becomes "unknown" rather than a formatted integer: the label vocabulary is a
// closed set, and a new class must be named here deliberately.
func apiErrorClassLabel(c netbox.ErrClass) string {
	switch c {
	case netbox.ClassTransport:
		return "transport"
	case netbox.ClassClient:
		return "client"
	case netbox.ClassServer:
		return "server"
	default:
		return "unknown"
	}
}

// IncAPIError counts one NetBox API failure by class.
func (*NetBoxMetrics) IncAPIError(c netbox.ErrClass) {
	netboxAPIErrors.WithLabelValues(apiErrorClassLabel(c)).Inc()
}

// IncAmbiguousClaim counts one claim whose outcome had to be resolved by lookup.
func (*NetBoxMetrics) IncAmbiguousClaim() { netboxAmbiguousClaims.Inc() }

// IncOrphansReclaimed counts one proven orphan deleted from NetBox.
func (*NetBoxMetrics) IncOrphansReclaimed() { netboxOrphansReclaimed.Inc() }

// IncSweepSkipped counts one declined reclamation. The reason MUST come from
// the sweeper's closed vocabulary — never from an error string, which carries
// addresses and host names and would make this label unbounded.
func (*NetBoxMetrics) IncSweepSkipped(reason string) {
	netboxSweepsSkipped.WithLabelValues(reason).Inc()
}

// IncStuckLease counts one address leaked in both systems until an operator acts.
func (*NetBoxMetrics) IncStuckLease() { netboxStuckLeases.Inc() }

// IncBindingSuspended counts one binding taken out of service by drift.
func (*NetBoxMetrics) IncBindingSuspended() { netboxBindingsSuspended.Inc() }
