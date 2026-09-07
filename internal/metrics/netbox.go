package metrics

import (
	"sync"
	"time"

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

	netboxUnclaimableDiscoveries *prometheus.CounterVec
	netboxMirrorObjects          *prometheus.CounterVec
	netboxMirrorSweeps           *prometheus.CounterVec
	netboxMirrorLastSuccess      prometheus.Gauge
)

// NetBoxDiscoveryReasons is the BOUNDED reason vocabulary of
// litevirt_netbox_unclaimable_discoveries_total, materialised at zero by
// netboxInit so a dashboard shows every series before the first occurrence.
//
// Literals rather than an import: the values are produced in internal/grpcapi,
// which imports THIS package, so the dependency cannot go the other way. The two
// lists are kept in step by a test on the grpcapi side
// (TestDiscoveryReasonLabelsAreMaterialisedAtZero), which compares its own
// constants against this slice — the same shape as the sink's structural
// interface check, and for the same reason.
var NetBoxDiscoveryReasons = []string{"not_ours", "unknown", "no_allocator", "no_identity"}

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
			Help: "Bindings taken out of service and left that way: by revalidation drift, or " +
				"by a bind whose adoption of the addresses its guests already hold could not " +
				"finish. Cumulative; the number suspended RIGHT NOW is " +
				"litevirt_netbox_bindings_suspended.",
		})
		netboxDuplicateObjects = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "litevirt_netbox_duplicate_objects_total",
			Help: "NetBox objects found duplicated for one litevirt identity by the inventory mirror.",
		})
		netboxUnclaimableDiscoveries = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_netbox_unclaimable_discoveries_total",
			Help: "Addresses a guest was discovered USING on a bound network that litevirt " +
				"declined to record, by bounded reason. reason=not_ours is the serious one: " +
				"NetBox holds that address for something else, so two things are using it. " +
				"Nothing repairs it automatically and the address is left off the NIC record " +
				"rather than asserted as litevirt's.",
		}, []string{"reason"})
		netboxMirrorObjects = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_netbox_mirror_objects_total",
			Help: "NetBox objects the inventory mirror WROTE, by object kind and operation. " +
				"The mirror writes only on change, so a count that keeps climbing over " +
				"unchanging inventory is drift the diff cannot settle.",
		}, []string{"kind", "op"})
		netboxMirrorSweeps = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_netbox_mirror_sweeps_total",
			Help: "Inventory mirror sweeps by result. Counted on the leader only — a node that " +
				"does not hold the lease runs no sweep and records nothing.",
		}, []string{"result"})
		netboxMirrorLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_netbox_mirror_last_success_seconds",
			Help: "Unix time of the last SUCCESSFUL inventory mirror sweep on this node; 0 if it " +
				"has never completed one. Alert on the cluster-wide max: only the leader sweeps.",
		})
		prometheus.DefaultRegisterer.MustRegister(
			netboxAPIErrors, netboxAmbiguousClaims, netboxOrphansReclaimed,
			netboxSweepsSkipped, netboxStuckLeases, netboxBindingsSuspended,
			netboxDuplicateObjects, netboxMirrorObjects, netboxMirrorSweeps,
			netboxMirrorLastSuccess, netboxUnclaimableDiscoveries,
		)
		// Materialise the three error classes at zero so a dashboard shows the
		// series before the first failure, and so rate() has a baseline.
		for _, class := range []string{"transport", "client", "server"} {
			netboxAPIErrors.WithLabelValues(class)
		}
		// Same for both sweep results. The error rate is what an operator
		// alerts on, and a series that only appears once something has already
		// failed gives the alert nothing to compare against.
		for _, result := range []string{"ok", "error"} {
			netboxMirrorSweeps.WithLabelValues(result)
		}
		// …and for every discovery-refusal reason. This is the counter that
		// matters most to have at zero: reason=not_ours means two things are
		// using one address, so it is the series an operator builds an alert on
		// — and an alert on a series that does not exist until the first
		// occurrence fires late or not at all, depending on the alerting stack.
		for _, reason := range NetBoxDiscoveryReasons {
			netboxUnclaimableDiscoveries.WithLabelValues(reason)
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

// IncBindingSuspended counts one binding taken out of service AND LEFT THERE —
// by revalidation drift, or by a bind-time adoption that could not finish.
//
// Not emitted for the suspension a successful bind takes while it adopts: that
// one is lifted inside the same RPC, and counting it would page an operator
// alerting on this counter's rate for a bind that worked. The live gauge reads
// the rows, so it shows that one for as long as it lasts.
func (*NetBoxMetrics) IncBindingSuspended() { netboxBindingsSuspended.Inc() }

// IncDuplicateObject counts one NetBox object found duplicated for a single
// litevirt identity by the inventory mirror, and deleted by the sweep.
func (*NetBoxMetrics) IncDuplicateObject() { netboxDuplicateObjects.Inc() }

// IncUnclaimableDiscovery counts one discovered address litevirt would not
// record. The reason MUST come from the discovery gate's closed vocabulary —
// never from an error string, which names a VM and an address and would make
// this label unbounded.
func (*NetBoxMetrics) IncUnclaimableDiscovery(reason string) {
	netboxUnclaimableDiscoveries.WithLabelValues(reason).Inc()
}

// IncMirrorObject counts one NetBox object the mirror wrote. BOTH label values
// come from the mirror's closed vocabularies — the NetBox object kind
// ("virtual_machine", "vminterface") and the operation ("created", "updated",
// "deleted") — never from an error string or a litevirt object name, which
// would make the label unbounded.
func (*NetBoxMetrics) IncMirrorObject(kind, op string) {
	netboxMirrorObjects.WithLabelValues(kind, op).Inc()
}

// IncMirrorSweep counts one mirror sweep by result ("ok" or "error").
func (*NetBoxMetrics) IncMirrorSweep(result string) {
	netboxMirrorSweeps.WithLabelValues(result).Inc()
}

// SetMirrorLastSuccess records when a sweep last SUCCEEDED, in unix seconds.
//
// Seconds, not nanoseconds and not a monotonic reading: the alert this exists
// for is arithmetic against Prometheus's own wall clock (`time() - <this>`), and
// any other unit reads as a mirror that converged in the distant future.
func (*NetBoxMetrics) SetMirrorLastSuccess(t time.Time) {
	netboxMirrorLastSuccess.Set(float64(t.Unix()))
}
