package metrics

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// netboxFamilies gathers the DEFAULT registry — the one promhttp serves — so
// these tests fail if a counter is constructed but never registered. A counter
// that exists only as a Go value is invisible to every dashboard and alert.
func netboxFamilies(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

// TestNetBoxMetricsRegistered pins every NetBox counter onto the default
// registry under its exact documented name.
//
// Each Inc runs first because a CounterVec with no children emits no family at
// all: "registered" is only observable once a series exists.
func TestNetBoxMetricsRegistered(t *testing.T) {
	m := NewNetBoxMetrics()
	m.IncAPIError(netbox.ClassTransport)
	m.IncAmbiguousClaim()
	m.IncOrphansReclaimed()
	m.IncSweepSkipped("host_unreachable")
	m.IncStuckLease()
	m.IncBindingSuspended()

	want := []string{
		"litevirt_netbox_api_errors_total",
		"litevirt_netbox_ambiguous_claims_total",
		"litevirt_netbox_orphans_reclaimed_total",
		"litevirt_netbox_sweeps_skipped_total",
		"litevirt_netbox_stuck_leases_total",
		"litevirt_netbox_bindings_suspended_total",
		"litevirt_netbox_duplicate_objects_total",
	}
	got := netboxFamilies(t)
	for _, name := range want {
		if got[name] == nil {
			t.Errorf("metric %s is not registered on the default registry", name)
		}
	}
}

// TestNetBoxMetricsConstructorIsIdempotent pins that a second construction does
// not panic on duplicate registration. Every test binary in this package that
// touches the sink would otherwise be a coin flip on test ordering, and the
// daemon itself constructs the sink after other subsystems have registered.
func TestNetBoxMetricsConstructorIsIdempotent(t *testing.T) {
	a := NewNetBoxMetrics()
	b := NewNetBoxMetrics()
	if a == nil || b == nil {
		t.Fatal("NewNetBoxMetrics returned nil")
	}
	b.IncOrphansReclaimed() // must reach the same registered counter
}

// TestNetBoxMetricsSatisfiesTheServerSink pins the STRUCTURAL contract with
// internal/grpcapi. The sink interface there is unexported and grpcapi imports
// this package, so the compile-time check has to live on this side: a renamed
// or dropped method here would otherwise only surface as the daemon silently
// falling back to the noop sink.
func TestNetBoxMetricsSatisfiesTheServerSink(t *testing.T) {
	// Mirrors grpcapi.netboxMetrics exactly.
	type serverSink interface {
		IncAPIError(netbox.ErrClass)
		IncSweepSkipped(reason string)
		IncOrphansReclaimed()
		IncStuckLease()
		IncBindingSuspended()
		IncAmbiguousClaim()
	}
	var _ serverSink = NewNetBoxMetrics()
}

// TestNetBoxAPIErrorClassLabelIsBounded pins the class label to the three
// classes netbox.Classify can produce plus one catch-all. An unmapped class
// must not put an integer (or an error string) into a Prometheus label.
func TestNetBoxAPIErrorClassLabelIsBounded(t *testing.T) {
	cases := map[netbox.ErrClass]string{
		netbox.ClassTransport: "transport",
		netbox.ClassClient:    "client",
		netbox.ClassServer:    "server",
		netbox.ErrClass(42):   "unknown",
	}
	for class, want := range cases {
		if got := apiErrorClassLabel(class); got != want {
			t.Errorf("apiErrorClassLabel(%d) = %q, want %q", class, got, want)
		}
	}

	m := NewNetBoxMetrics()
	for class := range cases {
		m.IncAPIError(class)
	}
	fam := netboxFamilies(t)["litevirt_netbox_api_errors_total"]
	if fam == nil {
		t.Fatal("litevirt_netbox_api_errors_total is not registered")
	}
	allowed := map[string]bool{"transport": true, "client": true, "server": true, "unknown": true}
	for _, series := range fam.GetMetric() {
		for _, l := range series.GetLabel() {
			if l.GetName() != "class" {
				t.Errorf("unexpected label %q on litevirt_netbox_api_errors_total", l.GetName())
				continue
			}
			if !allowed[l.GetValue()] {
				t.Errorf("class label %q is outside the bounded vocabulary", l.GetValue())
			}
		}
	}
}

// TestCollectNetBoxGauges pins the two DB-backed gauges. Both answer questions
// a counter cannot: how much mirror work is queued RIGHT NOW, and how many
// bindings are refusing allocations RIGHT NOW. A counter of suspensions keeps
// rising after an operator repairs one.
func TestCollectNetBoxGauges(t *testing.T) {
	db := initTestDB(t)
	ctx := context.Background()

	for _, b := range []corrosion.BindingRecord{
		{PrefixID: 11, Network: "net-a", ObservedCIDR: "10.0.5.0/24", VRFID: 3, ClusterFingerprint: "fp"},
		{PrefixID: 12, Network: "net-b", ObservedCIDR: "10.0.6.0/24", VRFID: 3, ClusterFingerprint: "fp"},
		{PrefixID: 13, Network: "net-c", ObservedCIDR: "10.0.7.0/24", VRFID: 3, ClusterFingerprint: "fp"},
	} {
		if ok, err := corrosion.ClaimBinding(ctx, db, b); err != nil || !ok {
			t.Fatalf("ClaimBinding %d: ok=%v err=%v", b.PrefixID, ok, err)
		}
	}
	for _, prefix := range []int{11, 13} {
		if err := corrosion.SuspendBinding(ctx, db, prefix, "prefix re-CIDRed"); err != nil {
			t.Fatalf("SuspendBinding %d: %v", prefix, err)
		}
	}
	for i := 0; i < 4; i++ {
		if err := corrosion.EnqueueSync(ctx, db, "vm", "vm-1", "upsert"); err != nil {
			t.Fatalf("EnqueueSync: %v", err)
		}
	}
	queued, err := corrosion.DrainSyncQueue(ctx, db, "vm", 1)
	if err != nil || len(queued) == 0 {
		t.Fatalf("DrainSyncQueue: %v (%d items)", err, len(queued))
	}
	// An acked item is done work, not queued depth.
	if err := corrosion.AckSyncItem(ctx, db, queued[0].ID); err != nil {
		t.Fatalf("AckSyncItem: %v", err)
	}

	c := newCollector(db, nil, nil, "host-a")
	ch := make(chan prometheus.Metric, 200)
	c.Collect(ch)
	close(ch)

	values := map[string]float64{}
	for m := range ch {
		d := m.Desc().String()
		for _, name := range []string{"litevirt_netbox_sync_queue_depth", "litevirt_netbox_bindings_suspended"} {
			// The two names are distinct, but sync_queue_depth is not a prefix
			// of bindings_suspended, so an exact-substring match is unambiguous.
			if strings.Contains(d, `fqName: "`+name+`"`) {
				var dm dto.Metric
				if err := m.Write(&dm); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
				values[name] = dm.GetGauge().GetValue()
			}
		}
	}

	if got, ok := values["litevirt_netbox_sync_queue_depth"]; !ok || got != 3 {
		t.Errorf("litevirt_netbox_sync_queue_depth = %v (present=%v), want 3", got, ok)
	}
	if got, ok := values["litevirt_netbox_bindings_suspended"]; !ok || got != 2 {
		t.Errorf("litevirt_netbox_bindings_suspended = %v (present=%v), want 2", got, ok)
	}
}

// TestNetBoxMetricsSatisfiesTheMirrorSink pins the STRUCTURAL contract with
// internal/netboxsync, whose sink interface is unexported for the same reason
// grpcapi's is. Without this check a renamed method there would silently leave
// the inventory mirror counting duplicates into a noop.
func TestNetBoxMetricsSatisfiesTheMirrorSink(t *testing.T) {
	// Mirrors netboxsync.mirrorMetrics exactly.
	type mirrorSink interface {
		IncDuplicateObject()
	}
	var s mirrorSink = NewNetBoxMetrics()
	s.IncDuplicateObject()

	fam := netboxFamilies(t)["litevirt_netbox_duplicate_objects_total"]
	if fam == nil || len(fam.GetMetric()) == 0 {
		t.Fatal("litevirt_netbox_duplicate_objects_total is not registered")
	}
	if got := fam.GetMetric()[0].GetCounter().GetValue(); got < 1 {
		t.Fatalf("litevirt_netbox_duplicate_objects_total = %v, want at least 1", got)
	}
}
