package netboxsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// macChurn is the NIC every scenario here mirrors.
const macChurn = "52:54:00:aa:bb:cc"

// TestMirrorCountsEveryObjectItWrites pins the churn counter to the writes the
// mirror actually issues, separated by object kind AND by operation.
//
// Both labels carry their own claim. The kind tells a VM churning apart from an
// interface churning, which are different faults — a NIC rewritten every sweep
// is a MAC or naming instability, a VM rewritten every sweep is a field the
// mirror cannot round-trip. The op tells convergence apart from thrash: a
// steady stream of creates is a mirror that never records what it wrote, while
// the same count under "updated" is a field that will not settle. Collapsed
// into one series they are indistinguishable, and write-on-change — the whole
// reason a quiet cluster costs NetBox nothing — becomes unobservable.
func TestMirrorCountsEveryObjectItWrites(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}, interfacesByIdentity: map[string][]int{}}
	r := newTestReconciler(t, nb)
	ctx := context.Background()

	vmKey := vmIdent("uuid-1")
	nicKey := nicIdent("uuid-1", macChurn)
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: macChurn}},
	}}, fp)

	for _, a := range []Action{
		{Kind: kindVM, Op: "create", Key: vmKey},
		{Kind: kindNIC, Op: "create", Key: nicKey, ParentNetBoxID: 11},
		{Kind: kindVM, Op: "update", Key: vmKey, NetBoxID: 11},
		{Kind: kindNIC, Op: "update", Key: nicKey, NetBoxID: 21},
		{Kind: kindVM, Op: "delete", Key: vmKey, NetBoxID: 11},
		{Kind: kindNIC, Op: "delete", Key: nicKey, NetBoxID: 21},
	} {
		if err := r.apply(ctx, []Action{a}, idx, fp); err != nil {
			t.Fatalf("%s/%s: %v", a.Kind, a.Op, err)
		}
	}

	want := map[string]int{
		netboxKindVM + "/created":  1,
		netboxKindVM + "/updated":  1,
		netboxKindVM + "/deleted":  1,
		netboxKindNIC + "/created": 1,
		netboxKindNIC + "/updated": 1,
		netboxKindNIC + "/deleted": 1,
	}
	got := mirrorSink(t, r).objects()
	if len(got) != len(want) {
		t.Fatalf("counted %v, want one series per kind and op: %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s counted %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
}

// TestMirrorCountsNoObjectItDidNotWrite is the write-on-change control.
//
// An ADOPTED object — one the search found standing in NetBox because a create
// landed but its identity-map write did not — is not a write, and a delete of an
// object already gone is not a write either. Counting either one would make a
// converged mirror look like it was churning, and the counter's only job is to
// tell those two apart.
func TestMirrorCountsNoObjectItDidNotWrite(t *testing.T) {
	vmKey := vmIdent("uuid-1")
	nicKey := nicIdent("uuid-1", macChurn)
	nb := &stubVirt{
		byIdentity:           map[string][]int{vmKey: {11}},
		interfacesByIdentity: map[string][]int{nicKey: {21}},
		deleteErr:            &netbox.APIError{Status: 404, Body: "Not found."},
	}
	r := newTestReconciler(t, nb)
	ctx := context.Background()
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: macChurn}},
	}}, fp)

	for _, a := range []Action{
		{Kind: kindVM, Op: "create", Key: vmKey},
		{Kind: kindNIC, Op: "create", Key: nicKey, ParentNetBoxID: 11},
		{Kind: kindVM, Op: "delete", Key: vmKey, NetBoxID: 11},
	} {
		if err := r.apply(ctx, []Action{a}, idx, fp); err != nil {
			t.Fatalf("%s/%s: %v", a.Kind, a.Op, err)
		}
	}

	if got := mirrorSink(t, r).objects(); len(got) != 0 {
		t.Fatalf("an adoption and an already-absent delete wrote nothing, but counted %v", got)
	}
}

// TestFailedSweepRecordsNoSuccess is the staleness signal.
//
// litevirt_netbox_mirror_last_success_seconds is what an operator alerts on —
// "the mirror has not converged in N minutes" — so it may only advance on a
// sweep that genuinely reconciled. A timestamp bumped by a failed pass reports a
// healthy mirror for as long as the failure lasts, which is exactly the window
// the alert exists to cover.
func TestFailedSweepRecordsNoSuccess(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", macChurn)
	ctx := context.Background()

	// Fail the sweep where a real NetBox does — on the write, after the reads —
	// so the pass reaches the end and returns an error rather than being turned
	// back at the door.
	fingerprint, err := corrosion.ClusterFingerprint(ctx, r.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	nb.createErr = map[string]error{
		netbox.Identity(fingerprint, "uuid-1", ""): errors.New("netbox refused the create"),
	}

	if err := r.SyncOnce(ctx); err == nil {
		t.Fatal("the create was rigged to fail, so the sweep must report an error")
	}

	m := mirrorSink(t, r)
	if got := m.sweeps(); got["error"] != 1 || got["ok"] != 0 {
		t.Fatalf("sweep results = %v, want exactly one error and no ok", got)
	}
	if ts := m.lastSuccess(); !ts.IsZero() {
		t.Fatalf("a failed sweep recorded a success at %v — the staleness alert would never fire", ts)
	}

	// The positive control: the same fixture, repaired, must advance it. Without
	// this the assertion above is satisfied by a sink nothing ever calls.
	nb.createErr = nil
	before := time.Now()
	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("the repaired sweep must succeed: %v", err)
	}
	if got := m.sweeps(); got["ok"] != 1 || got["error"] != 1 {
		t.Fatalf("sweep results = %v, want one ok and the earlier error", got)
	}
	ts := m.lastSuccess()
	if ts.Before(before) || ts.After(time.Now()) {
		t.Fatalf("last success = %v, want a wall-clock time from this sweep (between %v and now)", ts, before)
	}
}

// TestNonLeaderRecordsNoSweep pins the gate.
//
// Every configured node runs the loop and only one leads, so a node that never
// swept must not report a result at all. Counting a skipped pass as ok would put
// a fresh success timestamp on every node in the cluster and make the staleness
// alert unfireable; counting it as an error would raise one on every node but
// the leader.
func TestNonLeaderRecordsNoSweep(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{
		AcquireLease: func(context.Context) bool { return false },
		HoldsLease:   func(context.Context) bool { return false },
	})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", macChurn)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("a node that does not lead reports nothing, not an error: %v", err)
	}
	m := mirrorSink(t, r)
	if got := m.sweeps(); len(got) != 0 {
		t.Fatalf("a non-leader recorded sweep results %v, want none", got)
	}
	if ts := m.lastSuccess(); !ts.IsZero() {
		t.Fatalf("a non-leader recorded a success at %v", ts)
	}
}

// TestNilMetricsSinkNeverPanics pins the nil-safe accessor.
//
// Options.Metrics is optional and every bare construction leaves it nil, so an
// emit site reaching r.metrics directly would panic the sweep goroutine — taking
// the whole daemon down over a counter. Every method on the sink is exercised
// here, because only the one that was forgotten panics.
func TestNilMetricsSinkNeverPanics(t *testing.T) {
	vmKey := vmIdent("uuid-1")
	nb := &stubVirt{
		// Two objects under one identity: the applier de-duplicates, which is
		// the duplicate counter's only emit site.
		byIdentity:           map[string][]int{vmKey: {11, 12}},
		interfacesByIdentity: map[string][]int{},
	}
	r := New(Options{
		NetBox: nb, DB: newMirrorDB(t), Metrics: nil,
		AcquireLease: leaseHeld, HoldsLease: leaseHeld, Latched: leaseHeld,
	})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", macChurn)
	ctx := context.Background()

	// The sweep: cluster resolve, diff, create, sweep result, success stamp.
	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce with no metrics sink: %v", err)
	}
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: macChurn}},
	}}, fp)
	// The de-duplicating create, then an update and a delete: the remaining
	// emit sites.
	for _, a := range []Action{
		{Kind: kindVM, Op: "create", Key: vmKey},
		{Kind: kindVM, Op: "update", Key: vmKey, NetBoxID: 11},
		{Kind: kindVM, Op: "delete", Key: vmKey, NetBoxID: 11},
	} {
		if err := r.apply(ctx, []Action{a}, idx, fp); err != nil {
			t.Fatalf("%s/%s with no metrics sink: %v", a.Kind, a.Op, err)
		}
	}

	// The de-duplication really ran: without it the duplicate counter was never
	// reached and this test would pass on a nil-unsafe sink.
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.deleted) == 0 {
		t.Fatal("no duplicate was deleted, so the duplicate counter was never emitted")
	}
}

// mirrorSink returns the reconciler's test sink.
func mirrorSink(t *testing.T, r *Reconciler) *countingMetrics {
	t.Helper()
	m, ok := r.metrics.(*countingMetrics)
	if !ok {
		t.Fatalf("metrics sink is %T, want *countingMetrics", r.metrics)
	}
	return m
}
