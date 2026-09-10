// Fleet scenarios for the CA re-key's LEADER LEASE.
//
// The `netbox` leader_election key already has two writers — P1's orphan
// sweeper and P2's inventory mirror — under one key precisely so neither can
// act while the other believes it leads. The re-key is the third, and it was
// not under it.
//
// It has to be, because it rewrites the very objects the mirror reconciles.
// Mid-rewrite, BuildActual filters actual state on the LIVE fingerprint, so a
// not-yet-rewritten VM is invisible to it; Diff emits a create; createVM's
// search-before-create looks for the NEW identity, finds nothing, and asks
// NetBox to create a VM under a name the not-yet-rewritten object already
// holds. NetBox's cluster-scoped VM-name uniqueness refuses that, and the
// refusal fails the whole sweep. Nothing is corrupted and the next sweep
// converges once the re-key finishes — which is why this is worth closing
// rather than urgent — but a failed sweep is a false alarm an operator has to
// interpret.
//
// None of it is reachable from a single-package test: every scenario needs a
// real cluster fingerprint derived from a real replicated CA row, a real mirror
// sweep with real write batches, and — for the mid-flight one — two nodes.

package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// lapseNetBoxLease backdates the `netbox` lease row's expiry and leaves the
// HOLDER alone.
//
// It is the state a sweep that has outrun its own TTL is in, and the only state
// in which another node may take the lease at all: acquireNetBoxLease's
// conflict clause refuses to steal an unexpired lease, so a re-key on a peer
// while the row is live is a refusal, not a takeover.
func lapseNetBoxLease(t *testing.T, n *Node) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`UPDATE leader_election SET expires_at = ?, updated_at = ? WHERE key = 'netbox'`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), n.DB.NowTS()); err != nil {
		t.Fatalf("lapse netbox lease on %s: %v", n.Name, err)
	}
}

// netBoxLeaseRow reads the `netbox` lease as an operator would, so a scenario
// can assert WHO holds it and whether it is live.
func netBoxLeaseRow(t *testing.T, n *Node) (holder string, expires time.Time) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT holder, expires_at FROM leader_election WHERE key = 'netbox'`)
	if err != nil {
		t.Fatalf("read the netbox lease on %s: %v", n.Name, err)
	}
	if len(rows) == 0 {
		t.Fatalf("no netbox lease row on %s — the assertion would be vacuous", n.Name)
	}
	expires, err = time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil {
		t.Fatalf("unparseable netbox lease expiry %q on %s: %v",
			rows[0].String("expires_at"), n.Name, err)
	}
	return rows[0].String("holder"), expires
}

// ── scenarios ───────────────────────────────────────────────────────────────

// TestRekeyRefusedWithoutTheLease is the fail-closed direction, end to end: a
// re-key that cannot prove it leads the cluster rewrites NOTHING.
//
// The PATCH count is the assertion that matters. The identity rewrite is a
// PATCH per object and nothing else in this scenario issues one, so "zero
// PATCHes reached NetBox" is the only statement that covers every object the
// re-key would have touched — addresses, VMs and interfaces alike — rather than
// the handful a fingerprint census happens to enumerate.
func TestRekeyRefusedWithoutTheLease(t *testing.T) {
	nb, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	mustRevalidate(t, n)
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("precondition: a moved cluster fingerprint must suspend the binding")
	}

	// A peer holds the lease, and it has not expired: the mirror on that node
	// may be mid-sweep.
	stealNetBoxLease(t, n, "another-node")
	before := nb.PatchCount()

	err := rekey(c, n, orphanNetwork)
	if err == nil {
		t.Fatal("a re-key that does not hold the netbox leader lease must be refused — " +
			"it rewrites the objects the inventory mirror is reconciling")
	}
	if !strings.Contains(err.Error(), "another-node") {
		t.Fatalf("the refusal must name the holder so an operator knows what to wait for, got %v", err)
	}

	if got := nb.PatchCount() - before; got != 0 {
		t.Fatalf("a refused re-key issued %d PATCHes, want 0 — nothing may be rewritten "+
			"without the lease", got)
	}
	if got := netboxFingerprints(t, nb); got[oldFP] != 2 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both still under the old %q",
			got, oldFP)
	}
	if got := objectRefFingerprints(t, n); got[oldFP] != 2 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both still under the old %q",
			got, oldFP)
	}
	if holder, _ := netBoxLeaseRow(t, n); holder != "another-node" {
		t.Fatalf("the netbox lease holder = %q, want the peer's — a refused re-key must not "+
			"have taken it", holder)
	}

	// The other side: once the peer's lease has lapsed the same command goes
	// through and finishes the job. Without this the scenario would also pass
	// against a re-key that refused unconditionally.
	lapseNetBoxLease(t, n)
	mustRekey(t, c, n, orphanNetwork)
	newFP := clusterFP(t, n)
	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q",
			got, newFP)
	}
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("the completed re-key must resume the binding")
	}
}

// TestRekeyInventoryOnlyTakesTheLeaseToo is the same property on the
// CLUSTER-SCOPED, network-less form.
//
// It is a separate entry point with its own writes, and it is the ONLY re-key a
// mirror-only cluster has — exactly the cluster whose every NetBox object is
// written by the mirror this lease coordinates with. A lease taken in the
// per-network path alone would leave that cluster racing the sweep the command
// exists to keep working.
func TestRekeyInventoryOnlyTakesTheLeaseToo(t *testing.T) {
	nb, c := mirrorOnlyCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	if newFP == oldFP {
		t.Fatal("the cluster fingerprint did not move — the scenario would be vacuous")
	}
	assertNoBindings(t, n)

	stealNetBoxLease(t, n, "another-node")
	before := nb.PatchCount()

	err := rekeyInventoryOnly(c, n)
	if err == nil {
		t.Fatal("the cluster-scoped re-key must be refused without the netbox leader lease")
	}
	if !strings.Contains(err.Error(), "another-node") {
		t.Fatalf("the refusal must name the holder, got %v", err)
	}
	if got := nb.PatchCount() - before; got != 0 {
		t.Fatalf("a refused inventory re-key issued %d PATCHes, want 0", got)
	}
	if got := objectRefFingerprints(t, n); got[oldFP] != 2 || got[newFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both still under the old %q",
			got, oldFP)
	}

	// And it completes once the lease is free, leaving this node holding it.
	lapseNetBoxLease(t, n)
	mustRekeyInventoryOnly(t, c, n)
	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q",
			got, newFP)
	}
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}
	holder, expires := netBoxLeaseRow(t, n)
	if holder != n.Name || !time.Now().UTC().Before(expires) {
		t.Fatalf("the netbox lease is %q until %s, want a LIVE lease held by %s — the "+
			"cluster-scoped form must take the lease it rewrites under",
			holder, expires.Format(time.RFC3339), n.Name)
	}
}

// TestRekeyAbortsIfItLosesTheLease pins the mid-re-key half.
//
// Taking the lease once is not enough: a re-key over a large inventory is many
// seconds of writes, and a node that stopped leading partway through must STOP,
// not finish the rewrite under a lease another node is already acting on. The
// existing contract is what makes that safe — the binding stays suspended, the
// operation is re-runnable, and objects already rewritten no longer match the
// old pin — so aborting costs an operator a re-run and nothing else.
func TestRekeyAbortsIfItLosesTheLease(t *testing.T) {
	nb, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	mustRevalidate(t, n)

	// A peer takes the lease the instant the FIRST object has been rewritten.
	// The hook clears itself so the re-run below is not steered, and it returns
	// nil: the write it interrupts SUCCEEDS, which is what makes this a lost
	// lease rather than a refused PATCH (that path is already covered by
	// TestRekeyPartialFailureLeavesBindingSuspended).
	var once sync.Once
	nb.SetOnPatch(func(int) error {
		once.Do(func() {
			nb.SetOnPatch(nil)
			stealNetBoxLease(t, n, "another-node")
		})
		return nil
	})

	err := rekey(c, n, orphanNetwork)
	if err == nil {
		t.Fatal("a re-key that loses the leader lease partway must abort, not finish the " +
			"rewrite under a lease another node is acting on")
	}
	if !strings.Contains(err.Error(), "lease") {
		t.Fatalf("the error must say the lease was lost, got %v", err)
	}

	// The contract a partial re-key promises, unchanged: suspended, and every
	// object either fully old or fully new so a re-run finishes exactly what
	// this one left.
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a re-key aborted for a lost lease must leave the binding suspended")
	}
	if got := netboxFingerprints(t, nb); got[oldFP] != 2 || got[newFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both still under the "+
			"old %q — the abort landed on the address, before the inventory half", got, oldFP)
	}
	if got := objectRefFingerprints(t, n); got[oldFP] != 2 || got[newFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both still under the old %q — "+
			"a local index rewritten ahead of NetBox is a COLLISION", got, oldFP)
	}

	// Re-running with the lease back is the recovery, and it must finish the job.
	stealNetBoxLease(t, n, n.Name)
	mustRekey(t, c, n, orphanNetwork)
	if got := netboxFingerprints(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("NetBox inventory identities by fingerprint = %v, want both under the new %q",
			got, newFP)
	}
	if got := objectRefFingerprints(t, n); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("netbox_objects rows by fingerprint = %v, want both under the new %q", got, newFP)
	}
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("the completed re-run must resume the binding")
	}
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("the sweep after the completed re-key must converge, got %v", err)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("virtual_machine objects after the re-key sweep = %d, want 1", got)
	}
}

// TestRekeyStopsASweepMidFlight is the other direction: the re-key TAKES the
// lease, and the sweep that was holding it stops at its next batch boundary.
//
// That is the whole reason the re-key joins this key rather than getting one of
// its own. The mirror re-validates the lease before every write batch, so an
// outgoing writer halts by itself — no second mechanism, no signal, nothing for
// the re-key to do but take the lease.
//
// The lapse in the middle is not scaffolding around the property, it IS the
// precondition: acquireNetBoxLease refuses to steal an unexpired lease, so the
// only state in which a peer may take one from a running sweep is a sweep that
// has outrun its own TTL — which a sweep over a large cluster genuinely can.
// The assertion that the lease ends up LIVE and held by the re-key's node is
// what separates "the re-key took it" from "the TTL simply lapsed".
func TestRekeyStopsASweepMidFlight(t *testing.T) {
	nb, c := boundMirrorCluster(t, 2)
	sweeper, operator := c.Nodes[0], c.Nodes[1]

	// More VMs than one write batch holds, so the sweep has a boundary INSIDE a
	// phase to stop at. With a fixture that fits in one batch a mirror that
	// checked once per sweep and one that checks per batch look identical.
	const vms = mirrorBatchSize + 5
	for i := 0; i < vms; i++ {
		mustCreateVM(t, sweeper, vmName(i), orphanNetwork)
	}

	// The re-key lands between two write batches of a sweep already in flight —
	// a window a real lease handover can reach but a test cannot without racing.
	// The probe fires the takeover once and then hands the remaining checks back
	// to the REAL lease read, so what stops the sweep is the row, not the seam.
	var once sync.Once
	var rekeyErr error
	sweeper.Server.SetNetBoxLeaseProbe(func(context.Context) bool {
		once.Do(func() {
			sweeper.Server.SetNetBoxLeaseProbe(nil)
			lapseNetBoxLease(t, sweeper)
			rekeyErr = rekey(c, operator, orphanNetwork)
		})
		return true
	})

	err := sweeper.SyncNetBoxMirror()

	if rekeyErr != nil {
		t.Fatalf("the re-key must complete once the sweep's lease has lapsed, got %v", rekeyErr)
	}
	if err == nil {
		t.Fatal("a sweep whose lease was taken must stop and say so, not run to completion")
	}
	if !strings.Contains(err.Error(), "lease lost mid-sweep") {
		t.Fatalf("the sweep must stop on the leader lease, got %v", err)
	}

	// A GENUINE mid-sweep stop: past the first batch, short of the last. Zero
	// would mean the scenario never reached a boundary; all of them would mean
	// the sweep never checked.
	if got := nb.VMCountAll(); got == 0 || got >= vms {
		t.Fatalf("the sweep mirrored %d of %d VMs, want a stop at a batch boundary "+
			"between the two", got, vms)
	}

	holder, expires := netBoxLeaseRow(t, sweeper)
	if holder != operator.Name || !time.Now().UTC().Before(expires) {
		t.Fatalf("the netbox lease is %q until %s, want a LIVE lease held by %s — the sweep "+
			"must have stopped because the re-key TOOK the lease, not merely because the "+
			"old one expired", holder, expires.Format(time.RFC3339), operator.Name)
	}
}
