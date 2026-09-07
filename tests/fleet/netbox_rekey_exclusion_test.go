// Fleet scenarios for the re-key's INTRA-NODE exclusion, and for the one thing
// its cross-node refusal has to tell an operator.
//
// The `netbox` leader lease is the CROSS-node half and it was mistaken for the
// whole thing. It is not, in two directions:
//
//   - On a NON-leader the re-key refuses PERMANENTLY. The mirror and the orphan
//     sweeper each renew the lease on every tick with a TTL of twice the
//     interval, so it never expires while the leader is alive, and
//     acquireNetBoxLease refuses to steal an unexpired one. A message telling
//     the operator to retry describes something that cannot happen — and this is
//     the only path there is for re-stamping a moved fingerprint, so while it is
//     blocked every binding stays suspended and every create on a bound network
//     refuses.
//
//   - On the LEADER — the only node where it can succeed — the lease excludes
//     NOTHING. The re-key renews the same holder name the mirror wrote, so the
//     mirror's per-batch lease read still says "ours" and the sweep runs on. The
//     15-minute sweep tick and the 60-second queue poll can therefore both
//     overlap a re-key on the very node performing it, which is precisely the
//     half-rewritten-inventory hazard the lease was added to prevent.
//
// Both need a real cluster: a real replicated CA row to derive a fingerprint
// from, a real mirror pass with real write batches, and a real lease row.

package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestRekeyRefusalSaysWhereToRunIt.
//
// The refusal already NAMES the holder. What it said to do with that name was
// "that node may be mid-sweep — retry in a few minutes", and `docs/networking.md`
// said "wait for that node's sweep to finish and run it again". Neither ever
// works: the holder renews on every tick, so waiting on this node is waiting
// forever. The name is only useful if the message says to go and use it.
func TestRekeyRefusalSaysWhereToRunIt(t *testing.T) {
	_, c := mirroredCluster(t, "vm-1")
	n := c.Nodes[0]

	c.MoveClusterFingerprint()
	mustRevalidate(t, n)

	stealNetBoxLease(t, n, "another-node")

	err := rekey(c, n, orphanNetwork)
	if err == nil {
		t.Fatal("a re-key without the lease must be refused")
	}
	msg := err.Error()

	if !strings.Contains(msg, "another-node") {
		t.Fatalf("the refusal must name the lease holder, got %v", err)
	}
	// The actionable half. A refusal that names a node but tells the operator to
	// wait sends them nowhere: the lease does not lapse while that node is up.
	if !strings.Contains(msg, "run the re-key on") {
		t.Fatalf("the refusal must tell the operator to run the re-key on the holder, got %v", err)
	}
	for _, wrong := range []string{"retry in a few minutes", "mid-sweep"} {
		if strings.Contains(msg, wrong) {
			t.Fatalf("the refusal still advises %q, which cannot work — the holder renews "+
				"the lease on every tick: %v", wrong, err)
		}
	}
}

// TestRekeyRefusedWhileAMirrorSweepRunsOnTheSameNode is the missing INTRA-node
// half.
//
// The re-key fires from inside a write-batch boundary of a sweep in flight on
// the SAME node — the window the per-batch lease re-validation exists for, and
// the one the lease cannot close here because both writers are this node and the
// lease names the node, not the operation.
func TestRekeyRefusedWhileAMirrorSweepRunsOnTheSameNode(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	// More VMs than one write batch holds, so the sweep has a boundary INSIDE a
	// phase for the re-key to land on.
	const vms = mirrorBatchSize + 5
	for i := 0; i < vms; i++ {
		mustCreateVM(t, n, vmName(i), orphanNetwork)
	}
	c.MoveClusterFingerprint()
	mustRevalidate(t, n)

	var once sync.Once
	var rekeyErr error
	var rekeyRan bool
	var rekeyPatches int
	n.Server.SetNetBoxLeaseProbe(func(context.Context) bool {
		once.Do(func() {
			n.Server.SetNetBoxLeaseProbe(nil)
			rekeyRan = true
			// Bracketed around the nested call alone: the sweep issues PATCHes of
			// its own, so a count taken across the whole pass would say nothing
			// about what the re-key rewrote.
			before := nb.PatchCount()
			rekeyErr = rekey(c, n, orphanNetwork)
			rekeyPatches = nb.PatchCount() - before
		})
		// The lease is genuinely still this node's — nothing was stolen. That is
		// the whole point: the lease says "ours" to both writers at once.
		return true
	})

	sweepErr := n.SyncNetBoxMirror()

	if !rekeyRan {
		t.Fatal("the scenario never reached a write-batch boundary — the assertion would be vacuous")
	}
	if rekeyErr == nil {
		t.Fatal("a re-key ran to completion INSIDE a mirror sweep on the same node: the leader " +
			"lease names the node, so it cannot separate two writers that are both this node")
	}
	if !strings.Contains(rekeyErr.Error(), "already running on this node") {
		t.Fatalf("the refusal must say a NetBox pass is already in flight on this node, got %v", rekeyErr)
	}
	if rekeyPatches != 0 {
		t.Fatalf("the refused re-key issued %d identity rewrites, want 0 — a re-key that "+
			"cannot exclude the sweep must rewrite nothing", rekeyPatches)
	}
	_ = sweepErr // the sweep's own outcome is asserted by the mirror scenarios

	// The other side, so this cannot pass against a re-key that refuses
	// unconditionally: with no pass in flight the same command goes through.
	after := nb.PatchCount()
	mustRekey(t, c, n, orphanNetwork)
	if nb.PatchCount() == after {
		t.Fatal("the re-key rewrote nothing once the sweep had finished — the exclusion is " +
			"refusing more than the overlap")
	}
}

// mirrorSweepCounter records the inventory mirror's own per-pass outcome
// counter, which the sweeper fixture's sink deliberately discards.
//
// It is the observable that separates "the pass was excluded" from "the pass ran
// and could not represent what it found": a pass that runs mid-re-key sees a
// half-rewritten inventory, withholds every action for the VMs whose names it
// can no longer account for, and records a NON-CONVERGED sweep — which is the
// signal an operator alerts on, raised here by nothing but a re-key that was
// running normally.
type mirrorSweepCounter struct {
	*sweepMetrics
	mu      sync.Mutex
	results []string
}

func (m *mirrorSweepCounter) IncMirrorSweep(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, result)
}

func (m *mirrorSweepCounter) passes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.results...)
}

// TestAMirrorSweepFiredInsideARekeyIsExcluded is the same exclusion from the
// other direction, and it is the direction that produces the false alarm.
//
// A sweep that starts mid-re-key reads ACTUAL state filtered on the LIVE
// fingerprint, so every not-yet-rewritten object is invisible to it and Diff
// wants to create inventory NetBox already holds under the old identity. The
// name guard stops it from duplicating anything — but the pass still ends
// NON-CONVERGED, recording a failed sweep and telling the operator to check
// netbox.cluster_name or run the very re-key that is running. The 60-second
// queue poll makes that likely rather than rare.
func TestAMirrorSweepFiredInsideARekeyIsExcluded(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	const vms = 4
	for i := 0; i < vms; i++ {
		mustCreateVM(t, n, vmName(i), orphanNetwork)
	}
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("precondition: mirror the inventory first: %v", err)
	}
	if got := nb.VMCountAll(); got != vms {
		t.Fatalf("precondition: %d VMs mirrored, want %d", got, vms)
	}

	c.MoveClusterFingerprint()
	mustRevalidate(t, n)

	m := &mirrorSweepCounter{sweepMetrics: newSweepMetrics()}
	n.Server.SetNetBoxMetrics(m)

	// Fire the sweep from inside the re-key, a few rewrites in, so the cluster is
	// genuinely half-rewritten when the sweep looks at it.
	var patches int
	var once sync.Once
	var sweepErr error
	var sweepRan bool
	nb.SetOnPatch(func(int) error {
		patches++
		if patches < 3 {
			return nil
		}
		once.Do(func() {
			nb.SetOnPatch(nil)
			sweepRan = true
			sweepErr = n.SyncNetBoxMirror()
		})
		return nil
	})

	mustRekey(t, c, n, orphanNetwork)

	if !sweepRan {
		t.Fatal("the scenario never fired a sweep mid-re-key — the assertion would be vacuous")
	}
	if sweepErr != nil {
		t.Fatalf("the excluded sweep must decline quietly, not error: %v", sweepErr)
	}
	if got := m.passes(); len(got) != 0 {
		t.Fatalf("a mirror sweep fired inside a re-key on the same node ran anyway and recorded "+
			"%v — it observed a half-rewritten inventory and raised a sweep failure an "+
			"operator has to interpret", got)
	}
	if got := nb.VMCountAll(); got != vms {
		t.Fatalf("NetBox holds %d virtual machines, want %d", got, vms)
	}

	// The other side: once the re-key is done, a pass on the same node runs and
	// converges. Without this the scenario would pass against a mirror that never
	// swept at all.
	if err := n.SyncNetBoxMirror(); err != nil {
		t.Fatalf("a mirror pass after the re-key: %v", err)
	}
	if got := m.passes(); len(got) != 1 || got[0] != "ok" {
		t.Fatalf("mirror passes recorded = %v, want one converged pass after the re-key", got)
	}
}
