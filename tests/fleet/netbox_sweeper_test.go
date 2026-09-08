// Orphan-sweeper scenarios.
//
// The sweeper is the ONLY component that deletes an address from NetBox, and it
// may do so only under a STABLE, COMPLETE, WHOLE-CLUSTER negative proof. Every
// test here therefore asserts the same shape: some part of the proof is broken,
// and NOTHING is released. Leaking an address the next sweep can reclaim is
// always preferable to freeing one a live guest is using.
//
// Only TestSweeperReclaimsATrueOrphan asserts a deletion, and it is what keeps
// the rest honest: without it, a sweeper that deleted nothing ever would pass
// every other test in this file.

package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

func TestSweeperReleasesNothingWhenAHostIsUnreachable(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 3)

	c.Nodes[2].Stop() // one host unreachable

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a proof that cannot reach every host must release nothing, released %v", nb.Released())
	}
}

func TestSweeperBlockedByStoppedDefinedDomain(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[1].Virt.DefineStoppedDomain("ghost", orphanMAC)

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a stopped-but-defined domain must block reclamation, released %v", nb.Released())
	}
}

func TestSweeperBlockedByPeerOnlyRow(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	// Visible ONLY in node 1's local DB, not replicated to the leader.
	c.Nodes[1].InsertLocalNICRow(t, "vm-x", orphanMAC, orphanIP)

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a row visible only on a peer must block reclamation, released %v", nb.Released())
	}
}

func TestSweeperBlockedByMembershipChange(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[0].OnProofCollected(func() { c.AddHostRow(t, "new-host") })

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("membership changing between samples A and B must discard the proof, released %v", nb.Released())
	}
}

func TestSweeperBlockedByForceRemovedHostStillHoldingDomain(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[1].Virt.DefineStoppedDomain("ghost", orphanMAC)
	mustForceRemoveHost(t, c.Nodes[0], c.Nodes[1].Name)

	mustSweep(t, c.Nodes[0])

	// RemoveHost checks only replicated rows, --force skips even that, and it
	// never powers the machine off. Decommission proves nothing.
	//
	// The refusal arrives as "node-1 unreachable" rather than "node-1 still
	// claims it", and that is production behaviour, not a harness artefact: the
	// tombstone hides the row peer resolution reads, so the leader can no longer
	// dial the machine it must hear from. Both outcomes are the same decision —
	// the host stays in the proof set and its silence blocks. What this pins is
	// that the tombstone does NOT remove it from the set: filter the enumeration
	// on deleted_at and node-1 vanishes, every remaining host answers cleanly,
	// and the address is freed while a domain still holds its MAC.
	if len(nb.Identities()) != 1 {
		t.Fatalf("a force-removed host still holding the domain must block reclamation, released %v", nb.Released())
	}
}

func TestSweeperIgnoresFenceProofAfterRejoin(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	mustFenceConfirm(t, c.Nodes[0], c.Nodes[1].Name)
	c.Nodes[1].Rejoin()
	c.Nodes[1].Virt.DefineStoppedDomain("ghost", orphanMAC)

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a rejoined host's live state governs, not a past fence attestation, released %v", nb.Released())
	}
}

// TestSweeperStaysBlockedByAnUnreachableHostAnOperatorAttestedIsOff is the
// liveness trade this proof makes, and it is the opposite of what this test
// asserted for two rounds.
//
// `lv host fence-confirm` was offered as the escape from a permanent host loss:
// attest that the machine is off and the sweeper proceeds without it. That
// reading was refused. Confirming a machine is off proves its libvirt cannot be
// running a domain — it proves NOTHING about the hosts that machine alone knew
// existed, and nothing about the replicated rows it held. A fenced witness that
// was the only node able to name a third, still-running holder is the shape that
// settled it (netbox_witness_membership_test.go).
//
// So an unreachable host keeps the participant set unclosed however strong its
// fence record, the sweep withholds, and the address leaks until the cluster is
// whole again. `lv health` names the host it is waiting on. What the attestation
// still buys is one thing only: the host owes no runtime SCAN, which the
// package-local tests pin directly.
func TestSweeperStaysBlockedByAnUnreachableHostAnOperatorAttestedIsOff(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	// Permanently gone: off the network, and attested down ten minutes ago —
	// older than the VIP window, well inside the sweeper's own.
	c.Nodes[1].Stop()
	fenceConfirmAged(t, c.Nodes[0], c.Nodes[1].Name, 10*time.Minute)

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("an attestation that a host is off is not a statement about what that host "+
			"knew: the sweep must stay blocked, released %v", nb.Released())
	}
}

func TestSweeperBlockedByFenceLogReadFailure(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[1].Stop()
	c.Nodes[0].FailFencingLogRead(t)

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("an unreadable fencing_log must fail closed, released %v", nb.Released())
	}
}

// TestSweeperBlockedByIncompleteScan pins that a host which ANSWERED but could
// not finish looking blocks just as hard as one that never answered.
//
// An incomplete proof reports HoldsMAC=false for the simple reason that it
// never got to look — the flags only ever go true on something found. Reading
// that as absence is the single most likely way to delete a live address, and
// it is the one failure that arrives dressed as a successful RPC.
func TestSweeperBlockedByIncompleteScan(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[1].Virt.FailListDomains = func() error {
		return errors.New("libvirtd: connection reset by peer")
	}

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("an incomplete scan is a gap, not an absence, released %v", nb.Released())
	}
}

func TestSweeperAbortsWhenNetBoxObjectChanged(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	nb.SetOnBeforeDelete(func(id int) { nb.Reassign(id, "someone-else") })

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("the object must be re-read and re-matched immediately before deletion, released %v", nb.Released())
	}
}

// TestSweeperRequiresOneProofPerHost pins that an EMPTY unreachable set is not
// sufficient. A host that silently answers nothing — a fan-out bug, a response
// dropped on the floor — must block, because its silence would otherwise be
// read as "nothing here", which is exactly the absence the proof is trying to
// establish.
func TestSweeperRequiresOneProofPerHost(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	silent := c.Nodes[1].Name
	c.Nodes[0].Server.SetOnProofsGathered(func(proofs map[string]grpcapi.OrphanProof) {
		delete(proofs, silent)
	})

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a host that returned no proof must block reclamation, released %v", nb.Released())
	}
}

// TestSweeperSkipsSuspendedBinding pins that a suspended binding is out of
// scope entirely. Suspension means litevirt has stopped trusting the binding
// enough to allocate from it; enumerating it and deleting from it anyway would
// be the most destructive possible reading of "we are not sure about this
// prefix".
func TestSweeperSkipsSuspendedBinding(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	if err := corrosion.SuspendBinding(context.Background(), c.Nodes[0].DB, orphanPrefixID,
		"suspended by the test"); err != nil {
		t.Fatalf("SuspendBinding: %v", err)
	}

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("a suspended binding must not be swept, released %v", nb.Released())
	}
}

// TestSweeperStuckLeaseIsSurfacedNotDeleted covers the orphan-check queue item
// a failed compensation leaves behind: the local tombstone did not land, so a
// LIVE lease still references an address the compensating caller wanted gone.
//
// That is a stuck lease, not an orphan. Deleting the NetBox object would free an
// address litevirt still believes it holds — the worst outcome available — so
// the sweeper surfaces it for an operator and touches nothing.
func TestSweeperStuckLeaseIsSurfacedNotDeleted(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	n := c.Nodes[0]

	m := newSweepMetrics()
	n.Server.SetNetBoxMetrics(m)

	insertLiveLease(t, n, orphanNetwork, orphanIP, orphanMAC)
	if err := corrosion.EnqueueSync(context.Background(), n.DB, "orphan",
		orphanIdentity(t, n), "check"); err != nil {
		t.Fatalf("EnqueueSync: %v", err)
	}

	mustSweep(t, n)

	if len(nb.Identities()) != 1 {
		t.Fatalf("an address a live lease still references must never be deleted, released %v", nb.Released())
	}
	if m.stuck() != 1 {
		t.Fatalf("stuck-lease counter = %d, want 1 — the operator has no other signal", m.stuck())
	}
	if q := pendingQueueItems(t, n, "orphan"); q != 0 {
		t.Fatalf("%d orphan-check items left pending, want 0 — a stuck lease must not re-fire every sweep", q)
	}
}

// TestSweeperSkipsCandidateWithinGrace pins the grace window as a NECESSARY
// condition: an address young enough to belong to an in-flight create is not a
// candidate at all, whatever the proofs say.
func TestSweeperSkipsCandidateWithinGrace(t *testing.T) {
	nb, c := boundClusterWithOrphanAged(t, 2, time.Now().UTC())

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("an address inside the grace window must not be reclaimed, released %v", nb.Released())
	}
}

// TestSweeperAbortsWhenLeaseLostAfterProof pins the post-proof leader-lease
// revalidation. A proof collected while holding the lease says nothing about the
// moment of deletion: if another node took leadership in between, this node is
// no longer the single writer and must not delete.
func TestSweeperAbortsWhenLeaseLostAfterProof(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	c.Nodes[0].OnProofCollected(func() { stealNetBoxLease(t, c.Nodes[0], "another-node") })

	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 1 {
		t.Fatalf("losing the leader lease after the proof must abort the delete, released %v", nb.Released())
	}
}

func TestSweeperReclaimsATrueOrphan(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)

	// Nothing holds it anywhere, every host answers completely, membership is
	// stable, the object is unchanged.
	mustSweep(t, c.Nodes[0])

	if len(nb.Identities()) != 0 {
		t.Fatalf("a true orphan must be reclaimed, still held: %v", nb.Identities())
	}
}

// ── scenario helpers ────────────────────────────────────────────────────────

func mustForceRemoveHost(t *testing.T, n *Node, name string) {
	t.Helper()
	if _, err := n.cluster.SelfClient(n).RemoveHost(context.Background(),
		&pb.RemoveHostRequest{Name: name, Force: true}); err != nil {
		t.Fatalf("RemoveHost(%s, force) on %s: %v", name, n.Name, err)
	}
}

// fenceConfirmAged writes the fencing_log row `lv host fence-confirm` leaves
// behind, with an explicit AGE.
//
// The RPC stamps its own `now` and ignores any timestamp handed to it, so a
// scenario about an attestation that has been sitting there for a while has to
// write the row directly. Same columns and same result value the handler writes
// — only the timestamp differs.
func fenceConfirmAged(t *testing.T, n *Node, name string, age time.Duration) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES (?, ?, 'manual', 'manual-confirmed', ?, ?)`,
		"fence-confirm-"+name, name,
		time.Now().UTC().Add(-age).Format(time.RFC3339),
		"operator attestation, aged by the test"); err != nil {
		t.Fatalf("write an aged fence confirmation for %s on %s: %v", name, n.Name, err)
	}
}

func mustFenceConfirm(t *testing.T, n *Node, name string) {
	t.Helper()
	if _, err := n.cluster.SelfClient(n).FenceHost(context.Background(),
		&pb.FenceHostRequest{Name: name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
		t.Fatalf("FenceHost(%s, confirm-manual-only) on %s: %v", name, n.Name, err)
	}
}
