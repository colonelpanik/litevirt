// THE PERMANENT-LOSS LIMITATION, ASSERTED RATHER THAN MERELY DOCUMENTED.
//
// A machine that is never coming back cannot answer, and every premise in this
// subsystem is established by machine evidence. So reclamation stalls forever and
// an affected new binding stays suspended forever, and there is no operator
// remedy: no command, no flag, no record that lets somebody assert what the lost
// machine knew or what became of its rows.
//
// That is a real, deliberate boundary — docs/networking.md says so, and the
// recovery lifecycle is specified as a follow-up against a frozen contract in
// docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md. A prerelease build
// of this branch had a mechanism for it; it was removed so its authorization
// rules could be reviewed on their own terms.
//
// WHY THESE ARE DIFFERENTIALS. "Nothing was reclaimed" and "the binding is
// suspended" are the SAFE outcome and also what a build that never reclaims and
// never binds would produce. So every scenario here runs the same topology twice
// and differs in one fact — whether the third node is gone — and asserts the two
// outcomes are DIFFERENT. Without the reachable case, none of this would
// distinguish a documented boundary from a subsystem that simply does not work.
//
// Each also carries the FENCE ATTESTATION, which is the substitution operators
// reach for first: `lv host fence-confirm` proves a machine's libvirt cannot be
// running a domain, and that is all it proves. It excuses the runtime scan; it
// says nothing about the hosts that machine alone knew existed or the replicated
// rows it held, so it can never complete a membership closure or an inventory
// corroboration.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleetPermanentLossStallsReclamationAndFenceConfirmCannotHelp is acceptance
// case 3's reclamation half, and case 4's membership half, in one differential.
//
// Both runs hold exactly one genuinely reclaimable address: real cluster
// identity, no lease, no VM, no NIC row anywhere. The only difference is whether
// the third node is permanently gone — off the network and attested off ten
// minutes ago, which is as favourable as a permanent loss ever gets.
//
//   - GONE: the membership closure can never close, so the sweep withholds and
//     the address stays leaked. Repeated passes change nothing — there is no
//     convergence and no remedy.
//   - PRESENT: the same sweep reclaims. So the withholding above is the proof
//     doing its job, not the sweeper being inert.
func TestFleetPermanentLossStallsReclamationAndFenceConfirmCannotHelp(t *testing.T) {
	for _, tc := range []struct {
		name string
		lost bool
	}{
		{"a participant is permanently gone", true},
		{"every participant answers", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c := boundClusterWithOrphan(t, 3)
			sweeper, lost := c.Nodes[0], c.Nodes[2]

			if tc.lost {
				lost.Stop()
				// The strongest evidence an operator can produce about a
				// destroyed machine. It excuses the RUNTIME SCAN and nothing
				// else — in particular it does not say which hosts this machine
				// alone knew existed.
				fenceConfirmAged(t, sweeper, lost.Name, 10*time.Minute)
			}

			// Three passes, not one: a boundary that resolved itself on a later
			// pass would not be a boundary, and a pass that only withheld the
			// first time would be a race rather than a refusal.
			for i := 0; i < 3; i++ {
				mustSweep(t, sweeper)
			}

			left := len(nb.Identities())
			if tc.lost {
				if left != 1 {
					t.Fatalf("a permanently lost participant leaves the membership closure "+
						"open, so nothing may be reclaimed — and a fence attestation cannot "+
						"substitute for what that machine knew. Released %v", nb.Released())
				}
				return
			}
			if left != 0 {
				t.Fatalf("with every participant answering the address is a true orphan and "+
					"must be reclaimed; %d identities left, released %v", left, nb.Released())
			}
		})
	}
}

// TestFleetPermanentLossSuspendsANewBindingAndNothingLiftsIt is acceptance case
// 3's binding half, case 4's inventory half, and part of case 6.
//
// A bind has to corroborate its inventory against every participant, and a
// permanently lost host can never answer for its own rows. So the binding stays
// suspended, and NOTHING lifts it:
//
//   - the automatic revalidation pass cannot (the proof still does not hold);
//   - `lv netbox resume` REFUSES, because a resume re-runs the proof rather than
//     clearing a flag;
//   - the fence attestation on the lost host changes neither, because being off
//     is not a statement about the rows a machine held.
//
// THE TOPOLOGY IS BUILT SO THE LOST HOST IS THE ONLY THING WRONG, which took two
// attempts to get right. A binder with an EMPTY local inventory is suspended for
// its own reason — it cannot tell "this cluster has no VMs" from "I have not
// replicated yet" — and a scenario that stopped there passed with the lost host
// contributing nothing to the outcome. So here the whole cluster CONVERGES first,
// over the real state dump, and every node holds the incumbent's address-bearing
// rows. The reachable run then goes LIVE and adopts, which is what makes the
// three refusals above statements about the lost participant.
func TestFleetPermanentLossSuspendsANewBindingAndNothingLiftsIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		lost bool
	}{
		{"a participant is permanently gone", true},
		{"every participant answers", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			nb := NewNetBoxFake()
			t.Cleanup(nb.Close)
			nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
			c := NewClusterWithNetBox(t, 3, nb)
			gates := gateAll(t, c)
			latchNetBoxIPAM(t, c, gates)
			binder, holder, lost := c.Nodes[0], c.Nodes[1], c.Nodes[2]

			// The incumbent holds the first address the prefix will offer, so
			// there is something real for the bind to adopt and something real
			// to collide with if it goes live unproved.
			mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
			mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)
			want := vmNICIdentity(t, holder, "incumbent")

			mustCreateSuspendedBoundNetwork(t, c, binder)

			// EVERY node converges, including the one about to disappear. After
			// this the only thing that can keep the binding suspended is a
			// participant that will not answer.
			dump := pullDump(t, c, holder)
			binder.DB.MergeStateBytesLWW(dump)
			lost.DB.MergeStateBytesLWW(dump)

			if tc.lost {
				lost.Stop()
				// The strongest evidence an operator can produce about a
				// destroyed machine, and it excuses the runtime scan only.
				fenceConfirmAged(t, binder, lost.Name, 10*time.Minute)
			}

			// THE AUTOMATIC PATH. Several passes, because the self-lifting
			// suspension class exists: a boundary a later pass cleared would be
			// a latency bug rather than a limitation.
			for i := 0; i < 3; i++ {
				if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
					t.Fatalf("RevalidateBindingsOnce pass %d: %v", i, err)
				}
			}
			b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
			if err != nil || b == nil {
				t.Fatalf("binding row: %+v (err %v)", b, err)
			}

			if !tc.lost {
				if b.Suspended {
					t.Fatalf("with every participant answering and the rows converged, the "+
						"binding must go live: %q", b.SuspendReason)
				}
				if ids := nb.Identities(); len(ids) != 1 || ids[0] != want {
					t.Fatalf("a resumed bind must adopt the address the incumbent holds, got "+
						"%v want [%s]", ids, want)
				}
				return
			}

			if !b.Suspended {
				t.Fatalf("a binding that cannot corroborate its inventory against a "+
					"permanently lost participant must NOT be live: %+v", b)
			}
			// And it adopted nothing, so NetBox was never made the authority over
			// the incumbent's address.
			if ids := nb.Identities(); len(ids) != 0 {
				t.Fatalf("a suspended binding must not have claimed anything in NetBox: %v", ids)
			}

			// THE OPERATOR PATH refuses too, which is acceptance case 6 for this
			// door: the resume re-proves rather than clearing a flag, so there is
			// no way to talk a binding live over a participant that never
			// answered.
			if err := resumeBinding(c, binder, adoptNetName); err == nil {
				t.Fatal("`lv netbox resume` lifted a suspension whose inventory proof still " +
					"cannot complete; a resume must re-prove, not clear a flag")
			} else {
				t.Logf("resume refused, as it must: %v", err)
			}
			b, err = corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
			if err != nil || b == nil || !b.Suspended {
				t.Fatalf("a refused resume must leave the binding suspended: %+v (err %v)", b, err)
			}
		})
	}
}

// TestFleetAnIndependentlyAuthorizedBindingKeepsAllocatingAcrossTheRemoval is
// acceptance cases 1 and 5, and the liveness half of the prerelease boundary.
//
// Removing the prerelease trust mechanism added one startup check: a database
// that carries its schema is an unsupported upgrade and the daemon refuses to
// start on it. This is the other side of that decision — a cluster that never ran
// those commits must be COMPLETELY unaffected. So:
//
//   - the binding is live and a guest claims an address from NetBox;
//   - schema init runs again on every node, which is what a daemon restart after
//     the upgrade does;
//   - it succeeds, the binding is still live, the claim is still there, the
//     NetBox object is still there, and a second guest still gets an address.
//
// Without this, the boundary could have been implemented as "refuse always", and
// every scenario about the refusal would still have passed.
func TestFleetAnIndependentlyAuthorizedBindingKeepsAllocatingAcrossTheRemoval(t *testing.T) {
	ctx := context.Background()
	nb, c := boundCluster(t, 2)
	node := c.Nodes[0]

	first := mustCreateVMOnNetwork(t, c, node, "first-guest", orphanNetwork)
	firstIP := vmNICIP(t, node, first.GetName())
	if firstIP == "" {
		t.Fatal("a guest on a live NetBox binding must be given an address")
	}
	claimed := len(nb.Identities())
	if claimed != 1 {
		t.Fatalf("the claim must reach NetBox, got %d identities", claimed)
	}

	// THE UPGRADE. Schema init is where the prerelease boundary is checked, and
	// this database carries none of its schema — so it must find nothing and
	// proceed exactly as it always has.
	for _, n := range c.Nodes {
		if err := corrosion.InitSchema(ctx, n.DB); err != nil {
			t.Fatalf("re-init schema on %s: %v", n.Name, err)
		}
	}

	b, err := corrosion.GetBindingByPrefix(ctx, node.DB, orphanPrefixID)
	if err != nil || b == nil {
		t.Fatalf("binding row after the upgrade: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("a binding authorized by an ordinary proof must not be suspended by the "+
			"removal of a mechanism it never used: %q", b.SuspendReason)
	}
	leases, err := corrosion.ListLeasesByNetwork(ctx, node.DB, orphanNetwork)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, l := range leases {
		if l.VMName == first.GetName() && l.IP == firstIP {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("the existing claim must survive untouched, leases now %+v", leases)
	}
	if got := len(nb.Identities()); got != claimed {
		t.Fatalf("the NetBox objects behind existing claims must be untouched, %d -> %d",
			claimed, got)
	}

	// STILL ALLOCATING. A binding that survived as a row but refused new work
	// would be a silent half-outage.
	second := mustCreateVMOnNetwork(t, c, node, "second-guest", orphanNetwork)
	if ip := vmNICIP(t, node, second.GetName()); ip == "" || ip == firstIP {
		t.Fatalf("the binding must keep allocating distinct addresses after the upgrade, "+
			"got %q (first %q)", ip, firstIP)
	}
}
