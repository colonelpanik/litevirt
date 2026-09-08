// A supported recovery path for PERMANENT host loss, and the three properties
// that keep it from being a bypass.
//
// The previous round made an unreachable participant block the membership
// closure, correctly: power-off evidence excuses a RUNTIME, never a MEMORY. The
// consequence was a dead end — after a permanent loss the closure can never
// close, so reclamation and bind/adoption stay suspended forever with no
// remedy. These scenarios are the exit, and the guards on it.
//
// WHAT A RETIREMENT IS, STATED HERE BECAUSE IT IS THE POINT OF THE FILE. It
// substitutes HUMAN-ESTABLISHED evidence for machine evidence a destroyed
// machine can no longer produce. Every other premise these proofs rest on is
// read off the cluster itself; this one is a person's assertion, and litevirt
// cannot check it. What the code CAN do is keep the assertion from excusing
// anything beyond the single premise it names, and that is what is pinned here:
//
//   - RETIRING A SOURCE DOES NOT DISCARD WHAT IT KNEW. The manifest's host
//     identities stay inputs to discovery, so a permanently lost witness that
//     was the only node able to name a third, still-running holder still causes
//     that holder to be ASKED.
//   - MEMBERSHIP ACCOUNTING IS NOT INVENTORY ACCOUNTING. A membership-only
//     retirement must not let a bind go live over the lost host's unique
//     address-bearing rows — that is the round-five collision returning through
//     the recovery path.
//   - NEITHER IS POWER-OFF EVIDENCE, and a retirement is REVALIDATED on every
//     read: a rejoin, or a re-admission under the same hostname, invalidates it.
//
// Every scenario runs a real multi-node fleet — real gRPC, real host rows with
// real per-node certificate serials, real libvirt domains through libvirtfake.
// A single-package test cannot reach any of these shapes, because each is about
// what ANOTHER node has or no longer has.

package fleet

import (
	"context"
	"net"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// retireHost records, on every node, one operator attestation about a
// permanently lost host: an immutable manifest for ONE premise plus the narrow
// grant that rests on it.
//
// It reads the lost host's incarnation from its `hosts` row rather than taking
// one as an argument, because that is what the production command does and
// because an incarnation a test invented would match nothing — which would make
// every scenario here pass for the wrong reason.
//
// Written to EVERY node's database because these rows replicate and the sweep or
// bind may run anywhere; the in-process fleet does not run the replicator's push
// loop, so a scenario that wrote to one node would be testing a partition.
func retireHost(t *testing.T, c *Cluster, lost string, premise corrosion.RetirementPremise, accounting ...string) {
	t.Helper()
	ctx := context.Background()
	inc, found, err := corrosion.HostIncarnationOf(ctx, c.Nodes[0].DB, lost)
	if err != nil || !found || inc == "" {
		t.Fatalf("read the recorded incarnation for %s: inc=%q found=%v err=%v", lost, inc, found, err)
	}
	// accounting is passed THROUGH, empty included. For the membership premise an
	// empty list is the substantive claim "it knew of no host the survivors do
	// not already know of", and every entry is read as a HOST IDENTITY — so
	// filler text here would become a phantom host nothing can dial, blocking
	// the very closure these scenarios are about.
	id := randid.New()
	for _, n := range c.Nodes {
		if err := corrosion.InsertRecoveryManifest(ctx, n.DB, corrosion.RecoveryManifest{
			ID:                 id,
			ClusterFingerprint: mustFingerprint(t, n),
			HostName:           lost,
			HostIncarnation:    inc,
			Premise:            premise,
			Accounting:         accounting,
			AttestedBy:         "operator",
			AttestedAt:         n.DB.NowWall(),
		}); err != nil {
			t.Fatalf("record a %s manifest for %s on %s: %v", premise, lost, n.Name, err)
		}
		if err := corrosion.InsertHostRetirement(ctx, n.DB, corrosion.HostRetirement{
			ClusterFingerprint: mustFingerprint(t, n),
			HostIncarnation:    inc,
			Premise:            premise,
			HostName:           lost,
			ManifestID:         id,
			AttestedBy:         "operator",
			AttestedAt:         n.DB.NowWall(),
		}); err != nil {
			t.Fatalf("record a %s retirement for %s on %s: %v", premise, lost, n.Name, err)
		}
	}
}

func mustFingerprint(t *testing.T, n *Node) string {
	t.Helper()
	fp, err := corrosion.ClusterFingerprint(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("ClusterFingerprint on %s: %v", n.Name, err)
	}
	return fp
}

// readmitUnderANewIncarnation rewrites a host's recorded certificate serial on
// every node — a machine REPLACED under the same hostname.
//
// It is what `lv host add` leaves behind for a re-admission: AdmitHost refuses to
// re-admit a name with the certificate it was removed under, so a replacement
// answering to the same name necessarily presents a different serial. That is
// the whole reason a retirement names an incarnation and not a hostname.
func readmitUnderANewIncarnation(t *testing.T, c *Cluster, host string) {
	t.Helper()
	ctx := context.Background()
	fresh := randid.New() + randid.New()
	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			`UPDATE hosts SET cert_serial = ?, updated_at = ? WHERE name = ?`,
			fresh, n.DB.NowTS(), host); err != nil {
			t.Fatalf("re-admit %s under a new incarnation on %s: %v", host, n.Name, err)
		}
	}
}

// hiddenHolderCluster is the topology all three sweep scenarios below share, and
// the one the previous round settled: a WITNESS is the only node in the
// sweeper's reach that records the holder's existence at all.
//
// The sweeper's own row for the holder is deleted and its gossip names the
// witness alone, so nothing the sweeper can read names the holder. The holder is
// running a domain with the orphan's MAC, so the address is genuinely held: any
// proof that reaches the holder stops, and any proof that never learns it exists
// frees a live guest's address.
func hiddenHolderCluster(t *testing.T) (*NetBoxFake, *Cluster, *Node, *Node, *Node) {
	t.Helper()
	nb, c := boundClusterWithOrphan(t, 3)
	sweeper, witness, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	for _, n := range c.Nodes {
		if err := n.DB.Execute(ctx,
			"UPDATE hosts SET role = 'witness' WHERE name = ?", witness.Name); err != nil {
			t.Fatal(err)
		}
	}
	holder.Virt.DefineStoppedDomain("ghost", orphanMAC)
	if err := sweeper.DB.Execute(ctx,
		"DELETE FROM hosts WHERE name = ?", holder.Name); err != nil {
		t.Fatal(err)
	}
	sweeper.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: witness.Name, Addr: net.JoinHostPort(witness.Address, "7946")}}
	})
	return nb, c, sweeper, witness, holder
}

// TestFleetRetiringTheWitnessStillDiscoversItsHiddenHolder is THE acceptance
// test for requirement 2, and it decides whether the manifest is being used as
// an INPUT to discovery or merely as an excuse.
//
// The witness is permanently gone — stopped, attested off (so it owes no runtime
// scan), and retired for the MEMBERSHIP premise, so the closure no longer waits
// for it to say what it knew. The question this pins is what becomes of what it
// KNEW: it was the only node in the sweeper's reach recording the holder's
// existence at all, and the holder is running a domain that holds the address.
//
// IT IS A DIFFERENTIAL ON THE MANIFEST'S CONTENT, which is what makes it a real
// assertion rather than a vacuous one. Both cases retire the same host for the
// same premise with the same fence evidence; the ONLY difference is whether the
// manifest names the holder:
//
//   - NAMES THE HOLDER → the holder is folded into the candidate universe, so it
//     owes an answer, cannot give one, and the address is LEFT ALONE.
//   - NAMES NOBODY → nothing in the sweeper's reach records the holder, the
//     closure completes over hosts that all truthfully answer "not me", and the
//     address a live guest holds is FREED.
//
// Asserting only the first case would pass against a build with no recovery path
// at all, because there the closure simply never closed and every address
// survived. The second case removes that reading. It is also the trust boundary
// in executable form: an operator who under-reports what the lost machine knew
// loses precisely this protection, and no amount of auditing the attestation
// recovers it — which is why the manifest's content, not the grant's existence,
// is what the safety rests on.
//
// Drop the manifest from the closure's inputs and the FIRST case frees the
// address too, which is the collision the whole recovery path is built to avoid.
func TestFleetRetiringTheWitnessStillDiscoversItsHiddenHolder(t *testing.T) {
	for _, tc := range []struct {
		name string
		// namesTheHolder is the whole difference between the two cases.
		namesTheHolder bool
		wantHeld       int
		why            string
	}{{
		name:           "the manifest names the hidden holder",
		namesTheHolder: true,
		wantHeld:       1,
		why: "retiring the witness retires the obligation to ASK IT, never the hosts it " +
			"could have told us about: the holder it alone could name is still a candidate, " +
			"still owes a runtime scan, and cannot give one — so the address stays allocated",
	}, {
		name:           "the manifest names nobody",
		namesTheHolder: false,
		wantHeld:       0,
		why: "with nothing recording the holder's existence the closure completes over hosts " +
			"that all truthfully answer 'not me' and the address is reclaimed. This case keeps " +
			"the one above honest, and it is the trust boundary itself: the attestation is " +
			"only ever as good as what the operator put in it",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c, sweeper, witness, holder := hiddenHolderCluster(t)

			witness.Stop()
			mustFenceConfirm(t, sweeper, witness.Name)
			if tc.namesTheHolder {
				retireHost(t, c, witness.Name, corrosion.PremiseMembership, holder.Name)
			} else {
				retireHost(t, c, witness.Name, corrosion.PremiseMembership)
			}

			mustSweep(t, sweeper)

			if held := len(nb.Identities()); held != tc.wantHeld {
				t.Fatalf("%s: %s — held %d address(es), want %d (released %v)",
					tc.name, tc.why, held, tc.wantHeld, nb.Released())
			}
		})
	}
}

// TestFleetRetirementNeverExcusesTheRuntimeScan is requirement 4, and the reason
// reclamation needs TWO premises rather than one.
//
// THE TOPOLOGY IS DELIBERATELY THE MINIMAL ONE, and an earlier version of this
// test got that wrong in a way worth recording. It used the hidden-holder
// cluster, where a third host also cannot be scanned; the sweep was then blocked
// by the HOLDER whatever the retired host owed, so letting a retirement excuse
// the runtime premise changed nothing and the test passed against the very
// mutation it existed to catch. Here the retired host is the ONLY thing between
// the sweep and a reclamation, so the outcome turns on its runtime premise alone.
//
// Two nodes, a genuinely reclaimable orphan, and one host permanently gone. Its
// MEMBERSHIP premise is retired, so the closure closes. What is deliberately
// absent is any power-off evidence: nothing attests that its libvirt is not
// running a domain. Knowledge retirement says what a machine KNEW; it says
// nothing about whether its workloads are STOPPED, so it still owes a runtime
// scan — and being off the network it cannot produce one.
//
// The address therefore survives. This is the same setup as the "still lost"
// case below with exactly one premise removed, and the opposite outcome: that
// case adds `lv host fence-confirm` and reclaims, this one omits it and
// withholds. Together they show that reclamation needs both premises and that
// neither alone is enough.
func TestFleetRetirementNeverExcusesTheRuntimeScan(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	sweeper, lost := c.Nodes[0], c.Nodes[1]

	lost.Stop()
	// Membership retired — and NO fence confirmation, so the runtime premise is
	// untouched.
	retireHost(t, c, lost.Name, corrosion.PremiseMembership)

	mustSweep(t, sweeper)

	if len(nb.Identities()) != 1 {
		t.Fatalf("a membership retirement excused the RUNTIME scan: the sweep reclaimed an "+
			"address with no evidence that the retired host's libvirt is stopped. Knowing "+
			"what a machine knew says nothing about whether it is running a domain. "+
			"Released %v", nb.Released())
	}
}

// TestFleetRejoinAndHostnameReuseInvalidateTheRetirement is THE acceptance test
// for requirement 6's last two clauses, and its first case is the positive
// control that keeps the other two honest.
//
// A retirement is not a fact that was established once; it is a premise that
// must still hold every time it is read. Two things end it, both detected with
// nothing written and no operator action:
//
//   - A REJOIN. The retirement asserts the machine is GONE, so a machine that is
//     answering refutes it and its live state governs — the same rule a fence
//     attestation is already subject to.
//   - A RE-ADMISSION UNDER THE SAME HOSTNAME. The grant names an INCARNATION, so
//     a replacement machine — which necessarily presents a different certificate
//     serial, because AdmitHost refuses to re-admit a name with the certificate
//     it was removed under — matches nothing. A new incarnation cannot inherit
//     its predecessor's exception.
//
// The topology is the plain one: two nodes, a genuinely reclaimable orphan, and
// one host permanently lost. With both of reclamation's premises met the sweep
// reclaims; break the retirement either way and it withholds.
func TestFleetRejoinAndHostnameReuseInvalidateTheRetirement(t *testing.T) {
	for _, tc := range []struct {
		name string
		// invalidate runs after the retirement is recorded.
		invalidate func(t *testing.T, c *Cluster, lost *Node)
		reclaims   bool
		why        string
	}{{
		name:       "still lost",
		invalidate: func(*testing.T, *Cluster, *Node) {},
		reclaims:   true,
		why: "with membership accounted for and the host attested off, both of " +
			"reclamation's premises are met and the orphan must be reclaimed — without " +
			"this case the two below would pass against a build that ignored retirements " +
			"entirely",
	}, {
		name: "rejoined",
		invalidate: func(_ *testing.T, _ *Cluster, lost *Node) {
			// Reachable again — counted toward quorum — while its daemon stays
			// down, which is what a host whose gossip crosses but whose gRPC
			// does not looks like.
			lost.Rejoin()
		},
		reclaims: false,
		why: "a host that is answering refutes the attestation that it is gone, so its " +
			"live state governs and it must be asked again",
		// DEFENCE IN DEPTH, NOT AN ISOLATING ASSERTION, and worth saying so:
		// on the SWEEP side a rejoin also invalidates the fence attestation
		// (hasFreshPowerOffProof consults reachability first), so the runtime
		// premise alone would withhold here even if the retirement were
		// wrongly honoured. Removing the retirement's own reachability check
		// therefore does NOT turn this case red. The test that isolates it is
		// TestFleetARejoinedHostMustStillCorroborateTheInventory, on the BIND
		// side, where nothing else re-reads reachability.
	}, {
		name: "re-admitted under the same hostname",
		invalidate: func(t *testing.T, c *Cluster, lost *Node) {
			readmitUnderANewIncarnation(t, c, lost.Name)
		},
		reclaims: false,
		why: "the grant names an incarnation, so a replacement machine answering to the " +
			"same hostname inherits nothing",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c := boundClusterWithOrphan(t, 2)
			sweeper, lost := c.Nodes[0], c.Nodes[1]

			lost.Stop()
			mustFenceConfirm(t, sweeper, lost.Name)
			retireHost(t, c, lost.Name, corrosion.PremiseMembership)
			tc.invalidate(t, c, lost)

			mustSweep(t, sweeper)

			switch held := len(nb.Identities()); {
			case tc.reclaims && held != 0:
				t.Fatalf("%s: %s — still held %v", tc.name, tc.why, nb.Identities())
			case !tc.reclaims && held != 1:
				t.Fatalf("%s: %s — the retirement was honoured anyway and the address was "+
					"released: %v", tc.name, tc.why, nb.Released())
			}
		})
	}
}

// TestFleetMembershipOnlyRetirementCannotBindOverItsInventory is THE acceptance
// test for requirement 3, and it is the round-five finding reached through the
// recovery path.
//
// The permanently lost host holds the ONLY replicated copy of a running guest's
// VM and NIC rows — the shape replication lag, a lost database or a row that
// never arrived leaves behind. Those rows are what tell adoption that an address
// is already taken, so a bind that goes live without them hands the incumbent's
// live address to the next guest created.
//
// TWO PHASES, and the second is what makes the first non-vacuous:
//
//  1. MEMBERSHIP RETIRED ONLY. The closure now closes — the lost host's
//     obligation to say what it knew is retired — and the bind must STILL
//     withhold, because the inventory premise is untouched: the lost host's
//     digest of the address-bearing tables is still owed and it cannot produce
//     one. Membership accounting is not inventory accounting.
//  2. INVENTORY ALSO RETIRED. The operator has now separately accounted for the
//     lost host's unique address-bearing records, and the bind goes live. This
//     phase is why phase 1 is a real assertion rather than the old dead end
//     reported under a new name.
//
// Let a membership retirement excuse the inventory comparison and phase 1 goes
// live over the held address, which is exactly the collision this branch has
// already fixed once from the other direction.
func TestFleetMembershipOnlyRetirementCannotBindOverItsInventory(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
	c := NewClusterWithNetBox(t, 2, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	binder, lost := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	// A guest holding an address, whose records live ONLY on the host that is
	// about to be lost. The binder never received them.
	mustCreateUnboundNetwork(t, c, lost, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, lost, "incumbent", adoptNetName, adoptFirstIP)

	lost.Stop()
	retireHost(t, c, lost.Name, corrosion.PremiseMembership)

	// Phase 1 — membership accounted for, inventory NOT. Either safe outcome
	// passes: a refused bind or a suspended one. What must not happen is a live
	// binding over an address a running guest holds.
	assertBindHandsOutNoHeldAddress(t, c, binder)

	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil && !b.Suspended {
		t.Fatalf("a MEMBERSHIP-only retirement let the bind go live while the lost host's "+
			"unique VM and NIC rows were still unaccounted for: its inventory digest is a "+
			"separate premise and nothing has retired it. Binding: %+v", *b)
	}

	// Phase 2 — the operator accounts for the lost host's inventory as its own
	// attestation, which is the additional premise a bind needs.
	retireHost(t, c, lost.Name, corrosion.PremiseInventory,
		"the incumbent guest's address records were re-created on a surviving host")

	if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}
	b, err = corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("with BOTH premises accounted for the bind must be able to go live, or the "+
			"recovery path is the same dead end under a new name: %q", b.SuspendReason)
	}
}

// TestFleetARejoinedHostMustStillCorroborateTheInventory is where the
// retirement's OWN reachability check is load-bearing, and it is here because
// the sweep side cannot show that.
//
// On the sweep side a rejoin invalidates the fence attestation as well — power-off
// evidence consults reachability before it consults the fencing log — so the
// runtime premise withholds regardless and a wrongly-honoured retirement is
// masked. The BIND side reads neither the fencing log nor any other live signal:
// its premises are membership accounting and inventory accounting, so the
// retirement's own revalidation is the only thing standing between a host that is
// answering again and a bind that excuses it.
//
// The scenario is an ordinary one rather than a contrivance: a host counted
// toward quorum by gossip whose gRPC cannot be dialled. Its premises must go back
// to being owed — it is demonstrably present, so its live state governs — and the
// bind must suspend rather than go live over rows only that host holds.
func TestFleetARejoinedHostMustStillCorroborateTheInventory(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
	c := NewClusterWithNetBox(t, 2, nb)
	gates := gateAll(t, c)
	latchNetBoxIPAM(t, c, gates)
	binder, lost := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	mustCreateUnboundNetwork(t, c, lost, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, lost, "incumbent", adoptNetName, adoptFirstIP)

	lost.Stop()
	// BOTH premises retired, which is what a bind needs — so without the rejoin
	// below this bind would go live (the phase-2 case above pins that).
	retireHost(t, c, lost.Name, corrosion.PremiseMembership)
	retireHost(t, c, lost.Name, corrosion.PremiseInventory,
		"the incumbent guest's address records were re-created on a surviving host")

	// …and then it is counted live again while still undialable.
	lost.Rejoin()

	assertBindHandsOutNoHeldAddress(t, c, binder)

	b, err := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil && !b.Suspended {
		t.Fatalf("a host that is responding again had its inventory premise excused anyway: "+
			"the retirement asserts the machine is GONE, so a machine the cluster counts as "+
			"live refutes it and must be asked for its digest like any other peer. "+
			"Binding: %+v", *b)
	}
}

// ── the controlled application of an attestation ────────────────────────────

// retireOverRPC drives the real `lv netbox retire-host` path: privileged gRPC,
// the durable latch, the confirmation, the identity read, the reachability
// refusal and the revalidation. Every scenario below goes through it rather than
// writing rows, because the controls are the subject.
func retireOverRPC(t *testing.T, c *Cluster, on *Node, req *pb.RetireLostHostRequest) (*pb.RetireLostHostResponse, error) {
	t.Helper()
	return c.SelfClient(on).RetireLostHost(context.Background(), req)
}

// countRetirementRows counts the retirement rows on a node, whatever premise.
// A refusal has to leave NOTHING behind, and the response alone cannot show that.
func countRetirementRows(t *testing.T, n *Node) int {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT cluster_fingerprint FROM netbox_host_retirements WHERE deleted_at IS NULL`)
	if err != nil {
		t.Fatalf("count retirement rows on %s: %v", n.Name, err)
	}
	return len(rows)
}

// TestFleetRetireLostHostRefusesAHostThatIsStillResponding is the control that
// keeps the command from becoming routine cleanup.
//
// A machine that answers can speak for itself: it will report its own membership
// and its own digests, so there is no unavailable evidence to substitute for and
// nothing to retire. Accepting one would mean an operator's assertion silently
// displacing an answer the cluster could have had for the asking — which is the
// worst possible trade, because it is the one case where the machine evidence
// was available all along.
func TestFleetRetireLostHostRefusesAHostThatIsStillResponding(t *testing.T) {
	_, c := boundCluster(t, 2)
	binder, live := c.Nodes[0], c.Nodes[1]
	live.Rejoin() // counted toward quorum, i.e. responding

	_, err := retireOverRPC(t, c, binder, &pb.RetireLostHostRequest{
		Host: live.Name, KnewNobody: true, Confirmed: true,
	})
	if err == nil {
		t.Fatal("a host that is still responding must be refused: it can answer for itself, " +
			"so there is no unavailable evidence for an attestation to stand in for")
	}
	if n := countRetirementRows(t, binder); n != 0 {
		t.Fatalf("the refusal must leave nothing behind, found %d retirement row(s)", n)
	}
}

// TestFleetRetireLostHostRevalidatesInsideTheWindow is the "revalidated
// immediately before committing, not just at request time" control, driven
// through the window itself rather than asserted from the shape of the code.
//
// Between the request-time checks and the write there is a real window — a
// database read, an audit line — and a cluster can move inside it. Both things
// that end a retirement are exercised there: the host coming back, and a
// replacement being admitted under its name. Either must abort the write, and
// abort it having recorded NOTHING, because a manifest written against an
// incarnation that has already been superseded is an attestation about a machine
// that is no longer the one answering to that name.
func TestFleetRetireLostHostRevalidatesInsideTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shift func(t *testing.T, c *Cluster, lost *Node)
		why   string
	}{{
		name:  "the host comes back inside the window",
		shift: func(_ *testing.T, _ *Cluster, lost *Node) { lost.Rejoin() },
		why:   "it can answer for itself again, so there is nothing to substitute for",
	}, {
		name: "a replacement is admitted inside the window",
		shift: func(t *testing.T, c *Cluster, lost *Node) {
			readmitUnderANewIncarnation(t, c, lost.Name)
		},
		why: "the incarnation the attestation was prepared against is no longer the machine " +
			"answering to that name, so the record would name the wrong one",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := boundCluster(t, 2)
			binder, lost := c.Nodes[0], c.Nodes[1]
			lost.Stop()

			var fired bool
			binder.Server.SetOnBeforeRetireRevalidate(func() {
				// Once: the hook fires per call, and re-shifting on a retry
				// would test the retry rather than the window.
				if fired {
					return
				}
				fired = true
				tc.shift(t, c, lost)
			})

			_, err := retireOverRPC(t, c, binder, &pb.RetireLostHostRequest{
				Host: lost.Name, KnewNobody: true, Confirmed: true,
			})
			if !fired {
				t.Fatal("the revalidation window was never reached, so this scenario proved " +
					"nothing: RetireLostHost must revalidate between its request-time checks " +
					"and its write")
			}
			if err == nil {
				t.Fatalf("%s: %s — the write went ahead on state that had already moved", tc.name, tc.why)
			}
			if n := countRetirementRows(t, binder); n != 0 {
				t.Fatalf("%s: the refusal must leave nothing behind, found %d retirement row(s)",
					tc.name, n)
			}
		})
	}
}

// TestFleetRetireLostHostRefusesWithoutTheDurableLatch is the mixed-version
// control, and it is not about correctness of the attestation at all.
//
// Both tables are new and both writes are new REPLICATED STATEMENT SHAPES. A peer
// still on the old build cannot resolve the fingerprint, so its apply fails
// closed, its whole batch rolls back and its replication watermark stalls — which
// head-of-line blocks the stream into every not-yet-rolled node. This branch has
// already shipped one Critical of exactly that kind. netbox_ipam_v1 cannot latch
// while any advertising peer is on the old build, so gating on the DURABLE form
// is what keeps these shapes off a mid-roll cluster's wire.
func TestFleetRetireLostHostRefusesWithoutTheDurableLatch(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	// Deliberately NOT latched: gateAll wires the gates, and nothing drives the
	// negotiation, so netbox_ipam_v1 is advertised and not latched.
	c := NewClusterWithNetBox(t, 2, nb)
	gateAll(t, c)
	binder, lost := c.Nodes[0], c.Nodes[1]
	lost.Stop()

	_, err := retireOverRPC(t, c, binder, &pb.RetireLostHostRequest{
		Host: lost.Name, KnewNobody: true, Confirmed: true,
	})
	if err == nil {
		t.Fatal("recording a retirement before netbox_ipam_v1 is durably latched puts a " +
			"statement shape on the wire that a not-yet-upgraded peer cannot apply, stalling " +
			"its replication watermark; it must be refused")
	}
	if !strings.Contains(err.Error(), "netbox_ipam_v1") {
		t.Fatalf("the refusal must name the latch, so an operator knows the remedy is to "+
			"finish the rollout: %v", err)
	}
	if n := countRetirementRows(t, binder); n != 0 {
		t.Fatalf("nothing may be recorded before the latch, found %d retirement row(s)", n)
	}
}

// TestFleetRetireLostHostRefusesAnUnconfirmedOrEmptyAttestation covers the two
// refusals that keep the command from being run by reflex.
//
// --confirmed is required because this is the one operation in the subsystem
// that substitutes judgement for proof. An attestation naming NEITHER premise is
// refused rather than treated as "retire everything", which is the shape a
// single "the host is gone" flag would have had.
func TestFleetRetireLostHostRefusesAnUnconfirmedOrEmptyAttestation(t *testing.T) {
	_, c := boundCluster(t, 2)
	binder, lost := c.Nodes[0], c.Nodes[1]
	lost.Stop()

	for _, tc := range []struct {
		name string
		req  *pb.RetireLostHostRequest
	}{
		{"unconfirmed", &pb.RetireLostHostRequest{Host: lost.Name, KnewNobody: true}},
		{"no premise named", &pb.RetireLostHostRequest{Host: lost.Name, Confirmed: true}},
		{"contradictory membership accounting", &pb.RetireLostHostRequest{
			Host: lost.Name, KnewNobody: true, KnewHosts: []string{"somewhere"}, Confirmed: true}},
	} {
		if _, err := retireOverRPC(t, c, binder, tc.req); err == nil {
			t.Fatalf("%s must be refused", tc.name)
		}
	}
	if n := countRetirementRows(t, binder); n != 0 {
		t.Fatalf("no refusal may record anything, found %d retirement row(s)", n)
	}
}
