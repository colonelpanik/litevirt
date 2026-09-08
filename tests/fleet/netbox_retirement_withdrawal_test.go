// WITHDRAWING A RETIREMENT, pinned at the level the behaviour actually lives:
// the REPLICATED resolution, not the local write.
//
// A retirement substitutes an operator's judgement for machine evidence a
// destroyed host can no longer produce. Without a way to take one back, a
// mistaken attestation stands indefinitely — so `lv netbox withdraw-retirement`
// exists, and these scenarios are what keep it honest.
//
// THE FOUR REPLICATED PROPERTIES, each of which a single-package test
// structurally cannot reach, because each is about a proof that fans out to
// OTHER nodes and commits on the strength of what they said:
//
//   - A DORMANT GRANT DOES NOT COME BACK once withdrawn. The resolver merely
//     SKIPS a grant while its host is reachable; nothing is written, so the
//     stored grant applies again the moment that incarnation goes unreachable
//     once more. That is a PAUSE. A withdrawal is durable, and the only way to
//     see the difference is to pause a grant, withdraw it, and un-pause it.
//   - A DELAYED OR RE-DELIVERED GRANT CANNOT RESURRECT ONE. These rows are
//     append-only precisely so a node that lost one repairs it from a peer, so
//     replay is ordinary rather than exotic.
//   - A CONCURRENT RE-ATTESTATION OUT-RUNS A WITHDRAWAL, and neither side is
//     swallowed: the later human judgement governs, the withdrawal stays
//     recorded, and the listing names the grant version holding the grant up.
//   - A WITHDRAWAL INSIDE A PROOF PASS STOPS THE RECLAMATION. The sweep takes
//     TWO samples of the closed participant set and requires them equal, so a
//     withdrawal landing in that window makes the second sample unclosed and
//     nothing is committed.
//
// Every scenario runs a real multi-node fleet — real gRPC, real host rows with
// real per-node certificate serials, real libvirt domains through libvirtfake —
// and drives the withdrawal through the real privileged RPC.

package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// withdrawalReason is the operator's account of why trust was removed. Recorded,
// never verified — exactly like the attestation it withdraws.
const withdrawalReason = "the accounting named the wrong machine"

// withdrawOverRPC drives the real `lv netbox withdraw-retirement` path on `on`:
// privileged gRPC, the durable latch, the exact-grant lookup, the attribution
// and the reason. It runs on the node whose reads the scenario then asserts
// about, because the in-process fleet does not run the replicator's push loop.
func withdrawOverRPC(t *testing.T, on *Node, lost string, incarnation string,
	premise corrosion.RetirementPremise) (*pb.WithdrawHostRetirementResponse, error) {

	t.Helper()
	return on.cluster.SelfClient(on).WithdrawHostRetirement(context.Background(),
		&pb.WithdrawHostRetirementRequest{
			Host:            lost,
			HostIncarnation: incarnation,
			Premise:         string(premise),
			Reason:          withdrawalReason,
		})
}

// mustWithdraw is withdrawOverRPC with the refusal treated as a test failure,
// and it asserts the grant actually came out withdrawn — a response reporting
// "still in force" would otherwise leave a scenario asserting nothing.
func mustWithdraw(t *testing.T, on *Node, lost, incarnation string,
	premise corrosion.RetirementPremise) *pb.WithdrawHostRetirementResponse {

	t.Helper()
	resp, err := withdrawOverRPC(t, on, lost, incarnation, premise)
	if err != nil {
		t.Fatalf("WithdrawHostRetirement(%s, %s) on %s: %v", lost, premise, on.Name, err)
	}
	if !resp.GetGrantWithdrawn() {
		t.Fatalf("the withdrawal did not take: %+v", resp)
	}
	return resp
}

// TestFleetAWithdrawnRetirementDoesNotComeBackWhenTheHostGoesUnREACHABLEAgain is
// THE acceptance test for the correction this work rests on.
//
// RECORDED IS NOT THE SAME AS INACTIVE. A grant whose host is answering is
// merely SKIPPED by the resolver — nothing is written, and nothing durable has
// happened — so if that same incarnation goes unreachable again the stored grant
// applies AGAIN. That is why a dormant grant must be withdrawable, and it is why
// withdrawal cannot be inferred from the host having answered once.
//
// THE DIFFERENTIAL IS THE WHOLE TEST. Both cases put the grant to sleep by
// letting the host answer, then take it away again. The only difference is
// whether a withdrawal was recorded in between:
//
//   - NOT WITHDRAWN → the grant wakes up, the closure closes over it, and the
//     orphan is reclaimed. This case is what makes the other one non-vacuous:
//     without it a build where withdrawal did nothing at all would still pass,
//     because the pause alone would look like it had worked.
//   - WITHDRAWN → the grant stays gone. The lost host owes its membership
//     answer again, cannot give one, the closure never closes, and the address
//     is LEFT ALONE.
func TestFleetAWithdrawnRetirementDoesNotComeBackWhenTheHostGoesUnreachableAgain(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw bool
		wantHeld int
		why      string
	}{{
		name:     "merely dormant",
		withdraw: false,
		wantHeld: 0,
		why: "the resolver only SKIPS a grant while its host answers — nothing is written " +
			"— so the stored grant applies again the moment that incarnation goes " +
			"unreachable once more, and the reclamation proceeds. This case keeps the one " +
			"below honest: a build where withdrawal did nothing would pass without it",
	}, {
		name:     "withdrawn while dormant",
		withdraw: true,
		wantHeld: 1,
		why: "a withdrawal is a recorded decision, not a re-derivation of live state, so it " +
			"does not lapse when the host next goes unreachable. The lost host owes its " +
			"membership answer again and cannot give one, so the closure stays open and the " +
			"address must be left alone",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c := boundClusterWithOrphan(t, 2)
			sweeper, lost := c.Nodes[0], c.Nodes[1]
			inc := incarnationOf(t, sweeper, lost.Name)

			lost.Stop()
			mustFenceConfirm(t, sweeper, lost.Name)
			retireHost(t, c, lost.Name, corrosion.PremiseMembership)

			// ASLEEP: the host is counted toward quorum again, so the grant is
			// skipped and supplies nothing right now.
			lost.Rejoin()
			if tc.withdraw {
				// Withdrawn in exactly the state a build that refused an
				// "already lapsed" grant would refuse — which is the state that
				// most needs it.
				mustWithdraw(t, sweeper, lost.Name, inc, corrosion.PremiseMembership)
			}
			// AWAKE AGAIN: the same machine, gone for good this time.
			lost.GoUnreachableAgain()

			mustSweep(t, sweeper)

			if held := len(nb.Identities()); held != tc.wantHeld {
				t.Fatalf("%s: %s — held %d address(es), want %d (released %v)",
					tc.name, tc.why, held, tc.wantHeld, nb.Released())
			}
		})
	}
}

// grantSnapshot is the EXACT rows one retirement left behind — same manifest
// ids, same accounting, same attribution — captured so they can be replayed.
//
// It exists because retireHost mints a fresh manifest id per call, which makes
// it a RE-ATTESTATION rather than a replay. That distinction is the whole
// property being tested: a re-attestation is new human judgement and restores
// the grant, while a replay is the same assertion arriving twice and must not.
type grantSnapshot struct {
	manifests []corrosion.RecoveryManifest
	grant     corrosion.HostRetirement
}

// snapshotGrant captures what is recorded for one (incarnation, premise) on a
// node that has it.
func snapshotGrant(t *testing.T, from *Node, incarnation string,
	premise corrosion.RetirementPremise) grantSnapshot {

	t.Helper()
	ctx := context.Background()
	fp := mustFingerprint(t, from)
	all, err := corrosion.ManifestsForIncarnation(ctx, from.DB, fp, incarnation)
	if err != nil {
		t.Fatalf("read manifests for %s on %s: %v", incarnation, from.Name, err)
	}
	var snap grantSnapshot
	for _, m := range all {
		if m.Premise == premise {
			snap.manifests = append(snap.manifests, m)
		}
	}
	grants, err := corrosion.ListHostRetirements(ctx, from.DB, fp, premise)
	if err != nil {
		t.Fatalf("read %s grants on %s: %v", premise, from.Name, err)
	}
	g, ok := grants[incarnation]
	if !ok || len(snap.manifests) == 0 {
		t.Fatalf("nothing recorded for incarnation %s premise %s on %s, so there is nothing "+
			"to replay", incarnation, premise, from.Name)
	}
	snap.grant = g
	return snap
}

// replayGrant re-inserts a snapshot on every node. Both writers are
// INSERT OR IGNORE against append-only tables, so this is precisely what an
// arriving duplicate does — and what anti-entropy does for a row a node lost.
func replayGrant(t *testing.T, c *Cluster, snap grantSnapshot) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		for _, m := range snap.manifests {
			if err := corrosion.InsertRecoveryManifest(ctx, n.DB, m); err != nil {
				t.Fatalf("replay manifest %s on %s: %v", m.ID, n.Name, err)
			}
		}
		if err := corrosion.InsertHostRetirement(ctx, n.DB, snap.grant); err != nil {
			t.Fatalf("replay grant on %s: %v", n.Name, err)
		}
	}
}

// TestFleetADelayedGrantReplayCannotResurrectAWithdrawnRetirement is the
// "cannot be undone by replay" requirement, driven through the shapes
// replication actually produces.
//
// Both recovery tables are append-only precisely so a node that lost a row
// repairs it from a peer with no merge rule, which makes replay ORDINARY: the
// original manifest and grant can arrive after the withdrawal, or arrive again.
// Neither may put the premise back.
//
// The mechanism is that the discriminator is an IDENTITY, never a clock. A
// replayed manifest carries the id it always had, so the withdrawal that named
// that id still covers it. Nothing compares timestamps, so no clock skew and no
// delivery order can flip the answer — which matters here specifically, because
// a CRDT cluster offers no ordering between a withdrawal on one node and a
// repair from another.
func TestFleetADelayedGrantReplayCannotResurrectAWithdrawnRetirement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		replay func(t *testing.T, c *Cluster, sweeper, lost *Node, snap grantSnapshot)
	}{{
		name: "the grant is re-delivered after the withdrawal",
		replay: func(t *testing.T, c *Cluster, _, _ *Node, snap grantSnapshot) {
			// The same rows, byte for byte: a re-delivered copy is the same
			// assertion, not a new one.
			replayGrant(t, c, snap)
		},
	}, {
		name: "the rows were lost locally and repaired from a peer",
		replay: func(t *testing.T, c *Cluster, sweeper, lost *Node, snap grantSnapshot) {
			ctx := context.Background()
			for _, table := range []string{
				"netbox_host_retirements", "netbox_recovery_manifests",
			} {
				if err := sweeper.DB.Execute(ctx,
					`DELETE FROM `+table+` WHERE host_name = ?`, lost.Name); err != nil {
					t.Fatalf("drop %s on %s: %v", table, sweeper.Name, err)
				}
			}
			// …and anti-entropy brings them back from a peer that still has
			// them. The withdrawal row is deliberately NOT deleted: that
			// asymmetry is the property. A grant repairs itself, and it must
			// repair into a state that is still withdrawn.
			replayGrant(t, c, snap)
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c := boundClusterWithOrphan(t, 2)
			sweeper, lost := c.Nodes[0], c.Nodes[1]
			inc := incarnationOf(t, sweeper, lost.Name)

			lost.Stop()
			mustFenceConfirm(t, sweeper, lost.Name)
			retireHost(t, c, lost.Name, corrosion.PremiseMembership)
			// Captured BEFORE the withdrawal: this is the batch in flight.
			snap := snapshotGrant(t, sweeper, inc, corrosion.PremiseMembership)
			mustWithdraw(t, sweeper, lost.Name, inc, corrosion.PremiseMembership)

			tc.replay(t, c, sweeper, lost, snap)

			mustSweep(t, sweeper)

			if held := len(nb.Identities()); held != 1 {
				t.Fatalf("%s resurrected a withdrawn grant: the closure closed again and a "+
					"live guest's address was released (%v). A replayed grant carries the "+
					"same manifest id the withdrawal named, so it stays withdrawn",
					tc.name, nb.Released())
			}
		})
	}
}

// TestFleetAConcurrentReAttestationOutrunsAWithdrawalAndNeitherIsSwallowed is
// the race the requirement calls out, and it is the reason the grant VERSION had
// to become recordable as part of this work.
//
// THE PRIMARY-KEY PROBLEM, AND HOW IT IS RESOLVED. netbox_host_retirements is
// keyed (cluster_fingerprint, host_incarnation, premise) with no version, and its
// writer is INSERT OR IGNORE — so re-attesting with a corrected manifest was a
// silent no-op on the GRANT row, and "a withdrawal must not cancel a newer
// attestation" could not even be stated. The version now lives in the manifest
// trail, which is append-only and which the read side already unioned: each
// attestation mints a fresh manifest id, and a withdrawal names the exact
// versions it covers.
//
// THE OUTCOME, AND WHY IT IS THE DEFENSIBLE ONE. The later human judgement
// governs: an operator who re-attested after the withdrawal was aimed has
// supplied fresh evidence, and a withdrawal that could silence every future
// attestation about a machine would be a worse tool than none. And the loser is
// not swallowed — the withdrawal stays recorded, the listing shows it, and the
// grant version holding the grant up is named, so the operator can withdraw
// again and does.
func TestFleetAConcurrentReAttestationOutrunsAWithdrawalAndNeitherIsSwallowed(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	sweeper, lost := c.Nodes[0], c.Nodes[1]
	inc := incarnationOf(t, sweeper, lost.Name)
	ctx := context.Background()

	lost.Stop()
	mustFenceConfirm(t, sweeper, lost.Name)
	retireHost(t, c, lost.Name, corrosion.PremiseMembership)
	withdrawn := mustWithdraw(t, sweeper, lost.Name, inc, corrosion.PremiseMembership)

	// THE RACE: a fresh attestation, through the real retire path, recorded
	// after the withdrawal was aimed. It mints a new manifest id, so no
	// withdrawal names it.
	if _, err := retireOverRPC(t, c, sweeper, &pb.RetireLostHostRequest{
		Host: lost.Name, KnewNobody: true, Confirmed: true,
	}); err != nil {
		t.Fatalf("re-attest after the withdrawal: %v", err)
	}

	// The grant is in force again, so the closure closes and the orphan is
	// reclaimed — the later judgement governs.
	mustSweep(t, sweeper)
	if held := len(nb.Identities()); held != 0 {
		t.Fatalf("a re-attestation recorded AFTER a withdrawal did not restore the grant "+
			"(still held %v). A withdrawal covers the versions it named and nothing "+
			"attested after it, or one withdrawal would silence every future attestation "+
			"about that machine and re-attesting would be impossible", nb.Identities())
	}

	// And the withdrawal was not swallowed: it is still on the record, with the
	// version that beat it named.
	list, err := sweeper.cluster.SelfClient(sweeper).ListLostHostRetirements(ctx, nil)
	if err != nil {
		t.Fatalf("ListLostHostRetirements: %v", err)
	}
	var row *pb.LostHostRetirement
	for _, r := range list.GetRetirements() {
		if r.GetPremise() == string(corrosion.PremiseMembership) &&
			r.GetHostIncarnation() == inc {
			row = r
		}
	}
	if row == nil {
		t.Fatalf("the grant is gone from the listing entirely (%d row(s))",
			len(list.GetRetirements()))
	}
	if len(row.GetWithdrawals()) == 0 {
		t.Fatalf("the withdrawal of grant version(s) %v vanished from the listing once a "+
			"later attestation out-ran it. The operator who withdrew has to be able to see "+
			"that their decision was recorded and what beat it",
			withdrawn.GetWithdrawnVersions())
	}
	if len(row.GetUnwithdrawnVersions()) == 0 {
		t.Fatal("the listing does not name the grant version keeping the grant in force. " +
			"An outcome an operator cannot account for reads as the withdrawal having been " +
			"ignored")
	}
	if row.GetAttestedBy() == "" {
		t.Fatal("the listing lost the attribution of the attestation itself: withdrawal is " +
			"an addition to the record, so both halves of the decision must stay readable")
	}

	// Withdrawing again covers the newer version too — the operator is not stuck
	// in a loop they cannot win.
	mustWithdraw(t, sweeper, lost.Name, inc, corrosion.PremiseMembership)
	// A fresh orphan, since the pass above reclaimed the first one. Same shape:
	// a real cluster identity, aged past the grace window, held by nothing.
	nb.SeedIP(orphanCIDR, orphanVRF, orphanIdentity(t, sweeper),
		time.Now().UTC().Add(-orphanAge))
	mustSweep(t, sweeper)
	if held := len(nb.Identities()); held != 1 {
		t.Fatalf("withdrawing again did not cover the version the re-attestation added, so "+
			"the grant kept applying and the address was released (%v)", nb.Released())
	}
}

// TestFleetAWithdrawalInsideTheProofWindowStopsTheReclamation is the
// "withdrawal during a proof pass" requirement, and the answer is that the pass
// MUST NOT commit — which it does not, through a control that already existed.
//
// The sweep takes TWO samples of the closed participant set, one before it
// collects the per-host proofs and one after, and refuses unless they are equal.
// That is there for a host joining mid-collection, and it is exactly the right
// mechanism here: a withdrawal landing in the window makes the SECOND closure
// unclosed, because the lost host is owed its membership answer again and cannot
// give one. The reclamation is refused before the destructive call.
//
// The hook fires between the two samples, which is the window itself — asserted
// rather than assumed, because a scenario in which it never fired would prove
// nothing.
func TestFleetAWithdrawalInsideTheProofWindowStopsTheReclamation(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	sweeper, lost := c.Nodes[0], c.Nodes[1]
	inc := incarnationOf(t, sweeper, lost.Name)

	lost.Stop()
	mustFenceConfirm(t, sweeper, lost.Name)
	retireHost(t, c, lost.Name, corrosion.PremiseMembership)

	var fired bool
	sweeper.Server.SetOnProofCollected(func() {
		// Once: the hook fires per candidate, and withdrawing twice would test
		// idempotence rather than the window.
		if fired {
			return
		}
		fired = true
		mustWithdraw(t, sweeper, lost.Name, inc, corrosion.PremiseMembership)
	})

	mustSweep(t, sweeper)

	if !fired {
		t.Fatal("the proof window was never reached, so this scenario proved nothing: the " +
			"sweep must take a second sample of the participant set after collecting the " +
			"proofs")
	}
	if held := len(nb.Identities()); held != 1 {
		t.Fatalf("a withdrawal that landed INSIDE the proof window did not stop the "+
			"reclamation: the address was released on the strength of a grant the cluster "+
			"no longer trusts (%v). The second closure sample is what must catch it",
			nb.Released())
	}
}

// TestFleetAWithdrawnManifestStillFeedsDiscovery is the requirement most easily
// got wrong, at acceptance level and ISOLATED from the grant's applicability.
//
// Withdrawing permission to trust a source does NOT establish that the hosts it
// named never existed. Those identities stay inputs to discovery, because naming
// a host can only ever cause it to be ASKED — the leak direction — and a host
// that is asked and cannot answer leaves the closure open, which withholds.
//
// THE ISOLATION IS THE DIFFICULTY. A withdrawn grant withholds on its own, so a
// scenario that simply withdrew and swept would pass whether or not the
// identities survived. So the withdrawal is followed by a RE-ATTESTATION that
// names NOBODY: the grant is in force again, on a version that mentions no
// hosts at all, and the only thing that can still name the hidden holder is the
// WITHDRAWN manifest. If withdrawal dropped its identities, nothing in the
// sweeper's reach records the holder, the closure completes over hosts that all
// truthfully answer "not me", and a live guest's address is freed — by an
// operator trying to be MORE careful.
//
// The topology is the hidden-holder one: the retired witness is the only node in
// the sweeper's reach that records the holder's existence at all, and the holder
// is running a domain with the orphan's MAC, so the address is genuinely held.
func TestFleetAWithdrawnManifestStillFeedsDiscovery(t *testing.T) {
	nb, c, sweeper, witness, _ := hiddenHolderCluster(t)
	holder := c.Nodes[2]
	inc := incarnationOf(t, sweeper, witness.Name)

	witness.Stop()
	mustFenceConfirm(t, sweeper, witness.Name)
	// The attestation that names the hidden holder.
	retireHost(t, c, witness.Name, corrosion.PremiseMembership, holder.Name)

	// Trust in it is withdrawn…
	mustWithdraw(t, sweeper, witness.Name, inc, corrosion.PremiseMembership)
	// …and then re-attested, naming nobody. The grant is in force again on a
	// version with an EMPTY accounting, so the closure can close over the
	// witness — and the holder is named only by the manifest that was withdrawn.
	if _, err := retireOverRPC(t, c, sweeper, &pb.RetireLostHostRequest{
		Host: witness.Name, KnewNobody: true, Confirmed: true,
	}); err != nil {
		t.Fatalf("re-attest naming nobody: %v", err)
	}

	mustSweep(t, sweeper)

	if held := len(nb.Identities()); held != 1 {
		t.Fatalf("a WITHDRAWN manifest's host identities were dropped from discovery, so "+
			"nothing in the sweeper's reach recorded the hidden holder and its live guest's "+
			"address was released (%v). Withdrawing permission to trust a source does not "+
			"establish that the hosts it named never existed — those identities stay "+
			"discovery inputs, exactly as they do while the grant stands, because naming a "+
			"host can only ever cause it to be ASKED", nb.Released())
	}
}

// TestFleetWithdrawingTheInventoryGrantKeepsTheBindWithholding is the same
// property on the OTHER premise and the other consumer, and it is not redundant.
//
// The sweep and the bind reach the recovery path through different resolvers:
// the closure consumes the MEMBERSHIP grant, the bind's digest comparison
// consumes the INVENTORY grant. A withdrawal honoured by one and not the other
// would leave a bind going live over rows only a permanently lost host held —
// the round-five collision, reached through the withdrawal path.
//
// It is also where the retirement's own resolution is load-bearing with nothing
// else masking it: the bind reads no fencing log and no other live signal, so
// the inventory grant is the only thing between the binder and rows it does not
// have.
//
// WHAT A WITHDRAWAL GOVERNS IS FUTURE RELIANCE, and this test is shaped by that
// rather than around it. The inventory premise is consumed ONCE, when a bind
// goes live; withdrawing afterwards cannot un-adopt an address that has already
// been handed out, and nothing here pretends it can. So the differential is over
// a bind that has NOT yet gone live, which is every bind after the withdrawal.
func TestFleetWithdrawingTheInventoryGrantKeepsTheBindWithholding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw bool
		why      string
	}{{
		name:     "the inventory grant stands",
		withdraw: false,
		why: "with both premises accounted for the bind must be able to go live, or the " +
			"case below would pass against a build where binding never worked at all",
	}, {
		name:     "trust in the inventory grant was withdrawn",
		withdraw: true,
		why: "the lost host's digest of the address-bearing tables is owed again, and it " +
			"cannot produce one — so the bind must withhold rather than go live over a " +
			"running guest's address",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nb := NewNetBoxFake()
			t.Cleanup(nb.Close)
			nb.AddPrefix(adoptPrefix, adoptSubnet, adoptVRF, true)
			c := NewClusterWithNetBox(t, 2, nb)
			gates := gateAll(t, c)
			latchNetBoxIPAM(t, c, gates)
			binder, lost := c.Nodes[0], c.Nodes[1]
			ctx := context.Background()
			inc := incarnationOf(t, binder, lost.Name)

			// A guest holding an address, whose records live ONLY on the host
			// about to be lost. The binder never received them.
			mustCreateUnboundNetwork(t, c, lost, adoptNetName, adoptSubnet)
			mustCreateVMHoldingIP(t, c, lost, "incumbent", adoptNetName, adoptFirstIP)

			lost.Stop()
			retireHost(t, c, lost.Name, corrosion.PremiseMembership)
			retireHost(t, c, lost.Name, corrosion.PremiseInventory,
				"the incumbent guest's address records were re-created on a surviving host")

			if tc.withdraw {
				// The inventory accounting turns out to be wrong. Note the
				// MEMBERSHIP grant is deliberately left standing, so the
				// closure still closes and the only thing that can stop this
				// bind is the withdrawn inventory premise.
				mustWithdraw(t, binder, lost.Name, inc, corrosion.PremiseInventory)
			}

			_, err := createBoundNetwork(c, binder, adoptNetName, adoptSubnet, adoptPrefix)
			if err != nil && !tc.withdraw {
				t.Fatalf("%s: %s — the bind was refused: %v", tc.name, tc.why, err)
			}
			if err == nil {
				if rerr := binder.Server.RevalidateBindingsOnce(ctx); rerr != nil {
					t.Fatalf("RevalidateBindingsOnce: %v", rerr)
				}
			}
			b, berr := corrosion.GetBindingByPrefix(ctx, binder.DB, adoptPrefix)
			if berr != nil {
				t.Fatal(berr)
			}
			live := b != nil && !b.Suspended
			if tc.withdraw && live {
				t.Fatalf("%s: %s — the bind went live anyway: %+v", tc.name, tc.why, *b)
			}
			if !tc.withdraw && !live {
				t.Fatalf("%s: %s — the bind did not go live: %+v", tc.name, tc.why, b)
			}
			if tc.withdraw {
				// And no allocation escapes: whatever safe shape the bind took
				// — refused or suspended — the incumbent's address stays its.
				assertBindHandsOutNoHeldAddress(t, c, binder)
			}
		})
	}
}

// TestFleetWithdrawalRefusesWithoutTheDurableLatch is the mixed-version control,
// and it is about the wire rather than about the attestation.
//
// The withdrawal table is new, so its INSERT is a new REPLICATED STATEMENT
// SHAPE. A peer still on the old build cannot resolve the fingerprint, so its
// apply fails closed, its whole batch rolls back and its replication watermark
// stalls — head-of-line blocking the stream into every not-yet-rolled node. This
// branch has already shipped one Critical of exactly that kind.
//
// The gate cannot lock an operator out of withdrawing something: recording a
// retirement required this same durable latch, and the latch is MONOTONE, so any
// grant that exists is proof the latch already formed and cannot un-form.
func TestFleetWithdrawalRefusesWithoutTheDurableLatch(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	// Deliberately NOT latched: gateAll wires the gates and nothing drives the
	// negotiation, so netbox_ipam_v1 is advertised and not latched.
	c := NewClusterWithNetBox(t, 2, nb)
	gateAll(t, c)
	binder, lost := c.Nodes[0], c.Nodes[1]
	inc := incarnationOf(t, binder, lost.Name)
	lost.Stop()

	_, err := withdrawOverRPC(t, binder, lost.Name, inc, corrosion.PremiseMembership)
	if err == nil {
		t.Fatal("recording a withdrawal before netbox_ipam_v1 is durably latched puts a " +
			"statement shape on the wire that a not-yet-upgraded peer cannot apply, " +
			"stalling its replication watermark; it must be refused")
	}
	if !strings.Contains(err.Error(), "netbox_ipam_v1") {
		t.Fatalf("the refusal must name the latch, so an operator knows the remedy is to "+
			"finish the rollout: %v", err)
	}
	rows, qerr := binder.DB.Query(context.Background(),
		`SELECT manifest_id FROM netbox_retirement_withdrawals`)
	if qerr != nil {
		t.Fatalf("count withdrawal rows: %v", qerr)
	}
	if len(rows) != 0 {
		t.Fatalf("nothing may be recorded before the latch, found %d row(s)", len(rows))
	}
}
