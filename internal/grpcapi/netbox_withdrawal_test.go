package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// WITHDRAWING A RETIREMENT. A retirement substitutes a person's judgement for
// machine evidence, so a mistaken one must be revocable — without a way to
// withdraw it, a wrong attestation stands indefinitely.
//
// THE CORRECTION THAT SHAPES EVERY TEST HERE: RECORDED IS NOT THE SAME AS
// INACTIVE. The resolver merely SKIPS a grant while its host is reachable; it
// does not durably invalidate it, so if that incarnation becomes unreachable
// again the stored grant APPLIES AGAIN. A dormant grant is a live grant.
// Refusing to withdraw one would block withdrawal in exactly the state that most
// needs it, so there is no prerequisite here about the host being dead,
// unreachable, or currently matching.
//
// THE ASYMMETRY IS THE DESIGN. Granting trust needs evidence — an accounting, an
// exact incarnation, an unreachable host, a revalidation immediately before the
// write. Removing it needs none, because every consequence of a withdrawal is a
// WITHHELD premise: the proof goes back to being owed, which is the fail-closed
// direction.

const (
	// withdrawalReason is the operator's account of why trust was removed. It is
	// recorded and never verified — exactly like the attestation it withdraws.
	withdrawalReason = "the accounting named the wrong machine"
	// withdrawnV2 is the grant version a RE-ATTESTATION mints. A withdrawal
	// aimed at the first version must not reach it.
	withdrawnV2 = "manifest-corrected-v2"
)

// adminCtx is an authenticated admin caller, so the withdrawal is attributable.
func withdrawerCtx() context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "the-withdrawing-operator")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

// latchedServer is retireInForce plus the durable latch the write needs, so the
// RPC path is reachable. The latch is a MIXED-VERSION control and nothing to do
// with the attestation's correctness; see the ack in stmtshapecheck/newtables.go.
func latchedServer(t *testing.T, premises ...corrosion.RetirementPremise) *Server {
	t.Helper()
	s := retireInForce(t, premises...)
	s.gate = fakeServerGate{
		durablyLatchedTok: map[string]bool{capabilities.NetBoxIPAMV1: true},
	}
	// The withdrawal publishes a cluster event, like every other operator write
	// in this subsystem.
	s.events = events.NewBus()
	return s
}

// withdrawOverRPC drives the real verb.
func withdrawOverRPC(t *testing.T, s *Server, incarnation string,
	premise corrosion.RetirementPremise) (*pb.WithdrawHostRetirementResponse, error) {

	t.Helper()
	return s.WithdrawHostRetirement(withdrawerCtx(), &pb.WithdrawHostRetirementRequest{
		Host:            advisoryLostHost,
		HostIncarnation: incarnation,
		Premise:         string(premise),
		Reason:          withdrawalReason,
	})
}

// reAttest records a FRESH grant version for the same (incarnation, premise) —
// what an operator attesting again with a corrected manifest leaves behind.
//
// It exists as a helper because it is the shape the primary-key problem hid: the
// retirement row's INSERT OR IGNORE makes the GRANT row a no-op on a repeat, so
// the version has to live in the manifest trail, and this writes one there.
func reAttest(t *testing.T, s *Server, incarnation string,
	premise corrosion.RetirementPremise, id string, accounting ...string) {

	t.Helper()
	ctx := context.Background()
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	if err := corrosion.InsertRecoveryManifest(ctx, s.db, corrosion.RecoveryManifest{
		ID: id, ClusterFingerprint: fp, HostName: advisoryLostHost,
		HostIncarnation: incarnation, Premise: premise, Accounting: accounting,
		AttestedBy: "the-re-attesting-operator", AttestedAt: "2026-09-08T12:00:00Z",
	}); err != nil {
		t.Fatalf("re-attest %s: %v", premise, err)
	}
	// And the grant row, exactly as RetireLostHost writes it. It is a NO-OP
	// against the existing key, which is the point: the permission already
	// exists, and what the re-attestation actually adds is the version above.
	if err := corrosion.InsertHostRetirement(ctx, s.db, corrosion.HostRetirement{
		ClusterFingerprint: fp, HostIncarnation: incarnation, Premise: premise,
		HostName: advisoryLostHost, ManifestID: id,
		AttestedBy: "the-re-attesting-operator", AttestedAt: "2026-09-08T12:00:00Z",
	}); err != nil {
		t.Fatalf("re-attest grant %s: %v", premise, err)
	}
}

// membershipSupplied reports whether the MEMBERSHIP premise is currently being
// supplied for the lost host — the answer the closure acts on.
func membershipSupplied(t *testing.T, s *Server) bool {
	t.Helper()
	applicable, err := s.membershipRetirementsFor(context.Background(), []string{advisoryLostHost})
	if err != nil {
		t.Fatalf("membershipRetirementsFor: %v", err)
	}
	return applicable.retired(advisoryLostHost)
}

// inventorySupplied is the same question for the INVENTORY premise.
func inventorySupplied(t *testing.T, s *Server) bool {
	t.Helper()
	applicable, err := s.inventoryRetirementsFor(context.Background(), []string{advisoryLostHost})
	if err != nil {
		t.Fatalf("inventoryRetirementsFor: %v", err)
	}
	return applicable.retired(advisoryLostHost)
}

// TestWithdrawalStopsTheGrantSupplyingItsPremise is the acceptance test: after a
// withdrawal, the premise the grant was supplying is owed again.
//
// It asserts against the PREMISE RESOLVER rather than against the rows, because
// the resolver is what the closure and the bind act on. A withdrawal that wrote
// a row nothing read would pass a row-counting test and change nothing.
func TestWithdrawalStopsTheGrantSupplyingItsPremise(t *testing.T) {
	s := latchedServer(t, corrosion.PremiseMembership)

	// The positive control, so the assertion below cannot pass against a build
	// where the premise was never supplied in the first place.
	if !membershipSupplied(t, s) {
		t.Fatal("the fixture's grant is not supplying the membership premise, so nothing " +
			"below is being tested")
	}

	resp, err := withdrawOverRPC(t, s, advisoryIncarnation, corrosion.PremiseMembership)
	if err != nil {
		t.Fatalf("WithdrawHostRetirement: %v", err)
	}
	if !resp.GetGrantWithdrawn() {
		t.Fatalf("the response does not report the grant as withdrawn: %+v", resp)
	}
	if len(resp.GetWithdrawnVersions()) == 0 {
		t.Fatal("the response names no grant version, so an operator cannot see WHAT the " +
			"withdrawal reached — and a withdrawal that names no version cannot be " +
			"distinguished from a later re-attestation")
	}
	if membershipSupplied(t, s) {
		t.Fatal("the grant still supplies the membership premise after being withdrawn. " +
			"A withdrawal that does not reach the resolver is a row nothing reads")
	}
}

// TestWithdrawalHasNoPrerequisites is the requirement the correction is about.
//
// Removing trust needs no qualification; only granting it does. None of these
// states may block a withdrawal, and the DORMANT one is the case that matters
// most: a reachable host's grant is merely SKIPPED, not invalidated, so it comes
// back the moment that incarnation goes unreachable again. Refusing there would
// block withdrawal in precisely the state that most needs it.
func TestWithdrawalHasNoPrerequisites(t *testing.T) {
	for _, tc := range []struct {
		name string
		// state runs after the grant is recorded and before the withdrawal.
		state func(t *testing.T, s *Server)
		why   string
	}{{
		name:  "the grant is active",
		state: func(*testing.T, *Server) {},
		why:   "the ordinary case: a recorded grant currently supplying its premise",
	}, {
		name: "the grant is DORMANT because the host is responding",
		state: func(_ *testing.T, s *Server) {
			s.gate = fakeServerGate{
				healthy:           []string{advisoryLostHost},
				durablyLatchedTok: map[string]bool{capabilities.NetBoxIPAMV1: true},
			}
		},
		why: "the resolver skips it while the host answers but does not invalidate it, so " +
			"it applies again the moment that incarnation goes unreachable — a dormant " +
			"grant is a live grant and must be withdrawable",
	}, {
		name: "the host record is gone entirely",
		state: func(t *testing.T, s *Server) {
			if err := s.db.Execute(context.Background(),
				`DELETE FROM hosts WHERE name = ?`, advisoryLostHost); err != nil {
				t.Fatalf("delete the host row: %v", err)
			}
		},
		why: "the withdrawal targets the GRANT, which is recorded independently of any " +
			"`hosts` row; requiring one would make a grant unwithdrawable exactly when " +
			"the machine it names is most thoroughly gone",
	}, {
		name: "a different machine now answers to that name",
		state: func(t *testing.T, s *Server) {
			if err := s.db.Execute(context.Background(),
				`UPDATE hosts SET cert_serial = ?, updated_at = ? WHERE name = ?`,
				advisoryReplacement, s.db.NowTS(), advisoryLostHost); err != nil {
				t.Fatalf("re-admit under a new incarnation: %v", err)
			}
		},
		why: "the grant against the PREDECESSOR incarnation is still recorded and still " +
			"applies if that machine is ever seen again, so it must be withdrawable",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			s := latchedServer(t, corrosion.PremiseMembership)
			tc.state(t, s)

			if _, err := withdrawOverRPC(t, s, advisoryIncarnation,
				corrosion.PremiseMembership); err != nil {
				t.Fatalf("%s: %s — withdrawal was refused: %v", tc.name, tc.why, err)
			}
			// And it took effect: the grant no longer supplies the premise in
			// the state where it otherwise would.
			s.gate = fakeServerGate{
				durablyLatchedTok: map[string]bool{capabilities.NetBoxIPAMV1: true},
			}
			seedIfAbsent(t, s)
			if membershipSupplied(t, s) {
				t.Fatalf("%s: the withdrawal was accepted but the grant still supplies its "+
					"premise", tc.name)
			}
		})
	}
}

// seedIfAbsent restores the lost host's row with its ORIGINAL incarnation, so
// the "did the withdrawal take effect" check runs in the state where an
// unwithdrawn grant WOULD apply. Without it the deleted-row and replaced-
// incarnation cases would pass for the wrong reason — the grant would fail to
// apply because there is no incarnation to match, not because it was withdrawn.
func seedIfAbsent(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	if err := s.db.Execute(ctx, `DELETE FROM hosts WHERE name = ?`, advisoryLostHost); err != nil {
		t.Fatalf("clear the host row: %v", err)
	}
	seedLostHostRow(t, s, advisoryLostHost, advisoryIncarnation)
}

// TestWithdrawalTargetsTheExactGrantAndNotTheHostname is the targeting
// requirement, and its second case is what a hostname-aimed withdrawal would
// silently get wrong.
//
// A withdrawal names cluster, incarnation, premise and grant version. The
// hostname is a label: it is reusable, so aiming by it would land on whichever
// grant that name currently carries rather than on the one the operator meant —
// leaving the mistaken grant standing while revoking a different machine's.
func TestWithdrawalTargetsTheExactGrantAndNotTheHostname(t *testing.T) {
	t.Run("an incarnation with no recorded grant is refused", func(t *testing.T) {
		s := latchedServer(t, corrosion.PremiseMembership)
		_, err := withdrawOverRPC(t, s, advisoryReplacement, corrosion.PremiseMembership)
		if err == nil {
			t.Fatal("a withdrawal naming an incarnation with no recorded grant must be " +
				"refused: silently succeeding would tell an operator they had revoked " +
				"something while the grant they meant stood untouched")
		}
		if !strings.Contains(err.Error(), advisoryIncarnation) {
			t.Fatalf("the refusal must name the incarnation(s) that ARE recorded, so the "+
				"operator can aim again: %v", err)
		}
		if !membershipSupplied(t, s) {
			t.Fatal("a refused withdrawal revoked the grant anyway")
		}
	})

	t.Run("no incarnation at all is refused", func(t *testing.T) {
		s := latchedServer(t, corrosion.PremiseMembership)
		_, err := s.WithdrawHostRetirement(withdrawerCtx(), &pb.WithdrawHostRetirementRequest{
			Host:    advisoryLostHost,
			Premise: string(corrosion.PremiseMembership),
			Reason:  withdrawalReason,
		})
		if err == nil {
			t.Fatal("a withdrawal must name an incarnation. A hostname cannot identify a " +
				"grant, because a hostname is meant to be reused")
		}
	})

	t.Run("withdrawing one premise leaves the other alone", func(t *testing.T) {
		s := latchedServer(t, corrosion.PremiseMembership, corrosion.PremiseInventory)
		if !membershipSupplied(t, s) || !inventorySupplied(t, s) {
			t.Fatal("both premises must be supplied first, or the assertion below is vacuous")
		}
		if _, err := withdrawOverRPC(t, s, advisoryIncarnation,
			corrosion.PremiseMembership); err != nil {
			t.Fatalf("WithdrawHostRetirement(membership): %v", err)
		}
		if membershipSupplied(t, s) {
			t.Fatal("the membership premise is still supplied after being withdrawn")
		}
		if !inventorySupplied(t, s) {
			t.Fatal("withdrawing the MEMBERSHIP grant also withdrew the INVENTORY grant. " +
				"They are separate permissions attested separately, and collapsing them " +
				"here is the same conflation the two premises exist to prevent")
		}
	})
}

// TestWithdrawalCannotCancelANewerAttestation is the requirement that the
// primary-key problem made inexpressible, and the reason the grant version had
// to become recordable as part of this work.
//
// netbox_host_retirements is keyed (cluster_fingerprint, host_incarnation,
// premise) with no version, and its writer is INSERT OR IGNORE — so re-attesting
// with a corrected manifest was a silent no-op on the GRANT row and there was no
// "newer attestation" to protect. The version now lives in the manifest trail,
// which is append-only and already unioned by the read side: each attestation
// mints a fresh manifest id, and a withdrawal names the exact versions it covers.
//
// So a withdrawal reaches v1 and cannot reach v2. The operator who re-attested
// after the withdrawal is the later human judgement, and it governs.
func TestWithdrawalCannotCancelANewerAttestation(t *testing.T) {
	s := latchedServer(t, corrosion.PremiseMembership)

	resp, err := withdrawOverRPC(t, s, advisoryIncarnation, corrosion.PremiseMembership)
	if err != nil {
		t.Fatalf("WithdrawHostRetirement: %v", err)
	}
	if membershipSupplied(t, s) {
		t.Fatal("the withdrawal did not take effect, so the re-attestation below proves nothing")
	}
	withdrew := resp.GetWithdrawnVersions()

	// A CORRECTED ATTESTATION, recorded after the withdrawal.
	reAttest(t, s, advisoryIncarnation, corrosion.PremiseMembership, withdrawnV2)

	if !membershipSupplied(t, s) {
		t.Fatalf("a withdrawal aimed at grant version(s) %v cancelled a LATER attestation "+
			"(%s) as well. A withdrawal covers the versions it named and nothing attested "+
			"after it — otherwise one withdrawal would silence every future attestation "+
			"about that machine", withdrew, withdrawnV2)
	}

	// And the earlier withdrawal was NOT swallowed: it is still recorded, and the
	// surface says which version the grant is now resting on.
	rows := listRetirements(t, s)
	row := findRetirement(t, rows, corrosion.PremiseMembership)
	if len(row.GetWithdrawals()) == 0 {
		t.Fatal("the withdrawal vanished from the listing once a later attestation out-ran " +
			"it. The operator who withdrew must be able to see that their decision was " +
			"recorded and what beat it")
	}
	if !containsName(row.GetUnwithdrawnVersions(), withdrawnV2) {
		t.Fatalf("the listing does not name the grant version keeping the grant in force "+
			"(want %s, got %v). An outcome an operator cannot account for reads as the "+
			"withdrawal having been ignored", withdrawnV2, row.GetUnwithdrawnVersions())
	}

	// Withdrawing again covers the newer version too — the operator is not stuck.
	again, err := withdrawOverRPC(t, s, advisoryIncarnation, corrosion.PremiseMembership)
	if err != nil {
		t.Fatalf("second WithdrawHostRetirement: %v", err)
	}
	if !again.GetGrantWithdrawn() || membershipSupplied(t, s) {
		t.Fatalf("withdrawing again did not cover the newer grant version: %+v", again)
	}
}

// TestWithdrawalSurvivesAReplayedGrant is the "cannot be undone by replay"
// requirement.
//
// These rows replicate, and both tables are append-only precisely so a node that
// lost one repairs it from a peer. That makes REPLAY ordinary rather than
// exotic: the original manifest and grant can arrive, or arrive again, after the
// withdrawal. They must not resurrect anything.
//
// The mechanism is that the discriminator is an IDENTITY, never a clock: a
// replayed manifest carries the id it always had, so the withdrawal that named
// that id still covers it. Nothing here compares timestamps, so no clock skew
// and no delivery order can flip the answer.
func TestWithdrawalSurvivesAReplayedGrant(t *testing.T) {
	s := latchedServer(t, corrosion.PremiseMembership)
	ctx := context.Background()
	if _, err := withdrawOverRPC(t, s, advisoryIncarnation,
		corrosion.PremiseMembership); err != nil {
		t.Fatalf("WithdrawHostRetirement: %v", err)
	}

	for _, tc := range []struct {
		name   string
		replay func(t *testing.T, s *Server)
	}{{
		name: "the original manifest and grant are re-delivered",
		replay: func(t *testing.T, s *Server) {
			// The same ids, which is what a re-delivered copy carries.
			recordRetirement(t, s, advisoryLostHost, advisoryIncarnation,
				corrosion.PremiseMembership)
		},
	}, {
		name: "the rows were lost locally and repaired from a peer",
		replay: func(t *testing.T, s *Server) {
			if err := s.db.Execute(ctx,
				`DELETE FROM netbox_host_retirements WHERE host_incarnation = ?`,
				advisoryIncarnation); err != nil {
				t.Fatalf("drop the grant row: %v", err)
			}
			if err := s.db.Execute(ctx,
				`DELETE FROM netbox_recovery_manifests WHERE host_incarnation = ?`,
				advisoryIncarnation); err != nil {
				t.Fatalf("drop the manifest row: %v", err)
			}
			recordRetirement(t, s, advisoryLostHost, advisoryIncarnation,
				corrosion.PremiseMembership)
		},
	}, {
		name: "the withdrawal row itself is tombstoned",
		replay: func(t *testing.T, s *Server) {
			// A tombstone must not RESTORE trust. Restoring it takes a fresh
			// attestation by a named person, not the disappearance of a row.
			if err := s.db.Execute(ctx,
				`UPDATE netbox_retirement_withdrawals SET deleted_at = ?, updated_at = ?
				   WHERE host_incarnation = ?`,
				"2026-09-08T13:00:00Z", s.db.NowTS(), advisoryIncarnation); err != nil {
				t.Fatalf("tombstone the withdrawal: %v", err)
			}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			tc.replay(t, s)
			if membershipSupplied(t, s) {
				t.Fatalf("%s resurrected a withdrawn grant. A withdrawal is durable: a "+
					"delayed or re-delivered copy of the old grant carries the same "+
					"manifest id the withdrawal named, and a deleted withdrawal row must "+
					"not put trust back", tc.name)
			}
		})
	}
}

// TestWithdrawalIsIdempotent — repeating it succeeds and reports that nothing
// new was recorded, rather than erroring. An operator who is unsure whether the
// first attempt landed must be able to run it again.
func TestWithdrawalIsIdempotent(t *testing.T) {
	s := latchedServer(t, corrosion.PremiseMembership)
	first, err := withdrawOverRPC(t, s, advisoryIncarnation, corrosion.PremiseMembership)
	if err != nil {
		t.Fatalf("first withdrawal: %v", err)
	}
	if first.GetNewlyRecorded() == 0 {
		t.Fatal("the first withdrawal recorded nothing")
	}
	second, err := withdrawOverRPC(t, s, advisoryIncarnation, corrosion.PremiseMembership)
	if err != nil {
		t.Fatalf("repeating a withdrawal must succeed, not error: %v", err)
	}
	if second.GetNewlyRecorded() != 0 {
		t.Fatalf("a repeat recorded %d new withdrawal(s); it is the same assertion about "+
			"the same grant version and must add nothing", second.GetNewlyRecorded())
	}
	if !second.GetGrantWithdrawn() || membershipSupplied(t, s) {
		t.Fatal("the grant came back after a repeated withdrawal")
	}
}

// TestWithdrawalPreservesTheOriginalAssertion — withdrawal is an ADDITION to the
// record, never an edit of it.
//
// The attestation is the only thing that makes a wrong retirement traceable to
// whoever made it. If withdrawal rewrote or deleted it, the trail would show
// only that somebody had cleaned up, and the review that is the sole defence
// against a bad attestation would have nothing to read.
func TestWithdrawalPreservesTheOriginalAssertion(t *testing.T) {
	s := latchedServer(t, corrosion.PremiseMembership)
	ctx := context.Background()
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	before, err := corrosion.ManifestsForIncarnation(ctx, s.db, fp, advisoryIncarnation)
	if err != nil || len(before) == 0 {
		t.Fatalf("manifests before: %+v (err %v)", before, err)
	}

	if _, err := withdrawOverRPC(t, s, advisoryIncarnation,
		corrosion.PremiseMembership); err != nil {
		t.Fatalf("WithdrawHostRetirement: %v", err)
	}

	after, err := corrosion.ManifestsForIncarnation(ctx, s.db, fp, advisoryIncarnation)
	if err != nil {
		t.Fatalf("manifests after: %v", err)
	}
	if len(after) != len(before) || after[0].AttestedBy != before[0].AttestedBy ||
		after[0].AttestedAt != before[0].AttestedAt {
		t.Fatalf("the withdrawal changed the original attestation (%+v -> %+v). Who "+
			"attested, when and why must survive untouched: they are what makes a wrong "+
			"attestation traceable", before, after)
	}
	// The grant row survives too — the listing must still be able to show it.
	grants, err := corrosion.ListHostRetirements(ctx, s.db, fp, corrosion.PremiseMembership)
	if err != nil {
		t.Fatalf("ListHostRetirements: %v", err)
	}
	if _, ok := grants[advisoryIncarnation]; !ok {
		t.Fatal("the withdrawal DELETED the grant row. Withdrawal removes trust in it; it " +
			"does not erase the fact that it was recorded")
	}

	// And the withdrawal itself is recorded beside it, with its own attribution.
	row := findRetirement(t, listRetirements(t, s), corrosion.PremiseMembership)
	if !row.GetWithdrawn() {
		t.Fatal("the listing does not report the grant as withdrawn")
	}
	w := row.GetWithdrawals()
	if len(w) != 1 {
		t.Fatalf("want exactly one withdrawal record, got %d", len(w))
	}
	if w[0].GetWithdrawnBy() == "" || w[0].GetWithdrawnAt() == "" ||
		w[0].GetReason() != withdrawalReason || w[0].GetGrantVersion() == "" {
		t.Fatalf("the withdrawal record is missing who, when, why or which version: %+v", w[0])
	}
	if row.GetAttestedBy() != before[0].AttestedBy {
		t.Fatalf("the listing no longer shows who attested the grant (%q): both halves of "+
			"the decision have to be readable side by side", before[0].AttestedBy)
	}
}

// TestWithdrawalRetainsTheDiscoveredManifestIdentities is the requirement most
// easily got wrong, and it is the same rule that governs retirement itself, in
// the other direction.
//
// Withdrawing permission to trust a source does NOT establish that the hosts it
// named never existed. Those identities stay inputs to discovery, because naming
// a host can only ever cause it to be ASKED — the leak direction — and a host
// that is asked and cannot answer leaves the closure open, which withholds.
//
// Drop them on withdrawal and the decisive case breaks: a permanently lost
// witness that was the only node able to name a third, still-running holder.
// After the withdrawal nothing would record the holder's existence, the closure
// would complete over hosts that all truthfully answer "not me", and a live
// guest's address would be freed — by an operator trying to be MORE careful.
func TestWithdrawalRetainsTheDiscoveredManifestIdentities(t *testing.T) {
	const hiddenHolder = "the-host-only-the-lost-one-knew"
	s := newAttestationServer(t)
	s.gate = fakeServerGate{
		durablyLatchedTok: map[string]bool{capabilities.NetBoxIPAMV1: true},
	}
	s.events = events.NewBus()
	seedLostHostRow(t, s, advisoryLostHost, advisoryIncarnation)
	recordRetirement(t, s, advisoryLostHost, advisoryIncarnation,
		corrosion.PremiseMembership, hiddenHolder)
	ctx := context.Background()

	if got, err := s.recoveredMembershipCandidates(ctx); err != nil ||
		!containsName(got, hiddenHolder) {
		t.Fatalf("the fixture's manifest identity is not reaching discovery (%v, err %v), "+
			"so the assertion below is vacuous", got, err)
	}

	if _, err := withdrawOverRPC(t, s, advisoryIncarnation,
		corrosion.PremiseMembership); err != nil {
		t.Fatalf("WithdrawHostRetirement: %v", err)
	}

	got, err := s.recoveredMembershipCandidates(ctx)
	if err != nil {
		t.Fatalf("recoveredMembershipCandidates: %v", err)
	}
	if !containsName(got, hiddenHolder) {
		t.Fatalf("withdrawing the grant dropped %q from discovery (%v). Withdrawing "+
			"permission to trust a source does not establish that the hosts it named never "+
			"existed — those identities stay discovery inputs, exactly as they do while the "+
			"grant stands. Dropping them means a still-running holder goes unqueried and "+
			"its live address can be reclaimed", hiddenHolder, got)
	}
	// And the premise itself IS withdrawn — otherwise this test would pass
	// against a build where the withdrawal did nothing at all.
	if membershipSupplied(t, s) {
		t.Fatal("the grant still supplies its premise, so retaining the identities proves " +
			"nothing about withdrawal")
	}
}

// TestWithdrawalRefusesWithoutTheDurableLatch is the mixed-version control, and
// it is not about the attestation at all.
//
// The withdrawal table is new, so its INSERT is a new REPLICATED STATEMENT
// SHAPE. A peer still on the old build cannot resolve the fingerprint, so its
// apply fails closed, its batch rolls back and its replication watermark stalls
// — head-of-line blocking the stream into every not-yet-rolled node. This branch
// has already shipped one Critical of exactly that kind.
//
// The gate cannot lock an operator out of withdrawing something: recording a
// retirement required the same durable latch, and the latch is MONOTONE, so any
// grant that exists is proof the latch already formed and cannot un-form.
func TestWithdrawalRefusesWithoutTheDurableLatch(t *testing.T) {
	s := retireInForce(t, corrosion.PremiseMembership)
	s.gate = fakeServerGate{} // advertised, not latched

	_, err := withdrawOverRPC(t, s, advisoryIncarnation, corrosion.PremiseMembership)
	if err == nil {
		t.Fatal("recording a withdrawal before netbox_ipam_v1 is durably latched puts a " +
			"statement shape on the wire that a not-yet-upgraded peer cannot apply, " +
			"stalling its replication watermark; it must be refused")
	}
	if !strings.Contains(err.Error(), capabilities.NetBoxIPAMV1) {
		t.Fatalf("the refusal must name the latch so the remedy is obvious: %v", err)
	}
	rows, qerr := s.db.Query(context.Background(),
		`SELECT manifest_id FROM netbox_retirement_withdrawals`)
	if qerr != nil {
		t.Fatalf("count withdrawal rows: %v", qerr)
	}
	if len(rows) != 0 {
		t.Fatalf("nothing may be recorded before the latch, found %d row(s)", len(rows))
	}
}

// TestWithdrawalRefusesAnUnattributableOrUnexplainedRequest — the record is the
// point of the operation, so both halves of it are required.
//
// Neither refusal is a prerequisite about the HOST, which is what the "no
// prerequisites" requirement is about. They are about the row this writes: a
// withdrawal nobody stands behind, or one with no stated reason, leaves the
// trail saying only that somebody removed trust at some point.
func TestWithdrawalRefusesAnUnattributableOrUnexplainedRequest(t *testing.T) {
	t.Run("no reason", func(t *testing.T) {
		s := latchedServer(t, corrosion.PremiseMembership)
		_, err := s.WithdrawHostRetirement(withdrawerCtx(), &pb.WithdrawHostRetirementRequest{
			Host: advisoryLostHost, HostIncarnation: advisoryIncarnation,
			Premise: string(corrosion.PremiseMembership),
		})
		if err == nil {
			t.Fatal("a withdrawal must record why trust was removed: the original " +
				"attestation records who asserted what and why, and this is the other half")
		}
	})
	t.Run("not an admin", func(t *testing.T) {
		s := latchedServer(t, corrosion.PremiseMembership)
		ctx := context.WithValue(context.Background(), ctxKeyUsername, "a-viewer")
		ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
		_, err := s.WithdrawHostRetirement(ctx, &pb.WithdrawHostRetirementRequest{
			Host: advisoryLostHost, HostIncarnation: advisoryIncarnation,
			Premise: string(corrosion.PremiseMembership), Reason: withdrawalReason,
		})
		if err == nil {
			t.Fatal("withdrawal changes what the cluster's proofs rest on and must be " +
				"privileged, like every other host-level write")
		}
	})
	t.Run("an unknown premise", func(t *testing.T) {
		s := latchedServer(t, corrosion.PremiseMembership)
		_, err := s.WithdrawHostRetirement(withdrawerCtx(), &pb.WithdrawHostRetirementRequest{
			Host: advisoryLostHost, HostIncarnation: advisoryIncarnation,
			Premise: "runtime", Reason: withdrawalReason,
		})
		if err == nil {
			t.Fatal("only the two retirable premises can be withdrawn; a premise no reader " +
				"recognises would write a row nothing will ever read")
		}
	})
}

// TestWithdrawnGrantLeavesTheStandingAdvisory — the advisory shows grants that
// are IN FORCE, so a withdrawn one must stop appearing. Showing it would invite
// an operator to reason about an exception that is not there.
func TestWithdrawnGrantLeavesTheStandingAdvisory(t *testing.T) {
	s := latchedServer(t, corrosion.PremiseMembership)
	ctx := context.Background()

	s.evaluateAttestedPremises(ctx)
	if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); !ok {
		t.Fatal("the advisory was not raised — the fixture is wrong")
	}

	if _, err := withdrawOverRPC(t, s, advisoryIncarnation,
		corrosion.PremiseMembership); err != nil {
		t.Fatalf("WithdrawHostRetirement: %v", err)
	}
	// Two passes, because a standing condition resolves on consecutive clean
	// passes rather than immediately.
	s.evaluateAttestedPremises(ctx)
	s.evaluateAttestedPremises(ctx)

	if got, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); ok &&
		got.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a withdrawn grant is still advertised as IN FORCE (%+v). It supplies no "+
			"premise, and showing it invites reasoning about an exception that is gone", got)
	}
}

// listRetirements reads the operator-facing listing.
func listRetirements(t *testing.T, s *Server) []*pb.LostHostRetirement {
	t.Helper()
	resp, err := s.ListLostHostRetirements(withdrawerCtx(), nil)
	if err != nil {
		t.Fatalf("ListLostHostRetirements: %v", err)
	}
	return resp.GetRetirements()
}

func findRetirement(t *testing.T, rows []*pb.LostHostRetirement,
	premise corrosion.RetirementPremise) *pb.LostHostRetirement {

	t.Helper()
	for _, r := range rows {
		if r.GetPremise() == string(premise) {
			return r
		}
	}
	t.Fatalf("no %s retirement in the listing (%d row(s))", premise, len(rows))
	return nil
}

func containsName(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
