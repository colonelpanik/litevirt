// The two proofs that ask the CLUSTER whether this node's view is complete, at
// the branches a multi-node harness cannot drive precisely.
//
// tests/fleet has the real thing — two daemons, two divergent databases — and it
// covers the outcomes. What it cannot do is hand a peer a specific ANSWER, and
// these proofs turn on exactly that: a peer holding more rows than us, the same
// number of DIFFERENT rows, or fewer. A stub peer is the only way to sit on each
// of those branches deliberately rather than by arranging a fixture that happens
// to produce one.

package grpcapi

import (
	"context"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// answeringPeer is a peer that answers GetStateDigest with whatever the scenario
// decided, and nothing else.
type answeringPeer struct {
	pb.LiteVirtClient
	tables []*pb.TableDigest
}

func (p *answeringPeer) GetStateDigest(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return &pb.StateDigestResponse{HostName: "peer-b", Tables: p.tables}, nil
}

// peerReports wires every peer dial to a stub answering with these digests.
func peerReports(s *Server, tables ...*pb.TableDigest) {
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &answeringPeer{tables: tables}, func() {}, nil
	}
}

// localDigestFor reads this node's own digest for one table, so a scenario can
// build a peer answer RELATIVE to it — the same count with a different hash, one
// row fewer — instead of hardcoding numbers that a fixture change would silently
// invalidate.
func localDigestFor(t *testing.T, s *Server, table string) corrosion.TableDigest {
	t.Helper()
	d, err := s.localTableDigest(context.Background(), table)
	if err != nil {
		t.Fatalf("local %s digest: %v", table, err)
	}
	return d
}

func digestOf(d corrosion.TableDigest) *pb.TableDigest {
	return &pb.TableDigest{
		Name: d.Name, Count: int32(d.Count), Hash: d.Hash, HashV2: d.HashV2,
	}
}

// ── the bind's VM-inventory corroboration ───────────────────────────────────

// TestBindSuspendsWhenAPeerHoldsTheSameNumberOfDIFFERENTVMRows is the case a row
// COUNT cannot see, and the one that was shipped broken.
//
// Two nodes each holding one VM have `vms` tables of the same size and different
// contents. The binding node's guest is on an unrelated network; the peer's is
// the incumbent sitting on the first address the prefix will offer. Compared by
// count the two agree, the read looks whole, and the bind goes live having
// adopted nothing — then hands the incumbent's address to the next VM created
// there. Compared by the digest anti-entropy repairs on, they do not agree.
func TestBindSuspendsWhenAPeerHoldsTheSameNumberOfDIFFERENTVMRows(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "unrelated", "other-net", "aa:bb:cc:00:09:01", "10.90.0.50",
		"33333333-3333-3333-3333-333333333333", "running")

	local := localDigestFor(t, s, vmsTableName)
	if local.Count != 1 {
		t.Fatalf("precondition: this node must hold exactly one vms row, got %d", local.Count)
	}
	// Same size, different content — the peer holds a row this node does not.
	peerReports(s, &pb.TableDigest{
		Name: vmsTableName, Count: int32(local.Count), Hash: "a-different-table-entirely",
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a peer holding a DIFFERENT set of the same size means this node's list is not " +
			"the cluster's; the bind must not go live")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the uncorroborated-read one", b.SuspendReason)
	}
}

// TestBindSuspendsWhenAPeerHoldsMoreVMRowsThanThisNode is the same comparison
// against a NON-EMPTY local table, which is the whole of what generalising it
// bought.
//
// The proof once compared each peer's count against ZERO, because it was proving
// emptiness: a peer holding rows only mattered while this node held none. Against
// a node that holds one VM and a peer that holds two, comparing against zero says
// nothing at all — and the row this node is missing is exactly the guest whose
// address the bind is about to let NetBox hand out.
func TestBindSuspendsWhenAPeerHoldsMoreVMRowsThanThisNode(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:0c:01", "10.90.0.53",
		"44444444-4444-4444-4444-444444444444", "running")

	local := localDigestFor(t, s, vmsTableName)
	if local.Count == 0 {
		t.Fatal("precondition: this node must already hold a vms row, or the comparison is the empty one")
	}
	peerReports(s, &pb.TableDigest{
		Name: vmsTableName, Count: int32(local.Count + 1), Hash: "a-fuller-table",
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a peer holding more VM rows than this node means this node's list is short; " +
			"the bind must not go live")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the uncorroborated-read one", b.SuspendReason)
	}
}

// TestBindIsLiveWhenAReachablePeerAgrees is the property every other NetBox
// scenario depends on, spelled out: corroboration is a check that PASSES on a
// healthy cluster, immediately and with no suspension.
func TestBindIsLiveWhenAReachablePeerAgrees(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:0a:01", "10.90.0.51",
		"22222222-2222-2222-2222-222222222222", "running")

	peerReports(s, digestOf(localDigestFor(t, s, vmsTableName)))

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("a corroborated inventory must bind live immediately, got %q", b.SuspendReason)
	}
}

// TestBindIsLiveWhenAPeerIsMerelyBehind is the deliberate limit of the rule, and
// the reason it is not simply "every peer must agree".
//
// A peer that holds FEWER rows than this node is a peer that is lagging —
// restarted, or catching up — and it cannot be the reason THIS node's list is
// short. Refusing there would suspend a binding on any cluster where a node is
// behind, which is a cluster that has just restarted one, and the operator would
// have nothing to repair.
func TestBindIsLiveWhenAPeerIsMerelyBehind(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:0b:01", "10.90.0.52",
		"11111111-1111-1111-1111-111111111111", "running")

	local := localDigestFor(t, s, vmsTableName)
	peerReports(s, &pb.TableDigest{
		Name: vmsTableName, Count: int32(local.Count - 1), Hash: "an-older-table",
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("a lagging peer must not suspend a bind on a node that is ahead of it, got %q",
			b.SuspendReason)
	}
}

// TestAnUncorroboratedBindWithCandidatesKeepsTheSelfLiftingReason pins the
// ORDER of the two suspension reasons, which only a partially hydrated node can
// reach.
//
// Such a node has BOTH: addresses it can see and adopt on the network being
// bound, and no standing to call that list complete. The two reasons are not
// equivalent — only the uncorroborated one is in the class the revalidation pass
// lifts by itself — so writing "adoption is owed" over it would leave the
// binding waiting for an operator with nothing to repair, while the adoption it
// names refuses on the uncorroborated sentinel anyway. Deadlock, under a reason
// that says a human must act.
func TestAnUncorroboratedBindWithCandidatesKeepsTheSelfLiftingReason(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	// A guest of this node's own, holding an address INSIDE the prefix being
	// bound — so the plan has a candidate as well as no corroboration.
	seedVMHoldingIP(t, s, "mine", "shared", "aa:bb:cc:00:0d:01", "10.0.5.42",
		"55555555-5555-5555-5555-555555555555")

	local := localDigestFor(t, s, vmsTableName)
	peerReports(s, &pb.TableDigest{
		Name: vmsTableName, Count: int32(local.Count + 1), Hash: "a-fuller-table",
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a bind with candidates it cannot prove complete must not go live")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the self-lifting uncorroborated one — the adoption reason "+
			"would strand this binding, because the adoption itself refuses while the inventory "+
			"is unproven", b.SuspendReason)
	}
}

// ── the sweeper's membership corroboration ──────────────────────────────────

// TestMembershipViewIsUncorroboratedWhenAPeerKnowsMoreHosts is the second half
// of the sweeper fix, and the half a gossip union cannot supply.
//
// Unioning gossip into the participant universe covers a peer some source names.
// A host in NEITHER source is invisible to both, and the only node that can say
// so is one that HAS its row: a peer reporting more `hosts` rows than this node
// holds is saying this node cannot have asked every host.
func TestMembershipViewIsUncorroboratedWhenAPeerKnowsMoreHosts(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	local := localDigestFor(t, s, hostsTableName)
	peerReports(s, &pb.TableDigest{
		Name: hostsTableName, Count: int32(local.Count + 1), Hash: "a-fuller-host-table",
	})

	participants, err := s.proofParticipants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reason, cerr := s.membershipViewUncorroborated(ctx, participants)
	if cerr != nil {
		t.Fatalf("membershipViewUncorroborated: %v", cerr)
	}
	if reason == "" {
		t.Fatal("a peer that knows more hosts than this node leaves the membership view unproven")
	}
	// The reason has to NAME the host and what it said: "we could not prove it"
	// with nothing attached is the log line nobody can act on.
	if !strings.Contains(reason, "peer-b") || !strings.Contains(reason, hostsTableName) {
		t.Fatalf("reason = %q, want it to name the host and the table", reason)
	}
}

// TestMembershipViewIsCorroboratedWhenPeersAgreeOrLag keeps the check from being
// a permanent refusal.
//
// A peer that agrees, and a peer that is BEHIND, both leave the view
// corroborated — the second because a node that knows about fewer hosts cannot
// be evidence that this node's set is short. A sweeper that refused on either
// would never reclaim anything on a real cluster.
func TestMembershipViewIsCorroboratedWhenPeersAgreeOrLag(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		delta int32
	}{
		{"agrees", 0},
		{"lags", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdoptTestServer(t)
			seedPeerHost(t, s, "peer-b")
			local := localDigestFor(t, s, hostsTableName)
			peer := digestOf(local)
			peer.Count += tc.delta
			if tc.delta != 0 {
				peer.Hash = "an-older-host-table"
			}
			peerReports(s, peer)

			participants, err := s.proofParticipants(ctx)
			if err != nil {
				t.Fatal(err)
			}
			reason, cerr := s.membershipViewUncorroborated(ctx, participants)
			if cerr != nil {
				t.Fatalf("membershipViewUncorroborated: %v", cerr)
			}
			if reason != "" {
				t.Fatalf("the view must be corroborated, got %q", reason)
			}
		})
	}
}

// TestMembershipViewFailsClosedOnAPeerThatCannotAnswer pins the two silences.
//
// A host that cannot be reached, and one that answers without a `hosts` digest
// (an older build, or one whose digest set does not carry the table), are both
// hosts whose view could not be read. Neither is agreement, and reading either
// as agreement is what would let a reclamation rest on a cluster this node
// cannot see all of.
func TestMembershipViewFailsClosedOnAPeerThatCannotAnswer(t *testing.T) {
	ctx := context.Background()

	// Unreachable: seedPeerHost's address is a reserved documentation address
	// nothing answers on, and no stub is installed.
	s := newAdoptTestServer(t)
	seedPeerHost(t, s, "peer-b")
	participants, err := s.proofParticipants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reason, cerr := s.membershipViewUncorroborated(ctx, participants)
	if cerr != nil || reason == "" {
		t.Fatalf("an unreachable host must leave the view unproven, got %q (err %v)", reason, cerr)
	}

	// Answers, but says nothing about `hosts`.
	silent := newAdoptTestServer(t)
	seedPeerHost(t, silent, "peer-b")
	peerReports(silent, &pb.TableDigest{Name: vmsTableName, Count: 0})
	participants, err = silent.proofParticipants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reason, cerr = silent.membershipViewUncorroborated(ctx, participants)
	if cerr != nil || reason == "" {
		t.Fatalf("silence about %s must leave the view unproven, got %q (err %v)",
			hostsTableName, reason, cerr)
	}
}

// TestProofParticipantsKeepsGossipUnderTheSameExclusions is the trap the union
// walks straight into if it is bolted on rather than folded in.
//
// eligibility is not a property of the SOURCE that named a host. A host excluded
// by an operator's power-off attestation must stay excluded when gossip also
// names it — otherwise the union silently undoes the one escape hatch the
// sweeper has, and after a permanent host loss it is inert forever.
func TestProofParticipantsKeepsGossipUnderTheSameExclusions(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// Known ONLY to gossip: no hosts row at all.
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "gone", Addr: "203.0.113.9:7946"}}
	})
	hosts, err := s.proofParticipants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(hosts, "gone") {
		t.Fatalf("a gossip-only peer must be a participant, got %v", hosts)
	}

	// …and the operator attests it powered off. Nothing has made it reachable,
	// so the attestation governs and it leaves the set.
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('fence-confirm-gone', 'gone', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatalf("write fence confirmation: %v", err)
	}
	hosts, err = s.proofParticipants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(hosts, "gone") {
		t.Fatalf("a fenced host named by gossip must still be excluded, got %v", hosts)
	}
}
