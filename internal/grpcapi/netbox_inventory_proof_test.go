// The proofs that ask the CLUSTER whether this node's view is complete, at the
// branches a multi-node harness cannot drive precisely.
//
// tests/fleet has the real thing — two daemons, two divergent databases — and it
// covers the outcomes. What it cannot do is hand a peer a specific ANSWER, and
// these proofs turn on exactly that: a peer holding more rows than us, the same
// number of DIFFERENT rows, or fewer; a peer that names a host nobody here has
// heard of, one that cannot answer at all, one that answers with no membership
// view. A stub peer is the only way to sit on each of those branches
// deliberately rather than by arranging a fixture that happens to produce one.

package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// answeringPeer is a peer that answers GetStateDigest with whatever the scenario
// decided, ListHosts with the membership it was given, and nothing else.
type answeringPeer struct {
	pb.LiteVirtClient
	tables []*pb.TableDigest
	hosts  []string
}

func (p *answeringPeer) GetStateDigest(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return &pb.StateDigestResponse{HostName: "peer-b", Tables: p.tables}, nil
}

// ListHosts is what the participant-set closure asks for.
//
// Every scenario in this file is about a DIGEST branch, so the answer names only
// hosts this node already knows: the closure then closes in one round having
// learned nothing new, and the digest comparison is what decides the outcome. A
// stub that could not close the set would suspend every bind here for a reason
// none of these scenarios is about.
func (p *answeringPeer) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	resp := &pb.ListHostsResponse{}
	for _, h := range p.hosts {
		resp.Hosts = append(resp.Hosts, &pb.Host{Name: h})
	}
	return resp, nil
}

// peerReports wires every peer dial to a stub answering with these digests, and
// agreeing about membership.
func peerReports(s *Server, tables ...*pb.TableDigest) {
	s.peerClientOverride = func(ctx context.Context, _ string) (pb.LiteVirtClient, func(), error) {
		return &answeringPeer{tables: tables, hosts: localHostNames(ctx, s)}, func() {}, nil
	}
}

// localHostNames is every host THIS node knows — the ListHosts answer a peer in
// agreement about membership gives, so the closure learns nothing new from it.
func localHostNames(ctx context.Context, s *Server) []string {
	rows, err := s.db.Query(ctx, `SELECT name FROM hosts`)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		if n := r.String("name"); n != "" {
			out = append(out, n)
		}
	}
	return out
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

// agreeingDigests is this node's own digest for EVERY table corroboration
// covers, which is what a converged peer answers with.
//
// Built from adoptionInventoryTables rather than listed here, so a table added
// to the proof does not quietly turn this stub into a peer that stays silent
// about one — which the proof reads as "not corroborated", correctly, and which
// would make this scenario about the wrong thing.
func agreeingDigests(t *testing.T, s *Server) []*pb.TableDigest {
	t.Helper()
	var out []*pb.TableDigest
	for _, table := range adoptionInventoryTables() {
		out = append(out, digestOf(localDigestFor(t, s, table)))
	}
	return out
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

	peerReports(s, agreeingDigests(t, s)...)

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

// TestBindSuspendsWhenAPeerHoldsFEWERVMRowsThanThisNode is the relaxation this
// round removed, inverted.
//
// A peer holding STRICTLY FEWER rows was once accepted, on the reasoning that a
// lagging peer cannot be why THIS node's list is short and that suspending on
// one would suspend every bind on a cluster with a restarted node. Fewer rows do
// not make a subset: a peer holding one incumbent VM and a binder holding two
// unrelated ones land on exactly this branch — "the peer is behind" — and the
// incumbent's address is handed to the next VM created there. This scenario is
// that arithmetic, at its smallest: the peer holds one row fewer, and it is a
// row this node does not have.
//
// What makes the strictness affordable is that the bind CONVERGES: it is
// suspended under the reason the revalidation pass lifts by itself, so a lagging
// peer delays a bind and never fails one. Both halves are asserted, because
// suspending under any OTHER reason would be a refusal waiting on an operator
// who has nothing to repair.
func TestBindSuspendsWhenAPeerHoldsFEWERVMRowsThanThisNode(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:0b:01", "10.90.0.52",
		"11111111-1111-1111-1111-111111111111", "running")

	// Everything agrees except `vms`, where the peer is one row short — so the
	// count relation is the ONLY thing this scenario turns on.
	behind := agreeingDigests(t, s)
	for _, d := range behind {
		if d.GetName() == vmsTableName {
			d.Count--
			d.Hash = "an-older-table"
			d.HashV2 = ""
		}
	}
	peerReports(s, behind...)

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a peer that does not AGREE leaves this node unable to say its inventory is the " +
			"cluster's; fewer rows do not make a subset, so the bind must not go live")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the self-lifting uncorroborated one — a lagging peer must "+
			"DELAY a bind, not fail one", b.SuspendReason)
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

// TestBindSuspendsWhenAPeerIsSilentAboutOneInventoryTable.
//
// A peer that agrees about `vms` and says NOTHING about a NIC table has not
// agreed about the NIC table — it is an older build, or one whose digest set does
// not carry it. Reading silence as agreement would restore the defect covering
// four tables was meant to close: the addresses live on the NIC rows, and a peer
// that never mentions them cannot corroborate them.
func TestBindSuspendsWhenAPeerIsSilentAboutOneInventoryTable(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:0e:01", "10.90.0.54",
		"66666666-6666-6666-6666-666666666666", "running")

	silent := "vm_nics"
	var partial []*pb.TableDigest
	for _, d := range agreeingDigests(t, s) {
		if d.GetName() != silent {
			partial = append(partial, d)
		}
	}
	if len(partial) != len(adoptionInventoryTables())-1 {
		t.Fatalf("precondition: exactly one table must be withheld, %s is not in the set", silent)
	}
	peerReports(s, partial...)

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatalf("silence about %s is not agreement about it; the bind must not go live", silent)
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the self-lifting uncorroborated one", b.SuspendReason)
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

// ── the participant-set closure ─────────────────────────────────────────────

// membershipPeer answers only ListHosts — the question the closure asks — so a
// scenario can hand it one membership view and nothing else.
type membershipPeer struct {
	pb.LiteVirtClient
	hosts func() []string
}

func (p *membershipPeer) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	resp := &pb.ListHostsResponse{}
	for _, name := range p.hosts() {
		resp.Hosts = append(resp.Hosts, &pb.Host{Name: name})
	}
	return resp, nil
}

// peerKnows wires every peer dial to a stub whose membership view is fn().
// Called per dial, so a scenario can answer differently each round.
func peerKnows(s *Server, fn func() []string) {
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &membershipPeer{hosts: fn}, func() {}, nil
	}
}

// TestClosedParticipantSetLearnsAHostOnlyAPeerKnows is the whole point of the
// closure, and the case no comparison of this node's own set can reach.
//
// A host in NEITHER the local `hosts` table nor gossip is invisible to both
// samples of the sweeper's five-step proof, so the samples agree and stability
// gets mistaken for completeness. Asking each participant WHICH hosts it knows
// is what reveals it — by name, so it can then be asked whether it holds the
// address.
func TestClosedParticipantSetLearnsAHostOnlyAPeerKnows(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	peerKnows(s, func() []string { return []string{"peer-b", "peer-c"} })

	local, err := s.proofParticipants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(local, "peer-c") {
		t.Fatalf("precondition: peer-c must be unknown to this node's own sources, got %v", local)
	}

	closed, unclosed, err := s.closedParticipantSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close — every participant answered: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(closed, "peer-c") {
		t.Fatalf("a host a reachable peer knows about must be a participant, got %v", closed)
	}
}

// TestClosedParticipantSetKeepsPeerNamedHostsUnderTheSameExclusions is the trap
// a third source walks straight into if it is bolted on rather than folded in.
//
// Eligibility is not a property of the SOURCE that named a host. A host excluded
// by an operator's power-off attestation must stay excluded when a PEER also
// names it — otherwise the closure silently undoes the one escape hatch the
// sweeper has, and after a permanent host loss it is inert forever with nothing
// an operator can do about it.
func TestClosedParticipantSetKeepsPeerNamedHostsUnderTheSameExclusions(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	// "gone" is named ONLY by the peer: no host row here, and not in gossip.
	peerKnows(s, func() []string { return []string{"peer-b", "gone"} })

	closed, unclosed, err := s.closedParticipantSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(closed, "gone") {
		t.Fatalf("precondition: a peer-named host with no attestation must be a participant, got %v",
			closed)
	}

	// …and the operator attests it powered off. Nothing has made it reachable,
	// so the attestation governs and it leaves the set — even though the peer
	// still names it.
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('fence-confirm-gone', 'gone', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatalf("write fence confirmation: %v", err)
	}
	closed, unclosed, err = s.closedParticipantSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must still close: %q (err %v)", unclosed, err)
	}
	if slices.Contains(closed, "gone") {
		t.Fatalf("a fenced host named by a peer must still be excluded, got %v", closed)
	}
}

// TestClosedParticipantSetWithholdsWhenAParticipantCannotAnswer.
//
// A participant that cannot be reached leaves the set unclosable: what it knows
// is what would have revealed a further holder, and silence is not the statement
// that there is none. Same direction the per-host proof already takes for an
// unreachable host — withhold, and let the next pass try.
func TestClosedParticipantSetWithholdsWhenAParticipantCannotAnswer(t *testing.T) {
	s := newAdoptTestServer(t)
	// No stub: seedPeerHost's address is a reserved documentation address
	// nothing answers on.
	seedPeerHost(t, s, "peer-b")

	closed, unclosed, err := s.closedParticipantSet(context.Background())
	if err != nil {
		t.Fatalf("an unreachable peer is part of the answer, not an error: %v", err)
	}
	if unclosed == "" {
		t.Fatalf("a participant that cannot be asked leaves the set unclosed, got %v", closed)
	}
	if !strings.Contains(unclosed, "peer-b") {
		t.Fatalf("the reason must name the host that could not be asked, got %q", unclosed)
	}
}

// TestClosedParticipantSetWithholdsOnAnEmptyMembershipView.
//
// A node knows at least itself, so an answer naming nobody is a node whose own
// `hosts` table has not hydrated — not the claim that the cluster is empty.
// Folding that in as "learned nothing new" would close the set on the one answer
// that says the peer cannot speak for the cluster either.
func TestClosedParticipantSetWithholdsOnAnEmptyMembershipView(t *testing.T) {
	s := newAdoptTestServer(t)
	seedPeerHost(t, s, "peer-b")
	peerKnows(s, func() []string { return nil })

	closed, unclosed, err := s.closedParticipantSet(context.Background())
	if err != nil {
		t.Fatalf("an empty view is part of the answer, not an error: %v", err)
	}
	if unclosed == "" {
		t.Fatalf("a participant with no membership view leaves the set unclosed, got %v", closed)
	}
}

// TestClosedParticipantSetIsBounded pins that the fixpoint cannot spin.
//
// Each answer names a host nobody has seen before, so the set grows every round
// and never closes. The loop must give up — and giving up is a REFUSAL, not a
// truncated set: an unclosed set proves nothing, and returning it as though it
// were closed is how a bound turns into a fail-open.
func TestClosedParticipantSetIsBounded(t *testing.T) {
	s := newAdoptTestServer(t)
	seedPeerHost(t, s, "peer-b")
	round := 0
	peerKnows(s, func() []string {
		round++
		return []string{fmt.Sprintf("peer-generated-%d", round)}
	})

	closed, unclosed, err := s.closedParticipantSet(context.Background())
	if err != nil {
		t.Fatalf("a growing set is part of the answer, not an error: %v", err)
	}
	if unclosed == "" {
		t.Fatalf("a set that never stops growing must not be reported as closed, got %v", closed)
	}
	if closed != nil {
		t.Fatalf("an unclosed set must not be returned to a caller, got %v", closed)
	}
	// Each round learns exactly one new host from this stub, so the number of
	// dials IS the number of rounds — and it must not exceed the bound.
	if round > hostSetClosureRounds {
		t.Fatalf("the fan-out dialled %d times, past the %d-round bound",
			round, hostSetClosureRounds)
	}
}

// ── the table set corroboration covers ──────────────────────────────────────

// TestAdoptionInventoryTablesCoverEveryAddressBearingTable is the guard that
// keeps P1-3 from coming back.
//
// The corroboration once covered `vms` alone, which is the one table in the set
// that records no address at all. What makes the set right is that it is DERIVED
// from nicClaimTables — this package's single registry of the tables that record
// a NIC's MAC and IP, already read by the orphan proof — so a table added there
// is covered here without anybody remembering to. This asserts that derivation
// holds, and that every table in it is one a peer will actually report: a name
// missing from corrosion's replicated digest set would fail closed forever
// rather than loudly.
func TestAdoptionInventoryTablesCoverEveryAddressBearingTable(t *testing.T) {
	got := adoptionInventoryTables()

	if !slices.Contains(got, vmsTableName) {
		t.Fatalf("the enumeration adoption starts from must be covered, got %v", got)
	}
	for _, claim := range nicClaimTables {
		if !slices.Contains(got, claim.name) {
			t.Fatalf("%s records a NIC's address, so corroboration must cover it; got %v",
				claim.name, got)
		}
	}
	if len(got) != len(nicClaimTables)+1 {
		t.Fatalf("the set must be exactly `vms` plus nicClaimTables, so it cannot drift out of "+
			"step with what the proofs read; got %v", got)
	}

	// …and every one of them is a table THIS node digests, which is what makes
	// a peer's silence about one meaningful rather than universal.
	s := newAdoptTestServer(t)
	if _, err := s.localTableDigests(context.Background(), got); err != nil {
		t.Fatalf("every corroborated table must appear in the replicated digest set: %v", err)
	}
}
