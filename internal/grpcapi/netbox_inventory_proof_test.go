// The proofs that ask the CLUSTER whether this node's view is complete, at the
// branches a multi-node harness cannot drive precisely.
//
// tests/fleet has the real thing — two daemons, two divergent databases — and it
// covers the outcomes. What it cannot do is hand a peer a specific ANSWER, and
// these proofs turn on exactly that: a peer holding more rows than us, the same
// number of DIFFERENT rows, or fewer; a peer that names a host nobody here has
// heard of, one that names it only in GOSSIP, one running a build too old to
// answer the question at all, one that answers with no membership view. A stub
// peer is the only way to sit on each of those branches deliberately rather than
// by arranging a fixture that happens to produce one.

package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// answeringPeer is a peer that answers GetStateDigest and GetMembershipView with
// whatever the scenario decided, and nothing else.
//
// pb.LiteVirtClient is embedded UNIMPLEMENTED, which is load-bearing: any other
// RPC panics on the nil interface rather than quietly returning a zero value. So
// a scenario asserts by construction that the participant-set closure reaches a
// peer with one membership call and pulls no state dump — the whole-database
// fetch this replaced.
type answeringPeer struct {
	pb.LiteVirtClient
	tables []*pb.TableDigest
	// membership is what this peer answers GetMembershipView with. nil means it
	// answers Unimplemented, which is an OLDER BUILD — the shape that carries
	// this feature's entire mixed-version story.
	membership *pb.MembershipViewResponse
}

func (p *answeringPeer) GetStateDigest(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return &pb.StateDigestResponse{HostName: "peer-b", Tables: p.tables}, nil
}

// GetMembershipView is how the participant-set closure reads a peer's whole
// candidate universe: its `hosts` rows, tombstones included, and the gossip
// members only its own memberlist can name.
func (p *answeringPeer) GetMembershipView(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.MembershipViewResponse, error) {
	if p.membership == nil {
		return nil, status.Error(codes.Unimplemented,
			"unknown method GetMembershipView for service litevirt.v1.LiteVirt")
	}
	return p.membership, nil
}

// peerReports wires every peer dial to a stub answering with these digests.
//
// Every scenario built on it is about an INVENTORY digest branch, so the peer
// also answers the membership question with a view identical to this node's:
// the closure then learns nothing new, closes in a single round, and the
// inventory comparison is what decides the outcome. A stub that could not answer
// the membership question would leave every bind here unproven for a reason none
// of these scenarios is about.
func peerReports(s *Server, tables ...*pb.TableDigest) {
	s.peerClientOverride = func(ctx context.Context, host string) (pb.LiteVirtClient, func(), error) {
		return &answeringPeer{tables: tables, membership: viewLikeThisNodes(ctx, s, host)}, func() {}, nil
	}
}

// peerKnows wires every peer dial to a peer answering the membership question
// with fn(host). Called per dial, so a scenario can answer differently each
// round.
func peerKnows(s *Server, fn func(host string) *pb.MembershipViewResponse) {
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		return &answeringPeer{membership: fn(host)}, func() {}, nil
	}
}

// viewLikeThisNodes is the membership view a peer whose `hosts` table is
// identical to this node's, and whose gossip names nobody new, answers with.
func viewLikeThisNodes(ctx context.Context, s *Server, host string) *pb.MembershipViewResponse {
	return membershipNaming(host, workerRows(localHostNames(ctx, s)...), nil)
}

// membershipNaming builds the view a peer holding exactly these `hosts` rows and
// naming exactly these gossip members answers with. complete is true — the
// scenarios that need an incomplete view build one explicitly, because "could
// not enumerate" is a different claim from "knows nobody".
func membershipNaming(host string, rows []*pb.MembershipHost, gossip []string) *pb.MembershipViewResponse {
	return &pb.MembershipViewResponse{
		Host: host, Hosts: rows, GossipMembers: gossip, Complete: true,
	}
}

// workerRows names `hosts` rows carrying the ordinary worker role, which is what
// the exclusions leave in. Tombstoned and live rows are indistinguishable on the
// wire by contract — soft-deleting a row does not power a machine off — so a
// scenario about a tombstone names it here exactly like any other row and pins
// the CONTRACT in tests/fleet, against a real server.
func workerRows(names ...string) []*pb.MembershipHost {
	out := make([]*pb.MembershipHost, 0, len(names))
	for _, n := range names {
		out = append(out, &pb.MembershipHost{Name: n, Role: "worker"})
	}
	return out
}

// seedSelfHost gives this node the `hosts` row every real node holds for itself,
// which is the row a responder's completeness check looks for.
// newAdoptTestServer's database has none — that is itself the unhydrated shape
// TestGetMembershipViewIsIncompleteWithoutARowForItself is about.
func seedSelfHost(t *testing.T, s *Server) {
	t.Helper()
	seedPeerHost(t, s, s.hostName)
}

// localHostNames is every host THIS node holds a `hosts` row for, tombstones
// included — the set a peer whose table is identical to this one's would name.
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

// TestBindRequiresTheSAMEMembershipProofTheSweeperDoes is the asymmetry that
// shipped: the sweeper corroborated its membership view before reclaiming and
// the bind did not, so a holder invisible to the bind had its address handed to
// the next guest created — the same collision, reached from the other side.
//
// Every inventory table AGREES here, so nothing in the four-table comparison can
// account for the outcome. What is missing is membership: the peer holds a
// `hosts` row for a third host that cannot be reached, so the participant set
// cannot be closed, and an inventory corroborated by a set that is not the
// cluster's is not corroborated at all. Both proofs reach their peer set through
// one helper precisely so this cannot come back — and the suspension is the
// self-lifting one, so an unreachable third host delays the bind and never fails
// it.
func TestBindRequiresTheSAMEMembershipProofTheSweeperDoes(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:0c:01", "10.90.0.53",
		"44444444-4444-4444-4444-444444444444", "running")

	known := localHostNames(ctx, s)
	agreeing := agreeingDigests(t, s)
	// The peer agrees about every address-bearing table, and holds one `hosts`
	// row this node does not: an unreachable third host.
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host == "unreachable-third" {
			return nil, nil, fmt.Errorf("no route to host")
		}
		return &answeringPeer{
			tables: agreeing,
			membership: membershipNaming(host,
				workerRows(append(append([]string{}, known...), "unreachable-third")...), nil),
		}, func() {}, nil
	}

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("agreement across a participant set that is not the cluster's is not " +
			"corroboration; the bind must not go live on it")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the self-lifting uncorroborated one", b.SuspendReason)
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

// ── one participant's membership view ───────────────────────────────────────

// TestGetMembershipViewServesEveryRowAndTheGossipNamesNoTableHolds is the
// responder side of the closure, and the two halves it must carry.
//
// A TOMBSTONED row is served like any other: `lv host rm --force` does not power
// a machine off, so the host whose row was soft-deleted is exactly the one that
// may still be running the domain holding an address. And a gossip member with
// no row anywhere is served too, because that is the only source that can name
// such a host at all — no table records it, so no table-derived answer could.
func TestGetMembershipViewServesEveryRowAndTheGossipNamesNoTableHolds(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedSelfHost(t, s)
	seedPeerHost(t, s, "peer-b")
	// The asker: a live host, because the host whose row is tombstoned below is
	// no longer a trusted CN — which is itself the point of tombstoning it.
	seedPeerHost(t, s, "peer-c")
	if err := s.db.Execute(ctx,
		`UPDATE hosts SET deleted_at = '2026-09-01T00:00:00Z' WHERE name = ?`, "peer-b"); err != nil {
		t.Fatalf("tombstone the peer row: %v", err)
	}
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "gossip-only", Addr: "203.0.113.9:7946"}}
	})

	// The precondition that makes the tombstone case worth serving: the filtered
	// read every earlier attempt at this proof was built on cannot see it.
	live, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range live {
		if h.Name == "peer-b" {
			t.Fatal("precondition: ListHosts must be blind to the tombstoned row")
		}
	}

	resp, err := s.GetMembershipView(mtlsCtx("peer-c"), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("a peer must be able to ask: %v", err)
	}
	if !resp.GetComplete() {
		t.Fatalf("both enumerations succeeded, so the view is complete: %v", resp.GetErrors())
	}
	var named []string
	for _, r := range resp.GetHosts() {
		named = append(named, r.GetName())
	}
	if !slices.Contains(named, "peer-b") {
		t.Fatalf("a TOMBSTONED row must still be served — a forced removal does not power a "+
			"machine off; got %v", named)
	}
	if !slices.Contains(named, s.hostName) {
		t.Fatalf("this host's own row must be served, got %v", named)
	}
	if !slices.Contains(resp.GetGossipMembers(), "gossip-only") {
		t.Fatalf("a gossip member no table records must be served — nothing else can name "+
			"it; got %v", resp.GetGossipMembers())
	}
	if resp.GetHost() != s.hostName {
		t.Fatalf("host = %q, want the responder's own name", resp.GetHost())
	}
}

// TestGetMembershipViewCarriesTheRoleTheExclusionsTurnOn.
//
// The witness exclusion is the one rule that can drop a host from a proof on
// sight, and only a `hosts` row records a role. A view carrying bare names would
// leave a caller unable to apply that rule to a host it learned here — and
// re-deriving the rule from some second source is how two proofs come to
// disagree.
func TestGetMembershipViewCarriesTheRoleTheExclusionsTurnOn(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "a-witness", Address: "203.0.113.8", GRPCPort: 7443, Role: "witness",
		SSHUser: "root", SSHPort: 22, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := s.GetMembershipView(mtlsCtx("a-witness"), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("a peer must be able to ask: %v", err)
	}
	for _, r := range resp.GetHosts() {
		if r.GetName() == "a-witness" {
			if r.GetRole() != "witness" {
				t.Fatalf("role = %q on the wire, want the row's own role — the exclusion "+
					"turns on it, and a caller that got a bare name could not apply it",
					r.GetRole())
			}
			return
		}
	}
	t.Fatalf("the witness row must be served at all, got %v", resp.GetHosts())
}

// TestGetMembershipViewIsIncompleteWithoutARowForItself.
//
// A node holds at least its own row, so a table that does not carry one has not
// hydrated — it is not a small cluster. Serving that as a whole view would let a
// caller close a participant set over a database that has barely started, which
// is the shape this proof exists to refuse.
func TestGetMembershipViewIsIncompleteWithoutARowForItself(t *testing.T) {
	s := newAdoptTestServer(t)
	seedPeerHost(t, s, "peer-b")
	// Deliberately NOT seedSelfHost: this node's table names a peer and not
	// itself, which no hydrated database does.

	resp, err := s.GetMembershipView(mtlsCtx("peer-b"), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("a failed enumeration is part of the ANSWER, not an error: %v", err)
	}
	if resp.GetComplete() {
		t.Fatal("a node with no row for itself has an unhydrated table, and must say so")
	}
	if len(resp.GetErrors()) == 0 {
		t.Fatal("an incomplete view must name the reason it is incomplete")
	}
}

// TestGetMembershipViewIsPeerOnly.
//
// The answer names every host this node knows of, tombstones included, which is
// cluster-internal shape. Peer-mTLS is the same trust boundary
// CollectOrphanProof draws, and it is drawn by the same helper rather than a
// second convention.
func TestGetMembershipViewIsPeerOnly(t *testing.T) {
	s := newAdoptTestServer(t)
	if _, err := s.GetMembershipView(context.Background(), &emptypb.Empty{}); err == nil {
		t.Fatal("a caller with no peer host certificate must be refused")
	}
}

// ── reading each participant's membership view ──────────────────────────────

// TestClosedParticipantSetReadsRowsFromAPeerThatHoldsMoreThanThisNode.
//
// A peer holding a `hosts` row this node has never received is the shape a row
// COUNT was once used to detect, and detecting it was all a count could do: it
// said "this node's view is short" and stopped there. The set is now closed over
// the peer's own view instead, so the extra host is learned BY NAME and asked —
// and stopping only happens if it cannot answer, which is the fail-closed edge
// rather than the whole mechanism.
func TestClosedParticipantSetReadsRowsFromAPeerThatHoldsMoreThanThisNode(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	known := localHostNames(ctx, s)
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host,
			workerRows(append(append([]string{}, known...), "peer-c")...), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unclosed != "" {
		t.Fatalf("every participant answered, so the set must close: %q", unclosed)
	}
	if !slices.Contains(closed, "peer-c") {
		t.Fatalf("the host only the peer holds a row for must be a participant, got %v", closed)
	}
}

// TestClosedParticipantSetLearnsAHostONLYAPEERSGOSSIPNames is the finding this
// RPC exists for, and the one shape rows could never reach.
//
// No node the sweeper can read holds a `hosts` row for the holder, and this
// node's own gossip does not name it. The only record of its existence anywhere
// is the PEER's memberlist view. Every table-derived answer — ListHosts,
// ClusterStatus.hosts, a state digest, a state dump — is blind to it by
// construction, because there is no row to derive it from.
func TestClosedParticipantSetLearnsAHostONLYAPEERSGOSSIPNames(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	known := localHostNames(ctx, s)
	if slices.Contains(known, "gossip-only-holder") {
		t.Fatal("precondition: no row anywhere may name the holder")
	}
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		if host == "gossip-only-holder" {
			// It answers too, so the set can actually close and the assertion is
			// about LEARNING the name rather than about a dial failing.
			return membershipNaming(host, workerRows(known...), []string{"gossip-only-holder"})
		}
		return membershipNaming(host, workerRows(known...), []string{"gossip-only-holder"})
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unclosed != "" {
		t.Fatalf("every participant answered, so the set must close: %q", unclosed)
	}
	if !slices.Contains(closed, "gossip-only-holder") {
		t.Fatalf("a host only a PEER's gossip names must be a participant — no table "+
			"anywhere records it; got %v", closed)
	}
}

// TestClosedParticipantSetClosesOnOneCallPerParticipant is the cost statement,
// and it is a soundness statement too.
//
// What this replaced read a peer's whole-table digest set and then, for any peer
// whose `hosts` table differed at all, a gzipped dump of the entire replicated
// database — per participant, twice per candidate, every sweep. One unary call
// per participant per closure is strictly less, and the stub proves no dump is
// pulled by not implementing one: the embedded nil client panics if anything
// asks.
func TestClosedParticipantSetClosesOnOneCallPerParticipant(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	var mu sync.Mutex
	calls := map[string]int{}
	known := localHostNames(ctx, s)
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		mu.Lock()
		calls[host]++
		mu.Unlock()
		return membershipNaming(host, workerRows(known...), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(closed, "peer-b") {
		t.Fatalf("the peer must be a participant, got %v", closed)
	}
	if calls["peer-b"] != 1 {
		t.Fatalf("a participant already read must not be asked again: %v", calls)
	}
	if _, self := calls[s.hostName]; self {
		t.Fatalf("this node answers for itself from its own database and must not be "+
			"dialled: %v", calls)
	}
}

// TestClosedParticipantSetFailsClosedOnAPeerThatCannotAnswer pins the silences.
//
// A host that cannot be reached, one running a build with no membership view to
// report, one that says its own enumeration failed, and one naming a host with
// an empty name are all hosts whose view could not be read. None of them is
// agreement, and reading any of them as agreement is what would let a
// reclamation rest on a cluster this node cannot see all of.
//
// The OLDER BUILD case is the whole mixed-version story, so it is pinned as its
// own branch with its own reason rather than left to fall through the transport
// one: this RPC's novelty is what makes it safe on a cluster mid-upgrade, and an
// Unimplemented answer is a definite failure.
func TestClosedParticipantSetFailsClosedOnAPeerThatCannotAnswer(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		wire func(t *testing.T, s *Server)
		want string
	}{
		{
			// seedPeerHost's address is a reserved documentation address nothing
			// answers on, and no stub is installed.
			name: "unreachable",
			wire: func(*testing.T, *Server) {},
		},
		{
			name: "an older build with no membership view",
			wire: func(_ *testing.T, s *Server) {
				// membership nil: the stub answers Unimplemented.
				peerKnows(s, func(string) *pb.MembershipViewResponse { return nil })
			},
			want: "build",
		},
		{
			name: "a view the peer reports as incomplete",
			wire: func(_ *testing.T, s *Server) {
				peerKnows(s, func(host string) *pb.MembershipViewResponse {
					return &pb.MembershipViewResponse{
						Host:     host,
						Hosts:    workerRows(host),
						Complete: false,
						Errors:   []string{"read this host's `hosts` rows: database is locked"},
					}
				})
			},
		},
		{
			name: "a row that names no host",
			wire: func(_ *testing.T, s *Server) {
				peerKnows(s, func(host string) *pb.MembershipViewResponse {
					return membershipNaming(host,
						append(workerRows(host), &pb.MembershipHost{Role: "worker"}), nil)
				})
			},
		},
		{
			name: "a gossip member that names no host",
			wire: func(_ *testing.T, s *Server) {
				peerKnows(s, func(host string) *pb.MembershipViewResponse {
					return membershipNaming(host, workerRows(host), []string{""})
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdoptTestServer(t)
			seedPeerHost(t, s, "peer-b")
			tc.wire(t, s)

			closed, unclosed, err := s.closedRuntimeProofSet(ctx)
			if err != nil {
				t.Fatalf("a peer that cannot answer is part of the answer, not an error: %v", err)
			}
			if unclosed == "" {
				t.Fatalf("the set must not close, got %v", closed)
			}
			if !strings.Contains(unclosed, "peer-b") {
				t.Fatalf("the reason must name the host, got %q", unclosed)
			}
			if tc.want != "" && !strings.Contains(unclosed, tc.want) {
				t.Fatalf("the reason must say %q so the repair is legible, got %q", tc.want, unclosed)
			}
		})
	}
}

// TestDiscoveryTargetsKeepAHostAnOperatorAttestedIsPoweredOff is the fix for
// exactly the claim this test used to make.
//
// It once asserted the opposite: that an operator's power-off attestation drops a
// host from the DISCOVERY fan-out, so the sweeper has an escape from a permanent
// host loss. That reading was refused, and it was refused because it is unsound.
// Confirming that a machine is off proves its libvirt cannot be running a domain.
// It proves NOTHING about the hosts that machine knew existed — and a witness
// attested off was the only node that could name a third host still holding the
// address, so excusing it from the question freed a live address.
//
// So the attested host stays in the fan-out and is still asked what it knows.
// Power-off evidence excuses a host from the runtime-proof set and from nothing
// else (TestTheThreeSetsDifferOnlyWhereTheEvidenceDiffers), and an unreachable
// host therefore keeps blocking the closure — which is the trade that was chosen
// over freeing an address a guest holds.
func TestDiscoveryTargetsKeepAHostAnOperatorAttestedIsPoweredOff(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// Known ONLY to gossip: no hosts row at all.
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "gone", Addr: "203.0.113.9:7946"}}
	})
	hosts, err := localDiscoveryTargets(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(hosts, "gone") {
		t.Fatalf("a gossip-only peer must be asked what it knows, got %v", hosts)
	}

	// …and the operator attests it powered off. Nothing has made it reachable,
	// so the attestation is as strong as it will ever be — and it still buys no
	// silence about what that host knew.
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('fence-confirm-gone', 'gone', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatalf("write fence confirmation: %v", err)
	}
	hosts, err = localDiscoveryTargets(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(hosts, "gone") {
		t.Fatalf("power-off evidence excuses a SCAN, never the question of who exists: an "+
			"attested host must still be asked what it knows, got %v", hosts)
	}

	// The corroboration set keeps it too: a machine that is off still holds
	// every replicated row it received.
	cs, err := s.localParticipantCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if corroborating := s.inventoryCorroborationParticipants(cs.names()); !slices.Contains(corroborating, "gone") {
		t.Fatalf("an attested host still holds its rows, so its inventory digest must be "+
			"consulted, got %v", corroborating)
	}
}

// localDiscoveryTargets is the membership-discovery fan-out over the candidates
// this node can name WITHOUT asking anybody — one closure round's worth of
// targets, which is what the exclusion tests above and below are about.
func localDiscoveryTargets(t *testing.T, s *Server) ([]string, error) {
	t.Helper()
	cs, err := s.localParticipantCandidates(context.Background())
	if err != nil {
		return nil, err
	}
	return s.membershipDiscoveryTargets(cs.names()), nil
}

// localRoleReading is the accumulated witness reading for one host across every
// `hosts` row THIS node holds. It is what runtimeProofParticipants consumes, and
// deliberately not something the fan-out can see.
func localRoleReading(t *testing.T, s *Server, host string) (witness, known bool) {
	t.Helper()
	cs, err := s.localParticipantCandidates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs.all() {
		if c.name == host {
			return c.witness, true
		}
	}
	return false, false
}

// ── the participant-set closure ─────────────────────────────────────────────

// TestClosedParticipantSetLearnsAHostTOMBSTONEDOnAPeer is the case closing the
// set over ListHosts could not reach, and the reason a row's tombstone is not on
// the wire as a flag.
//
// The holder's row exists only on the peer, and only as a TOMBSTONE. ListHosts
// filters `deleted_at IS NULL`, so a closure built on it learns nothing and
// closes — over the filter, not over the cluster — while a forced host removal
// has not powered that machine off and its domain still holds the address. The
// membership view carries the row like any other, so nothing here can branch on
// it even by accident.
func TestClosedParticipantSetLearnsAHostTOMBSTONEDOnAPeer(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	known := localHostNames(ctx, s)
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host,
			workerRows(append(append([]string{}, known...), "tombstoned-holder")...), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unclosed != "" {
		t.Fatalf("the peer's view was readable, so the set must close: %q", unclosed)
	}
	if !slices.Contains(closed, "tombstoned-holder") {
		t.Fatalf("a host a peer holds a TOMBSTONED row for must be a participant — "+
			"a forced removal does not power a machine off; got %v", closed)
	}
}

// TestClosedParticipantSetLearnsAHostOnlyAPeerKnows is the whole point of the
// closure, and the case no comparison of this node's own set can reach.
//
// A host in NEITHER the local `hosts` table nor gossip is invisible to both
// samples of the sweeper's five-step proof, so the samples agree and stability
// gets mistaken for completeness. Reading each participant's own view is what
// reveals it — by name, so it can then be asked whether it holds the address.
func TestClosedParticipantSetLearnsAHostOnlyAPeerKnows(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host, workerRows("peer-b", "peer-c"), nil)
	})

	local, err := localDiscoveryTargets(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(local, "peer-c") {
		t.Fatalf("precondition: peer-c must be unknown to this node's own sources, got %v", local)
	}

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close — every participant answered: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(closed, "peer-c") {
		t.Fatalf("a host a reachable peer knows about must be a participant, got %v", closed)
	}
}

// TestTheRuntimeExclusionAppliesToPeerNamedHostsToo is the trap a third source
// walks straight into if it is bolted on rather than folded in.
//
// An exclusion is not a property of the SOURCE that named a host. A host the
// runtime-proof set excuses on an operator's power-off attestation must stay
// excused when a PEER names it rather than this node's own table or gossip —
// otherwise the merge quietly re-adds it and the sweeper waits for a scan from a
// machine that is off.
//
// Note what is NOT being asserted, because this test asserted it once: the
// attested host is still ASKED WHAT IT KNOWS. It is dialled here like any other
// candidate, and the set closes because it answered — not because it was skipped.
// Power-off evidence excuses a scan and never a memory.
func TestTheRuntimeExclusionAppliesToPeerNamedHostsToo(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	// "gone" is named ONLY by the peer: no host row here, and not in gossip.
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host, workerRows("peer-b", "gone"), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(closed, "gone") {
		t.Fatalf("precondition: a peer-named host with no attestation must be a participant, got %v",
			closed)
	}

	// …and the operator attests it powered off. Nothing has made it reachable,
	// so the attestation governs the SCAN — even though the peer still names it,
	// and even though it is still asked what it knows.
	if err := s.db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES ('fence-confirm-gone', 'gone', 'manual', 'manual-confirmed', ?, 'attested')`,
		s.db.NowWall()); err != nil {
		t.Fatalf("write fence confirmation: %v", err)
	}
	closed, unclosed, err = s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must still close — the attested host answered: %q (err %v)",
			unclosed, err)
	}
	if slices.Contains(closed, "gone") {
		t.Fatalf("a peer-named host attested off owes no runtime scan, got %v", closed)
	}
	peers, unclosed, err := s.closedInventoryCorroborationPeers(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the corroboration set must close too: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(peers, "gone") {
		t.Fatalf("an attested host still holds its replicated rows, so its digest must be "+
			"consulted, got %v", peers)
	}
}

// TestAPeersROWMayExcuseAWitnessNoRowHereRecords is what carrying the role on
// the wire buys, and it is the liveness half of this change.
//
// A witness votes and never hosts workloads, and — the operative part — it runs
// no libvirt, so a witness dragged into the RUNTIME-PROOF set answers with an
// INCOMPLETE scan and stops every reclamation. Before the role was on the wire,
// a witness whose row had not replicated here (or had been tombstoned there) was
// learned as a nameless candidate, asked for a proof it could not give, and
// wedged the sweeper with no escape but a per-host operator attestation. The row
// that names it also says what it is.
//
// It IS still asked what it knows: the membership-discovery fan-out has no role
// filter, and a witness holds the whole replicated `hosts` table. Being excused
// is about the SCAN, and the two sets are deliberately different sets — the
// assertion below is on the proof set the closure returns.
func TestAPeersROWMayExcuseAWitnessNoRowHereRecords(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host, append(workerRows("peer-b"),
			&pb.MembershipHost{Name: "a-witness", Role: "witness"}), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close: %q (err %v)", unclosed, err)
	}
	if slices.Contains(closed, "a-witness") {
		t.Fatalf("a host whose every row says `role=witness` hosts no workloads, so it must "+
			"not be asked for a runtime scan, got %v", closed)
	}
}

// TestAWitnessNamedInGOSSIPBeforeAnyROWIsStillExcused is the ordinary shape of
// the case above, and the one an order-dependent merge gets wrong.
//
// A witness IS a gossip member — it runs the daemon and votes — so this node
// names it in gossip while its ROW has not replicated here. Gossip carries no
// role, so the only role reading anywhere arrives later, from a peer. If a
// gossip naming could stand in for a row reading, the AND would treat the
// nameless candidate as "not a witness" and the peer's row could never excuse
// it: the witness would land in the proof set, be asked for an orphan proof it
// cannot complete (it runs no libvirt), and stop every reclamation the cluster
// would otherwise make.
func TestAWitnessNamedInGOSSIPBeforeAnyROWIsStillExcused(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	// This node knows the witness ONLY through gossip: no row for it here.
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "a-witness", Addr: "203.0.113.8:7946"}}
	})
	// The peer's row is the only role reading in the cluster this node can read.
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host,
			append(workerRows("peer-b"), &pb.MembershipHost{Name: "a-witness", Role: "witness"}), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close: %q (err %v)", unclosed, err)
	}
	if slices.Contains(closed, "a-witness") {
		t.Fatalf("a host gossip named before any row described it must still be excused once "+
			"a row does — being named is not a reading of its role; got %v", closed)
	}
}

// TestTwoROWSThatDisagreeAboutAWitnessKeepTheHostIN is the fail-closed half of
// the same rule.
//
// `lv host config --role` makes a role mutable, so the local row and a peer's row are the
// same replicated datum mid-flight, and there is no timestamp on the wire to
// order them. Trusting either one alone is fail-OPEN in one direction: a stale
// local `role=witness` would excuse a host that has since become a worker and is
// running the domain holding the address. A disagreement therefore resolves
// toward ASKING — a witness that gets dialled is work, a workload host that does
// not is a freed address someone is using.
func TestTwoROWSThatDisagreeAboutAWitnessKeepTheHostIN(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	// This node's row says witness…
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "contested", Address: "203.0.113.8", GRPCPort: 7443, Role: "witness",
		SSHUser: "root", SSHPort: 22, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	// Precondition, stated on the ROLE READING rather than on a participant set:
	// this node's only row for the host says witness. That reading is exactly
	// what the old code acted on — and it must NOT keep the host out of the
	// fan-out, or the peer row that contradicts it could never be read.
	if witness, known := localRoleReading(t, s, "contested"); !known || !witness {
		t.Fatalf("precondition: this node's own row must read as a witness (known %v, witness %v)",
			known, witness)
	}
	targets, err := localDiscoveryTargets(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(targets, "contested") {
		t.Fatalf("a host this node alone calls a witness must still be ASKED what it knows — "+
			"excluding it is what prevents learning the exclusion was wrong; got %v", targets)
	}

	// …and the peer's row says worker. It answers, so the set can close.
	known := localHostNames(ctx, s)
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host, workerRows(known...), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(ctx)
	if err != nil || unclosed != "" {
		t.Fatalf("the set must close: %q (err %v)", unclosed, err)
	}
	if !slices.Contains(closed, "contested") {
		t.Fatalf("two rows disagreeing about a role must leave the host IN — asking it is "+
			"work, not asking it can free an address it holds; got %v", closed)
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

	closed, unclosed, err := s.closedRuntimeProofSet(context.Background())
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
// A node knows at least itself, so an answer naming no rows is a node whose own
// `hosts` table has not hydrated — not the claim that the cluster is empty.
// Folding that in as "learned nothing new" would close the set on the one answer
// that says the peer cannot speak for the cluster either. The responder refuses
// this shape itself; this is the caller's backstop for one that claims
// completeness with nothing in it.
func TestClosedParticipantSetWithholdsOnAnEmptyMembershipView(t *testing.T) {
	s := newAdoptTestServer(t)
	seedPeerHost(t, s, "peer-b")
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		return membershipNaming(host, nil, nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(context.Background())
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
	var mu sync.Mutex
	round := 0
	peerKnows(s, func(host string) *pb.MembershipViewResponse {
		mu.Lock()
		round++
		n := round
		mu.Unlock()
		return membershipNaming(host, workerRows(fmt.Sprintf("peer-generated-%d", n)), nil)
	})

	closed, unclosed, err := s.closedRuntimeProofSet(context.Background())
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
