package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The UNCORROBORATED EMPTY VM READ, closed convergently.
//
// corrosion.ListVMs answers ([], nil) for a node hydrating after a database loss
// or a fresh join exactly as it does for a cluster that genuinely holds no VMs.
// No local table separates them, so the bind can neither refuse (that refuses
// the first bind on every installation) nor go live (that binds over addresses
// guests hold and NetBox will offer to the next VM). It asks the CLUSTER
// instead: every host reports its `vms` row count, and only a whole answer of
// zeroes corroborates the read. Anything else — a host that cannot be asked, a
// host that holds rows — leaves the binding SUSPENDED, serving no claim, until a
// revalidation pass can corroborate it and adopt what it finds.
//
// WHAT LIVES HERE and what lives in the fleet: these cases drive the DECISION
// and the resume, with a peer that cannot be asked (below). The proof's positive
// half — a reachable peer that genuinely holds nothing, which is every existing
// multi-node NetBox scenario — and the case where a peer holds a guest the
// binder has never heard of are in tests/fleet/netbox_unhydrated_test.go, which
// has two real daemons and a real repair path.

// seedPeerHost gives the server a SECOND host row, which is what makes an empty
// VM read uncorroborated here: the proof has to ask that host for its `vms`
// count, and the address is a reserved documentation address nothing answers on
// — so the host CANNOT BE ASKED, which is not the same as answering zero. That
// is one of the two negative branches, and the one a single-process fixture can
// produce; the other (a peer that answers a non-zero count) needs a second
// daemon and is covered in the fleet.
func seedPeerHost(t *testing.T, s *Server, name string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at)
		 VALUES (?, '203.0.113.9', 'root', 'serial', ?, ?)`,
		name, s.db.NowWall(), s.db.NowTS()); err != nil {
		t.Fatalf("seed peer host %s: %v", name, err)
	}
}

// agreeingPeer is a peer that answers GetStateDigest with THIS node's own
// digest, and nothing else.
//
// It is the positive branch of the proof, which a single-process fixture cannot
// otherwise reach: seedPeerHost's peer sits on a reserved documentation address
// nothing answers on, so every scenario built on it exercises "the host could
// not be asked". A peer that ANSWERS, and answers in agreement, is what says the
// local inventory IS the cluster's — and it has to be a real answer rather than
// a skipped check, because the whole defect being fixed here was a check that
// concluded corroboration from a local read alone.
type agreeingPeer struct {
	pb.LiteVirtClient
	digest     func() *pb.StateDigestResponse
	membership func() *pb.MembershipViewResponse
}

func (p *agreeingPeer) GetStateDigest(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return p.digest(), nil
}

// GetMembershipView is the other half of agreeing: the participant-set closure
// asks each participant which hosts IT knows of, and a peer that names the same
// ones and no new gossip members closes the set in a single round. A peer that
// agreed about every table but could not answer this would still leave the bind
// suspended — correctly, but for a reason none of these scenarios is about.
func (p *agreeingPeer) GetMembershipView(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.MembershipViewResponse, error) {
	return p.membership(), nil
}

// peerAgreesWithThisNode makes every peer answer with this node's own digest, so
// the cluster confirms the local inventory. Read at CALL time, not at wiring
// time: a scenario seeds rows after the bind, and a snapshot taken here would
// have the peer agreeing with a database that no longer exists.
func peerAgreesWithThisNode(t *testing.T, s *Server) {
	t.Helper()
	s.peerClientOverride = func(ctx context.Context, _ string) (pb.LiteVirtClient, func(), error) {
		return &agreeingPeer{digest: func() *pb.StateDigestResponse {
			digests, err := s.db.StateDigest(ctx)
			if err != nil {
				t.Errorf("local StateDigest for the peer stub: %v", err)
				return &pb.StateDigestResponse{}
			}
			resp := &pb.StateDigestResponse{HostName: "peer-b"}
			for _, d := range digests {
				resp.Tables = append(resp.Tables, &pb.TableDigest{
					Name: d.Name, Count: int32(d.Count), Hash: d.Hash, HashV2: d.HashV2,
				})
			}
			return resp
		}, membership: func() *pb.MembershipViewResponse {
			return viewLikeThisNodes(ctx, s, "peer-b")
		}}, func() {}, nil
	}
}

// TestBindOnAnUncorroboratedEmptyInventorySuspends is the hole D closes: the
// binding is recorded, and it is recorded SUSPENDED.
func TestBindOnAnUncorroboratedEmptyInventorySuspends(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("the bind must succeed — an uncorroborated read is not a refusal: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("the bind must record a binding row")
	}
	if !b.Suspended {
		t.Fatalf("a bind that could not corroborate its empty VM read must be SUSPENDED, got %+v", b)
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("the suspension must be recognisable as the uncorroborated-read one, got %q", b.SuspendReason)
	}
	// It has to say it lifts itself, or an operator reads it as work to do.
	if !strings.Contains(b.SuspendReason, "automatically") {
		t.Fatalf("the reason must say the binding resumes automatically, got %q", b.SuspendReason)
	}
}

// TestGossipNamesAPeerTheHostTableHasNotReceived is the fail-open the gossip
// half of the participant universe closes.
//
// The participant set is read from the replicated `hosts` table, so a node that
// has not received THAT table either sees only itself, concludes it stands
// alone, and corroborates its empty VM read by exhaustion — over a cluster whose
// peers hold every row it is missing. Memberlist is not CRDT state: it converges
// in seconds and independently of every table, so a peer it names is a peer that
// exists whatever the database says.
func TestGossipNamesAPeerTheHostTableHasNotReceived(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// NO host row for the peer — this node's `hosts` table is as unhydrated as
	// its `vms` table, which is the whole point.
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "peer-b", Addr: "203.0.113.9:7443"}}
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a peer known only to gossip must still have to answer for the cluster")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the uncorroborated-read one", b.SuspendReason)
	}
}

// TestAnUncorroboratedBindServesNoAllocation is why suspension is the answer at
// all: the whole point is that no address can be handed out into a prefix whose
// existing occupants are unknown.
func TestAnUncorroboratedBindServesNoAllocation(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.allocatorFor(ctx, "vm", "shared"); err == nil {
		t.Fatal("a suspended binding must refuse to produce an allocator")
	}
}

// TestBindOnACorroboratedEmptyClusterIsLiveImmediately is the property the
// existing bind tests were protecting, spelled out: with no peer there is
// nothing this node's database could be missing, so the ordinary first bind on a
// new installation stays a fast, live bind.
func TestBindOnACorroboratedEmptyClusterIsLiveImmediately(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("a peerless cluster corroborates its own empty read; the bind must be live, got %q",
			b.SuspendReason)
	}
}

// TestALocalRowDoesNotCorroborateAnInventoryWhileAPeerCannotAnswer is the
// inverse of what this file used to assert, and the correction is the point.
//
// The corroboration once short-circuited on ANY local `vms` row, tombstones
// included: a row was read as positive evidence that this database had been told
// about VMs, and the empty live read was then taken as its own answer. That
// reasoning does not survive contact with the hazard. A tombstone says this node
// once heard about ONE VM; it says nothing about the ones a peer holds right
// now, and those are the guests whose addresses a bind is about to let NetBox
// hand out again. The same short-circuit is what let a node knowing one
// unrelated VM bind over an incumbent's live address.
//
// So a local row corroborates nothing by itself. The cluster still has to
// answer, and a peer that cannot be asked leaves the binding suspended.
func TestALocalRowDoesNotCorroborateAnInventoryWhileAPeerCannotAnswer(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	seedVMInState(t, s, "was-here", "other-net", "aa:bb:cc:00:04:01", "",
		"88888888-8888-8888-8888-888888888888", "stopped")
	if err := corrosion.DeleteVM(ctx, s.db, "was-here"); err != nil {
		t.Fatalf("delete VM: %v", err)
	}

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a local tombstone is not a statement about what a peer holds; the bind must not go live")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the uncorroborated-read one", b.SuspendReason)
	}
}

// TestAdoptionRefusesAnUncorroboratedEmptyRead pins the refusal at the place
// every resume door goes through, rather than at each door.
//
// adoptExistingAddresses is "adopt everything that needs adopting", and an
// uncorroborated read means it cannot enumerate what that is. Refusing there is
// what makes the bind's own finisher, `lv netbox resume` and the re-key's tail
// all fail closed from one branch.
func TestAdoptionRefusesAnUncorroboratedEmptyRead(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	_, aerr := s.adoptExistingAddresses(ctx, corrosion.BindingRecord{
		Network: "shared", PrefixID: adoptTestPrefix, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: fp,
	}, nil)
	if !errors.Is(aerr, errAdoptionUncorroborated) {
		t.Fatalf("adoption over an uncorroborated read must refuse with the sentinel, got %v", aerr)
	}
	if !adoptionRefused(aerr) {
		t.Fatal("the refusal must be operator-actionable (FailedPrecondition), not Internal")
	}
}

// TestTheBindFinisherKeepsTheUnhydratedReason.
//
// finishAdoptionAndResume is the bind's own door. Over an uncorroborated read it
// must refuse WITHOUT rewriting the suspension's reason: the revalidation pass
// recognises exactly that reason, and a reason restated as "adoption is
// incomplete" would take the binding out of the one class of suspension that
// lifts itself.
func TestTheBindFinisherKeepsTheUnhydratedReason(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	err := s.finishAdoptionAndResume(ctx, "shared", adoptTestPrefix)
	if err == nil {
		t.Fatal("the finisher must report that the binding is suspended and why")
	}
	if !strings.Contains(err.Error(), "automatically") {
		t.Fatalf("the message must say the binding resumes automatically, got %v", err)
	}
	b, berr := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if berr != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, berr)
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("the finisher must leave the uncorroborated-read reason in place, got %q", b.SuspendReason)
	}
}

// TestTheFinisherDoesNotCallAFailedActivationWriteAnOwedAdoption is the same
// distinction at the OTHER door — the one `lv netbox resume` and the network
// create both go through.
//
// The defect was in what a NON-refusal from the activation gate is taken to
// mean, and every door took it to mean "adoption is owed". A fix verified at one
// door proves nothing about the rest, so this is what makes adoptionOwed
// non-vacuous at the finisher.
//
// THE SUSPENSION HERE IS DELIBERATELY NOT THE SELF-LIFTING ONE. This door
// short-circuits on that class before it ever reaches the gate (see
// finishAdoptionAndResume), so a scenario built on it would assert the early
// return and prove nothing about the gate at all — which is precisely the shape
// of masked test this round exists to remove. The producible sequence is the
// ordinary one: a binding suspended for drift the operator has repaired,
// `lv netbox resume`, nothing owed, and the activating write fails. What must not
// happen is the row being restated as an incomplete adoption, because the
// adoption finished.
func TestTheFinisherDoesNotCallAFailedActivationWriteAnOwedAdoption(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// A live bind (no peer, so the empty read corroborates itself), then a
	// suspension of a class this door acts on.
	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	const repairedDrift = "prefix re-CIDRed from 10.0.5.0/24 to 10.0.5.0/25"
	if err := corrosion.SuspendBinding(ctx, s.db, adoptTestPrefix, repairedDrift); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `CREATE TRIGGER fail_finisher_activation
		BEFORE UPDATE ON netbox_bindings WHEN NEW.suspended = 0
		BEGIN SELECT RAISE(ABORT, 'transient activation write failure'); END`); err != nil {
		t.Fatal(err)
	}

	err := s.finishAdoptionAndResume(ctx, "shared", adoptTestPrefix)
	if err == nil {
		t.Fatal("the finisher must report that the activation did not land")
	}
	b, berr := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if berr != nil || b == nil || !b.Suspended {
		t.Fatalf("binding row: %+v (err %v)", b, berr)
	}
	if b.SuspendReason != repairedDrift {
		t.Fatalf("the finisher rewrote a post-adoption write failure as an incomplete adoption, "+
			"which is a claim about work that finished: %q", b.SuspendReason)
	}
}

// TestRevalidationLeavesAnUnhydratedBindingSuspendedWhileStillUncorroborated:
// the pass may only resume what it can prove, so a pass that still cannot
// corroborate changes nothing.
func TestRevalidationLeavesAnUnhydratedBindingSuspendedWhileStillUncorroborated(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a pass that still cannot corroborate the empty read must not resume the binding")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("the reason must be unchanged, got %q", b.SuspendReason)
	}
}

// TestRevalidationResumesAnUnhydratedBindingOnceItCanCorroborate is the
// convergence itself: no operator action, and the binding is live again.
func TestRevalidationResumesAnUnhydratedBindingOnceItCanCorroborate(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	// The rows arrive, AND the cluster confirms they are all of them — which is
	// what corroboration now means. The arrival alone would not do it: a row this
	// node holds says nothing about the rows a peer holds.
	seedVMInState(t, s, "arrived", "other-net", "aa:bb:cc:00:05:01", "",
		"77777777-7777-7777-7777-777777777777", "running")
	peerAgreesWithThisNode(t, s)

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("the revalidation pass must resume the binding once it can corroborate, got %q",
			b.SuspendReason)
	}
}

// TestATransientActivationWriteFailureKeepsTheSuspensionSelfLifting.
//
// The activation gate's LAST step is a local write, and the two failures that
// happen after the gate has passed — a lapsed lease, and an upsert that failed —
// used to come back as plain errors. Every caller read a plain error as a failed
// ADOPTION and replaced the reason on the row with "adoption … is incomplete",
// which is a reason no pass may lift. So one transient write failure permanently
// converted the ONE self-lifting suspension in this tree into one that waits for
// an operator — and the reason text it wrote recorded, in the same sentence,
// that the adoption and the revalidation had both succeeded.
//
// The distinction is between an adoption that is OWED and an operational failure
// AFTER adoption finished. Nothing is owed here, nothing is wrong, and the row
// must keep the reason it already carries so the next pass retries by itself.
//
// The failure is injected as a trigger on the activating UPDATE and then
// removed, which is what makes it a transient rather than a permanent condition:
// the property is not "it survived one failure" but "it was still eligible for
// the automatic retry that follows".
func TestATransientActivationWriteFailureKeepsTheSuspensionSelfLifting(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	seedVMInState(t, s, "arrived", "other-net", "aa:bb:cc:00:05:01", "",
		"77777777-7777-7777-7777-777777777777", "running")
	peerAgreesWithThisNode(t, s)

	// Fail exactly the write that lifts the flag, and nothing else: the
	// predicate is `suspended = 0`, so the adoption's own writes and every
	// re-statement of a suspension still go through.
	if err := s.db.Execute(ctx, `CREATE TRIGGER fail_activation_write
		BEFORE UPDATE ON netbox_bindings WHEN NEW.suspended = 0
		BEGIN SELECT RAISE(ABORT, 'transient activation write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("a write failure on one binding must not fail the pass: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil || !b.Suspended {
		t.Fatalf("the binding must stay suspended: b=%+v err=%v", b, err)
	}
	// THE PROPERTY: the reason is untouched, so the binding is still in the
	// class the pass completes by itself.
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("a post-adoption write failure replaced the self-lifting reason with a manual "+
			"one, so no pass will ever lift it: %q", b.SuspendReason)
	}

	// The transient goes away, and the very next pass finishes the job with no
	// operator action at all.
	if err := s.db.Execute(ctx, `DROP TRIGGER fail_activation_write`); err != nil {
		t.Fatal(err)
	}
	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err = corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil || b.Suspended {
		t.Fatalf("the pass after the transient cleared must activate the binding: b=%+v err=%v",
			b, err)
	}
}

// TestRevalidationDoesNotResumeWhenALateAddressCannotBeAdopted is the half that
// makes the suspension worth having: the pass does not merely clear a flag once
// it can corroborate the read, it RUNS the adoption the bind could not — and
// leaves the binding suspended when that adoption does not complete.
//
// The address here cannot be claimed (this file's fake NetBox serves the prefix
// and VRF but no ipam address surface, so the claim's cross-check disagrees),
// which is exactly the shape a real un-claimable address produces. The adoption
// that SUCCEEDS is covered in the fleet, against a NetBox fake that allocates.
func TestRevalidationDoesNotResumeWhenALateAddressCannotBeAdopted(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	// A guest that was invisible to the bind, holding an address INSIDE the
	// bound prefix, and a cluster that now confirms this node's inventory — so
	// only the adoption can hold the resume back.
	seedVMHoldingIP(t, s, "late", "shared", "aa:bb:cc:00:06:01", "10.0.5.42",
		"66666666-6666-6666-6666-666666666666")
	peerAgreesWithThisNode(t, s)

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a pass whose adoption did not complete must not resume the binding")
	}
	// The reason has to MOVE, out of the self-lifting class and into one an
	// operator acts on: an adoption that keeps failing must not be retried
	// silently forever under a reason that says it will fix itself.
	if isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("a failed adoption must replace the self-lifting reason, got %q", b.SuspendReason)
	}
	if !strings.Contains(b.SuspendReason, "10.0.5.42") {
		t.Fatalf("the reason must name the address it could not adopt, got %q", b.SuspendReason)
	}
}

// TestRevalidationResumesWithInventoryMirroringOff.
//
// Adoption is an IPAM concern, not a mirror one: it teaches NetBox which
// addresses are already taken. Mirroring is opt-in behind its own capability
// token, and a cluster running NetBox as pure IPAM must still converge out of
// this suspension.
func TestRevalidationResumesWithInventoryMirroringOff(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	s.SetNetBoxMirrorInventory(false)
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	seedVMInState(t, s, "arrived", "other-net", "aa:bb:cc:00:07:01", "",
		"55555555-5555-5555-5555-555555555555", "running")
	peerAgreesWithThisNode(t, s)

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("adoption must not depend on the inventory mirror, got %q", b.SuspendReason)
	}
}

// TestUnhydratedSuspensionIsToldFromEveryOtherSuspension.
//
// The revalidation pass resumes exactly ONE class of suspension. If the
// predicate matched a drift reason it would lift a suspension nothing repaired;
// if it stopped matching its own writer's output it would never lift anything.
func TestUnhydratedSuspensionIsToldFromEveryOtherSuspension(t *testing.T) {
	if !isUnhydratedSuspension(unhydratedSuspendReason("net-a")) {
		t.Fatal("the predicate must match the reason its own writer produces")
	}
	for _, other := range []string{
		"",
		adoptionSuspendReason("net-a", 3),
		"cluster identity fingerprint moved: this binding is pinned to abc",
		"NetBox prefix 7 was re-CIDRed",
		"adoption of existing addresses on network net-a is incomplete after adopting 2: boom",
	} {
		if isUnhydratedSuspension(other) {
			t.Fatalf("the predicate must not match %q — it would lift a suspension nothing repaired", other)
		}
	}
}

// TestRevalidationDoesNotResumeAnUnhydratedBindingThatHasDrifted.
//
// A binding suspended for the uncorroborated read can ALSO be drifted — the
// prefix can be re-CIDRed while it waits. The pass must re-run the whole
// bind-time predicate before it resumes, and route the binding to the reason an
// operator has to act on rather than lifting the flag over a moved prefix.
func TestRevalidationDoesNotResumeAnUnhydratedBindingThatHasDrifted(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatal(err)
	}
	// The read is corroborable now, so only the drift can hold the resume back.
	seedVMInState(t, s, "arrived", "other-net", "aa:bb:cc:00:08:01", "",
		"44444444-4444-4444-4444-444444444444", "running")
	// …and the replicated `cluster` row is rewritten out of band, which is the
	// one thing that moves the fingerprint the binding is pinned to.
	if err := s.db.Execute(ctx, `UPDATE cluster SET ca_cert = ? WHERE id = 'default'`,
		"a-different-ca-cert"); err != nil {
		t.Fatalf("replace ca_cert: %v", err)
	}

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended {
		t.Fatal("a drifted binding must stay suspended")
	}
	if isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("the drift must replace the reason so an operator acts on it, got %q", b.SuspendReason)
	}
}
