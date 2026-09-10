// The proof has to certify the read that supplied the conclusion.
//
// Both consumers of the inventory corroboration have one shape: read the local
// inventory, conclude something from it, then prove the conclusion against the
// cluster. The proof used to sample its own digests when it was asked, which
// makes it a statement about the inventory AT THAT MOMENT — a different state
// from the one the conclusion came out of, whenever anything replicated in
// between. Two findings, one cause:
//
//   - the MIRROR planned a deletion from an inventory holding only its own
//     mapping row, the target's live `vms` row arrived, every peer agreed about
//     the now-complete inventory, and the old plan deleted a live VM's object;
//   - the BIND sampled between its VM enumeration and its NIC reads, so a row
//     arriving in that window was absent from the candidate list and present in
//     the digest the peers agreed with — a live binding over an address nobody
//     adopted.
//
// So a pass samples the inventory FIRST and the proof answers about that sample:
// every participant agrees with it, AND this node's own rows still are it. These
// scenarios sit on each half deliberately, which needs a peer that answers a
// chosen digest — the one thing a multi-node harness cannot do.

package grpcapi

import (
	"context"
	"go/ast"
	"go/token"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// peerAgreesLive wires every peer dial to a peer whose inventory is identical to
// this node's AT THE MOMENT IT IS ASKED, and counts the dials.
//
// That is the shape a real converged cluster has, and the shape the fleet's
// shared-database fixture has exactly: a row this node has just received is a
// row its peers hold too. It is also the only peer that can tell a bound proof
// from a freshly sampled one — a peer answering a FIXED digest disagrees with a
// moved local read all by itself, which would withhold for a reason that has
// nothing to do with the binding.
//
// THE COUNT IS THE ATTRIBUTION, and it is what the liveness scenarios below rest
// on. A proof that agreed and a proof that was never asked both leave the peers
// blameless, and only one of them is the cluster confirming anything; and in the
// other direction the change check answers BEFORE the fan-out, so a conclusion
// discarded by the binding dials nobody at all. The dial count therefore says
// WHICH HALF of the proof decided, which is not otherwise observable from
// outside it.
func peerAgreesLive(s *Server) *atomic.Int64 {
	var dials atomic.Int64
	s.peerClientOverride = func(ctx context.Context, host string) (pb.LiteVirtClient, func(), error) {
		dials.Add(1)
		digests, err := s.localTableDigests(ctx, adoptionInventoryTables())
		if err != nil {
			return nil, nil, err
		}
		var tables []*pb.TableDigest
		for _, table := range adoptionInventoryTables() {
			tables = append(tables, digestOf(digests[table]))
		}
		return &answeringPeer{tables: tables, membership: viewLikeThisNodes(ctx, s, host)},
			func() {}, nil
	}
	return &dials
}

// boundSample is the sample a production pass binds itself to, as the digests it
// holds.
//
// Taken through the production sampler rather than rebuilt here, so a scenario
// cannot be answering about a set of tables the daemon does not sample — which
// is the mistake these tests exist to catch, one level up.
func boundSample(t *testing.T, s *Server) map[string]corrosion.TableDigest {
	t.Helper()
	proof, ok := s.netboxInventorySnapshot(context.Background()).(boundInventory)
	if !ok {
		t.Fatalf("the production sampler returned %T rather than a bound sample; these "+
			"scenarios have to bind what a pass binds",
			s.netboxInventorySnapshot(context.Background()))
	}
	return proof.bound
}

// TestAConclusionIsDiscardedWhenThisNodesOwnInventoryMovesUnderIt is the half of
// the binding that peer agreement cannot supply.
//
// The peer answers with the SAMPLE — which is what a peer that has not yet
// received the row answers with, and it is a perfectly true statement about that
// sample. Meanwhile this node HAS received it. So every participant agrees about
// a read that the local database itself has already contradicted, and a
// conclusion of absence drawn from that read is about a VM this node can now see.
//
// Without the change check this is a corroborated inventory and the removal goes
// through. The withholding here comes from the binding and from nothing else:
// TestAnIrrelevantWriteDoesNotDiscardTheConclusion is the same fixture, the same
// peer and the same sample with a write that cannot change the answer, and it
// corroborates.
func TestAConclusionIsDiscardedWhenThisNodesOwnInventoryMovesUnderIt(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:20:01", "10.90.0.61",
		"55555555-5555-5555-5555-555555555555", "running")

	// The sample a pass's conclusions would be drawn from, and a peer that
	// agrees with it perfectly.
	bound := boundSample(t, s)
	peerReports(s, agreeingDigests(t, s)...)

	// Replication completes: a VM this node had no row for is now here.
	seedVMInState(t, s, "latecomer", "other-net", "aa:bb:cc:00:20:02", "10.90.0.62",
		"66666666-6666-6666-6666-666666666666", "running")

	ok, why := s.corroborateMirrorInventory(ctx, bound)
	if ok {
		t.Fatal("every peer agreed about the sample, but this node's own inventory has moved " +
			"past it: the conclusions drawn from that sample are contradicted by the local " +
			"database, and corroborating it authorizes deleting the object of a VM this node " +
			"can now see")
	}
	if !strings.Contains(why, "rows changed while the proof was being taken") {
		t.Fatalf("the reason must say the read moved, so an operator is not sent looking for "+
			"a divergent peer, got: %q", why)
	}
	if !strings.Contains(why, vmsTableName) {
		t.Fatalf("the reason must name the table that moved, got: %q", why)
	}
}

// TestAnIrrelevantWriteDoesNotDiscardTheConclusion is the negative, and it is
// not decoration: a change check scoped to the whole database would satisfy the
// scenario above and stall the mirror permanently.
//
// The write here is `netbox_objects` — the mirror's OWN mapping row, written by
// every object it creates. Every sweep on a cluster with any inventory churn
// makes one, so a proof that treated it as a moved read would never prove a
// mapping-only removal again: the removal that needs the proof would be withheld
// by the very writes the pass performs. Nothing in that table can make an absent
// VM present, which is the only question the proof answers.
func TestAnIrrelevantWriteDoesNotDiscardTheConclusion(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:21:01", "10.90.0.63",
		"77777777-7777-7777-7777-777777777777", "running")

	bound := boundSample(t, s)
	peerReports(s, agreeingDigests(t, s)...)

	// A write to a table the conclusion does not rest on.
	if err := corrosion.PutObjectRef(ctx, s.db, corrosion.ObjectRef{
		LitevirtKind: "vm", LitevirtKey: "fp:88888888-8888-8888-8888-888888888888",
		NetBoxKind: "virtual_machine", NetBoxID: 91,
	}); err != nil {
		t.Fatal(err)
	}

	ok, why := s.corroborateMirrorInventory(ctx, bound)
	if !ok {
		t.Fatalf("a write to a table outside the inventory cannot change whether a host holds "+
			"a row for an incarnation, so it must not withhold a removal — a mirror that "+
			"discarded its conclusions on its own mapping-row writes would never converge: %q",
			why)
	}
}

// TestARowInsideTheSampleDoesNotDiscardTheConclusion is the LIVENESS control
// for the write the scenario above discards on, and it is a different claim from
// the irrelevant one.
//
// Same fixture, same table, same production write — one moment EARLIER, so it is
// inside the sample rather than after it. That makes it the write most likely to
// be handled wrongly: an implementation that sampled its digests a moment too
// late, or compared the sample against a baseline older than it, would find a
// difference and withhold here too. Every removal on a cluster with any
// inventory churn would then be withheld, permanently, by arrivals the pass's own
// conclusions already account for — and it would look like the safe direction
// while being a mirror that never converges again. The irrelevant-write scenario
// cannot cover it: that one turns on the table being outside the proof's scope,
// and this row is squarely inside it.
//
// The proof is taken through the PRODUCTION sampler and asked afterwards, the
// two steps a pass does either side of reading its state, so what agrees here is
// the object the mirror actually carries.
func TestARowInsideTheSampleDoesNotDiscardTheConclusion(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	dials := peerAgreesLive(s)
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:26:01", "10.90.0.69",
		"17171717-1717-1717-1717-171717171717", "running")

	// REPLICATION COMPLETING BEFORE THE PASS BEGINS. This is the same arrival
	// the discard scenario drives, landing before the sample instead of after
	// it.
	seedVMInState(t, s, "newcomer", "other-net", "aa:bb:cc:00:26:02", "10.90.0.70",
		"18181818-1818-1818-1818-181818181818", "running")
	if got := localDigestFor(t, s, vmsTableName).Count; got != 2 {
		t.Fatalf("precondition: both rows must be in this node's inventory BEFORE it samples, "+
			"got %d vms row(s) — otherwise this scenario is not about an early arrival", got)
	}

	// The pass samples, reads its state, and asks its proof later.
	proof := s.NetBoxInventorySnapshotOnce(ctx)
	ok, why := proof.Corroborated(ctx)

	if !ok {
		t.Fatalf("a row that arrived before the digests were collected is IN the sample the "+
			"conclusions were drawn from, so it cannot be a read that moved under them; "+
			"withholding here withholds every removal on any cluster whose inventory "+
			"changes at all: %q", why)
	}
	if n := dials.Load(); n == 0 {
		t.Fatal("no peer was asked, so this corroboration is not the one production runs: the " +
			"binding check must pass the sample THROUGH to the fan-out, and a proof that " +
			"agreed without asking anybody would agree with a divergent cluster too")
	}
}

// TestABoundProofIsNotAFreshOne pins the binding at the point a caller could
// undo it by accident: an empty sample.
//
// A proof that answered from a fresh read when handed nothing would be the
// defect exactly, reintroduced by a caller that forgot to sample — and it would
// look like a healthy cluster, because a fresh read agrees with the peers it was
// just compared against.
func TestABoundProofIsNotAFreshOne(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:22:01", "10.90.0.64",
		"99999999-9999-9999-9999-999999999999", "running")
	peerReports(s, agreeingDigests(t, s)...)

	if ok, why := s.corroborateMirrorInventory(ctx, nil); ok {
		t.Fatalf("with no sample there is no conclusion to certify, so nothing may be "+
			"corroborated; got ok with reason %q", why)
	}
	if ok, _ := s.corroborateMirrorInventory(ctx, map[string]corrosion.TableDigest{}); ok {
		t.Fatal("an empty sample is not a read this proof can answer for")
	}
}

// TestBindDoesNotGoLiveOnAPlanThatMissedARowEveryPeerHoldsNow is the same
// finding on the bind, which is where the corroboration was reused from.
//
// The bind's proof was taken part-way through planAdoption: after the VM
// enumeration the candidate list is built from, before the per-VM NIC reads. A
// `vms` row arriving in that window is therefore absent from the candidates and
// PRESENT in the digest — so every peer agrees, the read looks whole, and the
// binding goes live having never seen the address that guest holds. NetBox then
// offers it to the next VM created there, which is the collision the whole
// adoption step exists to prevent.
//
// The row lands through the production write path in the production window (see
// SetOnInventoryRead). Either safe outcome is acceptable and both are the same
// one here: the binding is suspended under the self-lifting reason, and the
// revalidation pass re-plans from a fresh sample.
//
// WHICH HALF OF THE PROOF WITHHELD IT IS ASSERTED, and it has to be, because a
// live-agreeing peer is not the neutral bystander it looks like: the fan-out is
// handed the BOUND sample, so a peer answering with this node's rows as they
// stand now necessarily disagrees with a sample taken before the arrival — and
// it withholds this bind all by itself, with the local change check deleted. The
// dial count is what tells the two apart: the change check answers BEFORE the
// fan-out, so a plan discarded by the binding asks no peer at all.
func TestBindDoesNotGoLiveOnAPlanThatMissedARowEveryPeerHoldsNow(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	dials := peerAgreesLive(s)

	// The binder's own world: one VM, on a network with nothing to do with the
	// prefix. Enough that no check keyed on an empty read is what answers.
	seedVMInState(t, s, "unrelated", "other-net", "aa:bb:cc:00:23:01", "10.90.0.65",
		"12121212-1212-1212-1212-121212121212", "running")

	// THE INCUMBENT, replicating in after the enumeration this plan is built
	// from: a running guest holding an address inside the prefix being bound.
	var arrived bool
	s.SetOnInventoryRead(func() {
		if arrived {
			return // one arrival, not one per plan: the resume re-plans too
		}
		arrived = true
		seedVMInState(t, s, "incumbent", "shared", "aa:bb:cc:00:23:02", "10.0.5.44",
			"13131313-1313-1313-1313-131313131313", "running")
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Logf("bind refused safely: %v", err)
	}
	if !arrived {
		t.Fatal("the plan never reached its inventory read, so this scenario proves nothing " +
			"about the window after it")
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		return // refused before claiming the prefix: nothing is live
	}
	if !b.Suspended {
		t.Fatal("the adoption plan was enumerated before the incumbent's row arrived, so its " +
			"address was never adopted; a live binding then hands that running guest's " +
			"address to the next VM created on this network")
	}
	if !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("reason = %q, want the uncorroborated-read one the revalidation pass lifts "+
			"by itself — a plan whose inputs moved is re-derived, not repaired by an operator",
			b.SuspendReason)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("the discarded plan dialled %d peer(s), so what withheld it is the peer half "+
			"disagreeing with the bound sample — which it does whatever the local change check "+
			"says, and this scenario is about the change check", n)
	}
}

// TestABindGoesLiveOnceTheRowThatDiscardedItIsInsideTheSample is the bind's
// liveness half, and it is what makes the scenario above a DELAY rather than a
// stall.
//
// ONE row, TWO passes, and the difference between them is only when it arrived.
// It lands inside the first plan's window — after the enumeration that plan is
// built from — so that plan's sample does not carry it and the plan is
// discarded, correctly. By the second pass the same row is older than everything
// that pass reads, its digests included: the plan and the proof are one read
// again, they agree about the row, and the binding has to GO LIVE. An
// implementation that sampled after its reads, or compared its sample against
// anything older than itself, would keep discarding — a prefix suspended for as
// long as the cluster keeps creating VMs, with no operator action that could
// finish it, which is the cost of reading this binding as safety alone.
//
// The row is outside the bound prefix, so there is nothing to adopt in either
// pass and the only question left is whether the read can be certified — the
// binding is live or it is suspended under the uncorroborated reason, with no
// third outcome to confuse the two.
//
// WHAT WITHHELD THE FIRST PASS IS ASSERTED, not assumed: the change check
// answers before the fan-out, so a plan discarded by the binding dials no peer
// at all, and a first pass that had asked the cluster would be suspended for the
// peer half's reasons instead — which would make the resume below a statement
// about a different gate. The resume is asserted the same way from the other
// side: the pass that goes live must have ASKED somebody.
func TestABindGoesLiveOnceTheRowThatDiscardedItIsInsideTheSample(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()
	seedPeerHost(t, s, "peer-b")
	dials := peerAgreesLive(s)

	// The binder's own world: one VM on a network with nothing to do with the
	// prefix, so no check keyed on an empty read is what answers here.
	seedVMInState(t, s, "unrelated", "other-net", "aa:bb:cc:00:27:01", "10.90.0.71",
		"19191919-1919-1919-1919-191919191919", "running")

	// THE ARRIVAL, once, inside the first plan's window. One-shot deliberately:
	// the second pass re-plans, and a row landing in ITS window too would make
	// this a scenario about an endlessly moving inventory rather than about a
	// read that has settled.
	var arrived bool
	s.SetOnInventoryRead(func() {
		if arrived {
			return
		}
		arrived = true
		seedVMInState(t, s, "newcomer", "other-net", "aa:bb:cc:00:27:02", "10.90.0.72",
			"20202020-2020-2020-2020-202020202020", "running")
	})

	if err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef); err != nil {
		t.Fatalf("a plan whose read moved leaves the binding suspended; it does not refuse the "+
			"bind: %v", err)
	}
	if !arrived {
		t.Fatal("the plan never reached its inventory read, so nothing arrived in the window " +
			"the first pass is supposed to discard on")
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if !b.Suspended || !isUnhydratedSuspension(b.SuspendReason) {
		t.Fatalf("the first pass must be discarded by the binding — suspended=%v reason=%q; "+
			"without that this scenario never reaches the state whose self-clearing is the "+
			"property under test", b.Suspended, b.SuspendReason)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("the discarded plan dialled %d peer(s): the change check answers before the "+
			"fan-out, so either the peer half is what withheld this pass or that order has "+
			"changed — and the resume below would then be about a different gate", n)
	}

	// THE NEXT PASS, over a read that has settled.
	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("revalidation pass: %v", err)
	}
	b, err = corrosion.GetBindingByPrefix(ctx, s.db, adoptTestPrefix)
	if err != nil || b == nil {
		t.Fatalf("binding row: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("the row arrived before this pass collected its digests, so it is inside the "+
			"sample the plan was built from and the cluster agrees about it: the binding must "+
			"be live, got %q. A binding still suspended here is one no arrival can ever "+
			"finish, because every arrival looks like a read that moved", b.SuspendReason)
	}
	if dials.Load() == 0 {
		t.Fatal("the binding went live without the cluster ever being asked: the resume has to " +
			"come from a corroborated read, and a pass that dialled nobody would resume over " +
			"an unhydrated inventory just as happily")
	}
}

// TestOneSpellingOfWhetherTheReadMoved pins the two consumers onto the shared
// comparison, from the side an AST guard cannot see: the ANSWER.
//
// Both proofs have to treat the same movement the same way, because they are one
// mechanism asked from two directions (see
// TestTheMirrorsRemovalProofIsTheBindsInventoryProof). A second comparison would
// most likely differ by a table — which is how the peer half of this proof came
// to disagree with the sweeper's three times.
func TestOneSpellingOfWhetherTheReadMoved(t *testing.T) {
	s := newAdoptTestServer(t)
	seedVMInState(t, s, "known", "other-net", "aa:bb:cc:00:24:01", "10.90.0.66",
		"14141414-1414-1414-1414-141414141414", "running")

	bound := boundSample(t, s)
	for _, table := range adoptionInventoryTables() {
		moved := bound[table]
		moved.Count++
		changed := map[string]corrosion.TableDigest{}
		for k, v := range bound {
			changed[k] = v
		}
		changed[table] = moved
		if why := inventoryMoved(changed, bound); !strings.Contains(why, table) {
			t.Fatalf("a change to %s must be reported as a moved read naming that table, got %q",
				table, why)
		}
	}
	if why := inventoryMoved(bound, bound); why != "" {
		t.Fatalf("an unchanged read must compare equal, got %q", why)
	}
	// A count that matches under a different hash is a REPLACED row, and it
	// moves the read as surely as an added one.
	sameCount := map[string]corrosion.TableDigest{}
	for k, v := range bound {
		sameCount[k] = v
	}
	rehashed := sameCount[vmsTableName]
	rehashed.Hash, rehashed.HashV2 = "a-different-table", "a-different-table"
	sameCount[vmsTableName] = rehashed
	if why := inventoryMoved(sameCount, bound); why == "" {
		t.Fatal("the same number of DIFFERENT rows is a moved read; comparing counts alone is " +
			"the mistake the peer half of this proof already made")
	}
	// A sample missing a table cannot be certified, in either direction.
	missing := map[string]corrosion.TableDigest{}
	for k, v := range bound {
		if k != vmsTableName {
			missing[k] = v
		}
	}
	if why := inventoryMoved(missing, bound); why == "" {
		t.Fatal("a sample carrying no vms digest has nothing to be corroborated against")
	}
	if why := inventoryMoved(bound, missing); why == "" {
		t.Fatal("a node that can no longer digest vms cannot confirm the sample is still its own")
	}
}

// TestTheAdoptionPlanSamplesItsInventoryBeforeItReadsAnything is the bind's half
// of the ordering, pinned where behaviour cannot reach it.
//
// The window the scenario above drives is one hook wide. What makes it narrow is
// the ORDER of four reads and two calls inside one function, and any edit that
// moves the sample down past a read — or the proof up above one — reopens it
// silently: every existing scenario still passes, because on a quiet fixture the
// sample and the reads see the same rows.
//
// So the positions are asserted directly: the sample precedes every read the
// candidate list is built from, and the corroboration follows all of them.
func TestTheAdoptionPlanSamplesItsInventoryBeforeItReadsAnything(t *testing.T) {
	fset := token.NewFileSet()
	funcs := parseFuncs(t, fset, "netbox_adopt.go")
	plan, ok := funcs["planAdoption"]
	if !ok {
		t.Fatal("planAdoption is gone: it is where the adoption plan and its proof are bound " +
			"to one read")
	}
	sample := firstCall(t, plan, "localTableDigests")
	// Every read that goes INTO the plan, in the order the function makes them.
	// A read added here without being covered is a read the proof does not
	// certify, which is the defect one table at a time.
	for _, read := range []string{
		"ListLeasesByNetwork", "ListContainerInterfacesByNetwork", "ListVMs", "MergedVMNICs",
	} {
		first := firstCall(t, plan, read)
		if first < sample {
			t.Errorf("planAdoption reads %s BEFORE it samples the inventory digests: a row "+
				"arriving between that read and the sample is absent from the plan and "+
				"present in the digest every peer agrees with, which is a live binding over "+
				"an address nobody adopted", read)
		}
		if last := lastCall(t, plan, read); last > firstCall(t, plan, "corroborateAdoptionInventory") {
			t.Errorf("planAdoption reads %s AFTER it corroborates: the proof must cover every "+
				"read the plan rests on", read)
		}
	}

	prove, ok := funcs["corroborateAdoptionInventory"]
	if !ok {
		t.Fatal("corroborateAdoptionInventory is gone")
	}
	if !slices.Contains(functionsCalled(prove), "inventoryMoved") {
		t.Fatal("corroborateAdoptionInventory no longer checks whether the read moved under " +
			"the plan; peer agreement about a sample this node has already passed is not a " +
			"statement about the plan built from it")
	}
	if arg := soleDigestArgOf(t, prove, "proveNoPeerHoldsInventoryRowsWeLack"); arg != "bound" {
		t.Fatalf("corroborateAdoptionInventory proves %q against the peers, want the BOUND "+
			"sample the plan was built from", arg)
	}
}

// firstCall and lastCall are the positions of the calls to `name` inside fn.
// They fail the test when there are none, so a renamed read is a failure to fix
// rather than a guard that quietly covers nothing.
func firstCall(t *testing.T, fn *ast.FuncDecl, name string) token.Pos {
	t.Helper()
	if pos := callPositions(fn, name); len(pos) > 0 {
		return pos[0]
	}
	t.Fatalf("%s no longer calls %s", fn.Name.Name, name)
	return 0
}

func lastCall(t *testing.T, fn *ast.FuncDecl, name string) token.Pos {
	t.Helper()
	if pos := callPositions(fn, name); len(pos) > 0 {
		return pos[len(pos)-1]
	}
	t.Fatalf("%s no longer calls %s", fn.Name.Name, name)
	return 0
}

// callPositions is where fn calls `name`, in source order.
func callPositions(fn *ast.FuncDecl, name string) []token.Pos {
	var out []token.Pos
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				out = append(out, call.Lparen)
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				out = append(out, call.Lparen)
			}
		}
		return true
	})
	slices.Sort(out)
	return out
}
