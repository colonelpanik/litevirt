package netboxsync

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// ONE removal-evidence policy, and the two ways the previous one failed open.
//
// The rule both destructive VM removals obey — the vm/replace that frees a
// reused name and the ordinary vm/delete — has TWO requirements, and the round
// that produced these findings delivered only the first:
//
//  1. INCARNATION-SPECIFIC EVIDENCE. Never the name. A name is a slot; the
//     incarnation NetBox holds under it is not necessarily the one any local row
//     is about.
//  2. A JUSTIFIED CONCLUSION OF ABSENCE. Evidence that this incarnation STOPPED
//     EXISTING, not merely that this node can name it. A mapping row proves the
//     incarnation was MIRRORED — identifying the victim precisely is not
//     permission to delete it.
//
// The scenarios below are the two shapes where requirement 2 was missing, plus
// the controls that fail if the fix withholds everything instead.

// withCorroboratedInventory states, for one reconciler, that the cluster
// CONFIRMED this node's inventory read is its own — what a caught-up node's
// digest fan-out answers when every participant's address-bearing tables agree
// with it.
//
// Wired explicitly at every call site rather than defaulted in the fixture. It
// is the premise that turns a mapping row from "we mirrored this incarnation"
// into "this incarnation exists nowhere", so a scenario that depends on it has
// to say so — a fixture-wide default would make the two mapping-row scenarios
// below differ in nothing visible.
func withCorroboratedInventory(r *Reconciler) {
	withInventoryProof(r, &fixedProof{ok: true})
}

// withUncorroboratedInventory is the other half: the cluster could NOT confirm
// this node's read, which is what a node still replicating gets.
func withUncorroboratedInventory(r *Reconciler, why string) {
	withInventoryProof(r, &fixedProof{why: why})
}

// withInventoryProof makes one proof the answer this reconciler's passes get,
// through the production sampler seam.
//
// A SAMPLER, matching production, so a scenario cannot accidentally pin a shape
// the daemon does not have: the pass takes the proof before it reads anything
// and asks it later, and the tests below that count how often it was asked are
// counting what a pass actually does.
func withInventoryProof(r *Reconciler, proof InventoryProof) {
	r.inventorySnapshot = func(context.Context) InventoryProof { return proof }
}

// fixedProof is a corroboration with a predetermined answer, counting how many
// times it was asked.
type fixedProof struct {
	ok    bool
	why   string
	asked int
}

func (f *fixedProof) Corroborated(context.Context) (bool, string) {
	f.asked++
	return f.ok, f.why
}

// TestAMappingRowAloneDoesNotProveTheIncarnationStoppedExisting is finding 1.
//
// THE SHAPE: the partially hydrated leader of
// TestReplacementIsNotProvenByAnotherVMsNameUnderTheSameName, plus the
// occupant's `netbox_objects` mapping row. Replication is per TABLE, so a node
// can hold the mapping row for an incarnation whose `vms` row has not arrived —
// and the row this node's mirror wrote when it created that object is exactly
// what it holds first, because the mirror wrote it before the peer's `vms` row
// was ever replicated here.
//
// Without the mapping row the replacement is withheld, correctly. WITH it the
// incarnation premise was satisfied by a record that says the object was
// MIRRORED, and the NetBox VM was deleted — for an incarnation whose VM may be
// alive on a peer whose rows have not reached this node. Nothing about the
// mapping row speaks to whether uuid-2 still exists.
//
// Asserted on the DELETES, not on the sweep's error: freeing the name is what
// lets the colliding rename land, so the pass that removes an object it cannot
// account for goes on to report convergence. The damage is silent.
func TestAMappingRowAloneDoesNotProveTheIncarnationStoppedExisting(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	nb.enforceNames = true
	// The node is still replicating, so the cluster does not confirm its read.
	// That is the scenario, not a device: it is what a partial replica gets, and
	// it is the only thing that could turn the mapping row below into a
	// conclusion about uuid-2.
	withUncorroboratedInventory(r, "a peer holds VM rows this node has not received")
	// Two objects, so nothing else in the pass can withhold anything: vm-1
	// under uuid-1 and vm-2 under uuid-2. The occupant's interface belongs to
	// the object the replace removes, so the cascade owns it and no separate
	// nic/delete exists to withhold the parent by accident.
	nb.listVMs = nb.listVMs[:2]
	nb.listIfaces = nb.listIfaces[:2]
	// THE ONE RECORD THIS NODE HOLDS OF uuid-2: the mapping row its own mirror
	// wrote when it created object 12. No `vms` row of any kind carries uuid-2.
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-2", ""), 12)
	// …and the one local VM row: uuid-1's, renamed onto the name NetBox still
	// shows object 12 holding.
	seedHydratedVM(t, r, "vm-2", "uuid-1", macH1)

	err := r.SyncOnce(context.Background())

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a partial replica deleted VMs %v and interfaces %v on a MAPPING row alone: "+
			"that row proves this node's mirror once created the object for uuid-2, not that "+
			"uuid-2 stopped existing — its VM may be live on a peer whose `vms` rows have not "+
			"replicated here; sweep error=%v", vms, ifaces, err)
	}
}

// TestAMappingRowWithACorroboratedInventoryProvesTheRemoval is the control for
// finding 1, and the ONE premise that differs from it.
//
// Byte for byte the fixture above, with the corroboration answering yes: every
// participant's address-bearing tables agree with this node's, so no host in the
// cluster holds a `vms` row carrying uuid-2 — and a VM nobody holds a row for is
// not running anywhere. That is the justified absence the mapping row cannot
// supply on its own, and with it the replacement is right: this is the ordinary
// same-name re-create, whose `vms` tombstone InsertVMWithHardware's purge takes
// away, so the mapping row is genuinely all a caught-up node has left.
//
// Without this control, "a mapping row never authorizes anything" would satisfy
// the finding-1 regression and bring back the permanent collision stall the
// replacement exists to prevent.
func TestAMappingRowWithACorroboratedInventoryProvesTheRemoval(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	nb.enforceNames = true
	withCorroboratedInventory(r)
	nb.listVMs = nb.listVMs[:2]
	nb.listIfaces = nb.listIfaces[:2]
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-2", ""), 12)
	seedHydratedVM(t, r, "vm-2", "uuid-1", macH1)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatalf("a corroborated inventory read makes the mapping row a proven absence, so "+
			"the name must be freed and the rename must land: %v", err)
	}

	vms, _ := deletes(nb)
	if len(vms) != 1 || vms[0] != 12 {
		t.Fatalf("deleted VMs = %v, want exactly the superseded object holding the name", vms)
	}
	if got := nb.updatedName(11); got != "vm-2" {
		t.Fatalf("the survivor's object is named %q, want the freed name", got)
	}
}

// TestAnUnwiredCorroborationWithholdsAMappingOnlyRemoval pins the nil default in
// the fail-closed direction, at the gate rather than at the constructor.
//
// The mirror's other predicates are nil-safe the same way, and this one has to
// be: a wiring that forgot to thread the cluster half of the policy would
// otherwise be a mirror deleting objects on identification alone — the exact
// finding, reintroduced by omission instead of by argument.
func TestAnUnwiredCorroborationWithholdsAMappingOnlyRemoval(t *testing.T) {
	nb, r, fp := hydrationReconciler(t)
	nb.enforceNames = true
	nb.listVMs = nb.listVMs[:2]
	nb.listIfaces = nb.listIfaces[:2]
	if r.inventorySnapshot != nil {
		t.Fatal("this scenario is about the UNWIRED default; the fixture has supplied one")
	}
	seedMirroredObjectRef(t, r, netbox.Identity(fp, "uuid-2", ""), 12)
	seedHydratedVM(t, r, "vm-2", "uuid-1", macH1)

	err := r.SyncOnce(context.Background())

	if vms, ifaces := deletes(nb); len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("a mirror wired without an inventory corroboration deleted VMs %v and "+
			"interfaces %v on a mapping row alone; sweep error=%v", vms, ifaces, err)
	}
}

// TestAnOrdinaryDeleteIsNotProvenByAnotherIncarnationsTombstone is finding 2.
//
// THE SHAPE: NetBox holds vm-2 under uuid-2. The local database holds a
// tombstone at the NAME vm-2 under a DIFFERENT incarnation — uuid-2b — which is
// what a VM re-created under a reused name and then destroyed leaves behind.
// The name-keyed premise reads that tombstone as proof about whatever NetBox
// happens to hold under vm-2, so the object carrying uuid-2 is deleted and the
// sweep reports success.
//
// NetBox holds NO interface under the doomed object, deliberately. With one
// there, its nic/delete would be unprovable, and a withheld child escalates to
// withholding every destructive action in the pass — so the parent would be
// withheld by a bystander and this scenario would pass with the defect intact.
func TestAnOrdinaryDeleteIsNotProvenByAnotherIncarnationsTombstone(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	ctx := context.Background()
	nb.listVMs = nb.listVMs[:2]
	nb.listIfaces = nb.listIfaces[:1]
	// The survivor, fully accounted for.
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
	// A DIFFERENT incarnation of the name vm-2, created and destroyed. Its
	// tombstone is the only row at that name, and it carries uuid-2b.
	seedHydratedVM(t, r, "vm-2", "uuid-2b")
	if err := corrosion.DeleteVM(ctx, r.db, "vm-2"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatalf("the sweep must still run its non-destructive phases: %v", err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 0 || len(ifaces) != 0 {
		t.Fatalf("deleted VMs %v and interfaces %v: the local tombstone at the name vm-2 "+
			"carries uuid-2b, and NetBox's object there carries uuid-2 — a tombstone for one "+
			"incarnation says nothing about another that may be live on a peer", vms, ifaces)
	}
}

// TestAnOrdinaryDeleteRunsOnTheMatchingIncarnationsTombstone is the control for
// the scenario above, and the whole point of it: the ONLY difference is which
// incarnation the tombstone carries. Without it, a policy that withheld every
// delete would satisfy finding 2's regression while leaving NetBox advertising
// every VM the cluster ever destroyed.
func TestAnOrdinaryDeleteRunsOnTheMatchingIncarnationsTombstone(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	ctx := context.Background()
	nb.listVMs = nb.listVMs[:2]
	nb.listIfaces = nb.listIfaces[:1]
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
	// The MATCHING incarnation: the tombstone carries the uuid NetBox's object
	// at that name was created under.
	seedHydratedVM(t, r, "vm-2", "uuid-2")
	if err := corrosion.DeleteVM(ctx, r.db, "vm-2"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	m := mirrorSink(t, r)

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, _ := deletes(nb)
	if len(vms) != 1 || vms[0] != 12 {
		t.Fatalf("deleted VMs = %v, want exactly the object whose own incarnation this node "+
			"holds a tombstone for", vms)
	}
	if ts := m.lastSuccess(); ts.IsZero() {
		t.Fatal("a pass that accounted for every NetBox object converged and must stamp the gauge")
	}
}

// TestATemplatedIncarnationsObjectIsStillRetired is the control over the one
// state where a LIVE row still authorizes a removal.
//
// Converting a VM to a template leaves its `vms` row live and takes it out of
// the desired set — desiredState skips templates, because a template is a disk
// image and not a running machine — so the mirror has to retire the object it
// holds for it. The record is the incarnation's own live row, and the conclusion
// is not that the incarnation is absent but that the mirror must no longer
// represent it, which this node can read directly off the row.
//
// Without this, "a live row for the incarnation withholds" would strand that
// object on every sweep forever, on an ordinary operation.
func TestATemplatedIncarnationsObjectIsStillRetired(t *testing.T) {
	nb, r, _ := hydrationReconciler(t)
	ctx := context.Background()
	nb.listVMs = nb.listVMs[:1]
	nb.listIfaces = nb.listIfaces[:1]
	seedHydratedVM(t, r, "vm-1", "uuid-1", macH1)
	if err := corrosion.SetVMTemplate(ctx, r.db, "vm-1", true); err != nil {
		t.Fatalf("SetVMTemplate: %v", err)
	}

	if err := r.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	vms, ifaces := deletes(nb)
	if len(vms) != 1 || vms[0] != 11 {
		t.Fatalf("deleted VMs = %v, want the object of the incarnation this cluster turned "+
			"into a template — the mirror does not represent one, so it may not keep "+
			"advertising it", vms)
	}
	if len(ifaces) != 1 || ifaces[0] != 21 {
		t.Fatalf("deleted interfaces = %v, want the template's own", ifaces)
	}
}

// ── the policy itself, one record at a time ─────────────────────────────────

// TestVMRemovalProvenCoversEveryRecordAndAsksTheClusterForOne is the policy over
// each record the local database can hold, with the two requirements separated:
// which records are incarnation-specific enough to be considered at all, and
// which of those justify a conclusion.
//
// The evidence is read through the PRODUCTION reader over real rows written by
// production write paths, so the classification under test is the one a sweep
// gets and not a hand-built value.
func TestVMRemovalProvenCoversEveryRecordAndAsksTheClusterForOne(t *testing.T) {
	ctx := context.Background()
	r := pollingReconciler(t, &stubVirt{byIdentity: map[string][]int{}},
		Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	seedHydratedVM(t, r, "vm-live", "uuid-live", macH1)
	seedHydratedVM(t, r, "vm-template", "uuid-template", macH2)
	seedHydratedVM(t, r, "vm-gone", "uuid-gone", macH3)
	if err := corrosion.SetVMTemplate(ctx, r.db, "vm-template", true); err != nil {
		t.Fatalf("SetVMTemplate: %v", err)
	}
	if err := corrosion.DeleteVM(ctx, r.db, "vm-gone"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	mirrored := netbox.Identity("fp", "uuid-mirrored", "")
	seedMirroredObjectRef(t, r, mirrored, 12)

	known, err := corrosion.ReadMirrorEvidence(ctx, r.db)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}

	for _, tc := range []struct {
		what         string
		identity     string
		corroborated bool
		want         bool
		wantAsked    bool
		why          string
	}{
		{"a tombstone for this exact incarnation", netbox.Identity("fp", "uuid-gone", ""),
			false, true, false,
			"a destroyed incarnation's own tombstone justifies absence with no help from " +
				"the cluster, and needing help would strand every ordinary delete behind a " +
				"peer fan-out"},
		{"a live row for this exact incarnation", netbox.Identity("fp", "uuid-live", ""),
			true, false, false,
			"the incarnation EXISTS; a corroborated inventory makes that MORE certain, not " +
				"less, so corroboration must not be able to overrule it"},
		{"a live row that is a template", netbox.Identity("fp", "uuid-template", ""),
			false, true, false,
			"the mirror does not represent a template, and this node reads that off the row " +
				"it holds — no absence, and nothing to ask the cluster"},
		{"a mapping row alone, uncorroborated", mirrored, false, false, true,
			"the mapping row proves the object was MIRRORED; without the cluster confirming " +
				"this node's read, its absence from that read is not a fact about the cluster"},
		{"a mapping row alone, corroborated", mirrored, true, true, true,
			"every participant agreeing means no host holds a row for this uuid, and a VM " +
				"nobody holds a row for is running nowhere"},
		{"no record at all, corroborated", netbox.Identity("fp", "uuid-unknown", ""),
			true, false, false,
			"corroboration is the SECOND requirement, never a substitute for the first: " +
				"with no incarnation-specific record there is nothing to corroborate"},
		{"an identity carrying no uuid", "not-an-identity", true, false, false,
			"an unparseable identity names no incarnation"},
	} {
		proof := &fixedProof{ok: tc.corroborated, why: "the cluster could not confirm this read"}
		corr := r.removalCorroboration(ctx, proof)

		if got := vmRemovalProven(tc.identity, known, corr); got != tc.want {
			t.Errorf("%s: proven = %v, want %v — %s", tc.what, got, tc.want, tc.why)
		}
		if (proof.asked > 0) != tc.wantAsked {
			t.Errorf("%s: the cluster was asked %d time(s), want asked=%v. The corroboration "+
				"is a peer fan-out, so it must be reached only by the record that cannot "+
				"answer without it", tc.what, proof.asked, tc.wantAsked)
		}
		if proof.asked > 1 {
			t.Errorf("%s: the cluster was asked %d times for ONE pass; two fan-outs can "+
				"straddle a write and give two answers to one question", tc.what, proof.asked)
		}
	}
}

// TestOnePassAsksTheClusterAtMostOnce is the memoisation across CANDIDATES,
// which the table above cannot see: it builds one corroboration per row.
//
// Two mapping-only removals in one pass must share one answer. Two fan-outs can
// straddle a replicated write and disagree, which would let one object be
// removed on a whole read and another withheld on a partial one in the same
// sweep — and it is a peer round trip per object on a fleet-sized inventory.
func TestOnePassAsksTheClusterAtMostOnce(t *testing.T) {
	ctx := context.Background()
	r := pollingReconciler(t, &stubVirt{byIdentity: map[string][]int{}},
		Options{AcquireLease: leaseHeld, HoldsLease: leaseHeld})
	seedClusterRow(t, r)
	first := netbox.Identity("fp", "uuid-mirrored-a", "")
	second := netbox.Identity("fp", "uuid-mirrored-b", "")
	seedMirroredObjectRef(t, r, first, 12)
	seedMirroredObjectRef(t, r, second, 13)

	known, err := corrosion.ReadMirrorEvidence(ctx, r.db)
	if err != nil {
		t.Fatalf("ReadMirrorEvidence: %v", err)
	}
	proof := &fixedProof{ok: true}

	corr := r.removalCorroboration(ctx, proof)
	if !vmRemovalProven(first, known, corr) || !vmRemovalProven(second, known, corr) {
		t.Fatal("both mapping-only removals are corroborated and must be proven")
	}
	if proof.asked != 1 {
		t.Fatalf("the cluster was asked %d times for two candidates in one pass, want 1", proof.asked)
	}
}

// ── one policy, both paths ──────────────────────────────────────────────────

// TestBothVMRemovalsReachTheOnePolicy is the structural half, and it guards the
// shape rather than a behaviour: the two scenarios above catch a path left
// unfixed today, and this catches a SECOND ANSWER being grown tomorrow.
//
// Both findings were one destructive path deriving its own answer from the
// records — the replace from a name, then the delete from a name. So the record
// classification has exactly one reader in this package, the policy, and
// provenRemovable reaches it only through that. A path that wants to decide for
// itself has to call VMRemoval, and this fails on it.
func TestBothVMRemovalsReachTheOnePolicy(t *testing.T) {
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse the package: %v", err)
	}

	readers := map[string]int{}
	var provenRemovableCalls, policyCalls int
	for _, p := range pkg {
		for _, file := range p.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch f := call.Fun.(type) {
					case *ast.SelectorExpr:
						if f.Sel.Name == "VMRemoval" {
							readers[fn.Name.Name]++
						}
					case *ast.Ident:
						if f.Name == "vmRemovalProven" && fn.Name.Name == "provenRemovable" {
							provenRemovableCalls++
						}
						if f.Name == "vmRemovalProven" {
							policyCalls++
						}
					}
					return true
				})
			}
		}
	}

	if len(readers) != 1 || readers["vmRemovalProven"] == 0 {
		t.Fatalf("the record classification is read by %v: it must have exactly ONE reader, "+
			"vmRemovalProven. A second reader is a second policy, and a removal path with a "+
			"policy of its own is both findings this guard exists for", readers)
	}
	if provenRemovableCalls < 2 {
		t.Fatalf("provenRemovable reaches the policy %d time(s): the vm/delete branch and the "+
			"vm/replace branch must BOTH go through it, so a change to the policy cannot fix "+
			"one path and miss the other", provenRemovableCalls)
	}
	if policyCalls != provenRemovableCalls {
		t.Fatalf("the policy is called %d times, %d of them from provenRemovable: every VM "+
			"removal is gated in one place, and a caller outside it is a removal that skips "+
			"the gate", policyCalls, provenRemovableCalls)
	}
}
