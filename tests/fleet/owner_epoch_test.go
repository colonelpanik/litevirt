// Fleet scenarios for Phase 4 owner epochs.
//
// The equal-timestamp ownership fight, observed live on 2026-08-01: a host
// rejoins carrying a stale replica that says it still owns a VM which was in
// fact rescheduled away while it was down. Its reconciler then "syncs cluster
// state to libvirt reality" — an out-of-band stop sync — and because that
// statement's WHERE clause matched by NAME ONLY, it replicated to every peer
// and stomped the REAL owner's row (state flapped cluster-wide until a manual
// `lv doctor repair-owner`; it recurred on every rejoin). These scenarios run
// the real spine — separate per-node DBs, statements carried over real gRPC +
// mTLS + applyStatementLWW — and pin the Phase 4 property: a stale node's sync
// cannot stomp a row whose ownership generation has moved past what that node
// knows.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// epochGate is the reconciler gate for these scenarios: split-brain machinery
// active and enforced (incl. owner_epoch_v1), quorum present, not self-fenced.
// The properties under test are the statement-level epoch guards, not the
// gate's own refusals — those have their own scenarios.
type epochGate struct{}

func (epochGate) ExecutionGate(context.Context) health.GateResult { return health.GateResult{OK: true} }
func (epochGate) CapabilityActive(context.Context, string) (bool, string) {
	return true, ""
}
func (epochGate) Enforced(context.Context, string) bool { return true }
func (epochGate) SelfFenced() bool                      { return false }

// pumpMutations carries every mutation_log entry from one node to another over
// the real PushMutations RPC (real gRPC, real mTLS, real applyStatementLWW +
// mutation_seen dedup on the receiver). The fleet harness does not run the
// replicator's discovery loop (no memberlist in-process), so scenarios steer
// delivery explicitly — which is exactly what lets them model a node that
// missed an interval of history.
func pumpMutations(t *testing.T, c *Cluster, from, to *Node) {
	t.Helper()
	ctx := context.Background()
	rows, err := from.DB.Query(ctx,
		`SELECT seq, hlc, origin, stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", from.Name, err)
	}
	entries := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq:    r.Int64("seq"),
			Hlc:    r.String("hlc"),
			Origin: r.String("origin"),
			Stmts:  r.String("stmts"),
		})
	}
	if len(entries) == 0 {
		return
	}
	if _, err := c.PeerClient(from, to).PushMutations(ctx, &pb.ReplicateRequest{
		Sender:              from.Name,
		SenderVersion:       "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
		AfterSeq:            0,
		Entries:             entries,
	}); err != nil {
		t.Fatalf("push %s→%s: %v", from.Name, to.Name, err)
	}
}

// TestFleet_OwnerEpoch_StaleSyncCannotStompTheOwner reproduces the rejoin
// fight and pins its structural fix.
//
// Timeline (each node has its OWN DB; delivery is steered to model the
// partition a dead host lives through):
//
//  1. vm1 is owned by node `stale` at generation 2, replicated everywhere.
//  2. While `stale` is down, node a takes ownership (real failover would do
//     this via the proof-gated path; the transfer primitive is the same
//     epoch-CAS write): generation 2→3, host=a. Replicated to b — but NOT to
//     `stale`, which is off.
//  3. `stale` comes back. Its replica still says "vm1 is mine, running, gen 2";
//     its local domain is defined but destroyed out-of-band. Its reconciler
//     runs before anti-entropy catches it up and emits the out-of-band stop
//     sync — exactly the write observed live.
//  4. That sync replicates. THE PROPERTY: on the owner (a) and the bystander
//     (b), whose rows carry generation 3, the stale node's generation-2 sync
//     must be a no-op. Before the fix its name-only WHERE stomped them.
func TestFleet_OwnerEpoch_StaleSyncCannotStompTheOwner(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	a, b, stale := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	// (1) Ownership at generation 2 on `stale`, known cluster-wide.
	if err := corrosion.InsertVM(ctx, stale.DB, corrosion.VMRecord{
		Name: "vm1", HostName: stale.Name, State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Reach generation 2 through REGISTERED writers only — the receiver's apply
	// guard refuses ad-hoc statement shapes (it just refused this test's first
	// draft, which seeded epochs with inline SQL — the guard working as built).
	if err := corrosion.BackfillOwnerEpochs(ctx, stale.DB, stale.Name); err != nil { // 0→1
		t.Fatal(err)
	}
	if err := corrosion.TransferVMOwnerFresh(ctx, stale.DB, "vm1", stale.Name, "running"); err != nil { // 1→2
		t.Fatal(err)
	}
	pumpMutations(t, c, stale, a)
	pumpMutations(t, c, stale, b)
	if vm, _ := corrosion.GetVM(ctx, a.DB, "vm1"); vm == nil || vm.OwnerEpoch != 2 {
		t.Fatalf("seed did not replicate to a: %+v", vm)
	}

	// (2) a takes ownership at generation 3; b learns, `stale` does not.
	if err := corrosion.TransferVMOwnerFresh(ctx, a.DB, "vm1", a.Name, "running"); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	pumpMutations(t, c, a, b)
	if vm, _ := corrosion.GetVM(ctx, b.DB, "vm1"); vm == nil || vm.HostName != a.Name || vm.OwnerEpoch != 3 {
		t.Fatalf("transfer did not replicate to b: %+v", vm)
	}

	// (3) `stale` rejoins and its reconciler runs against its stale replica:
	// the domain it "owns" was destroyed out of band.
	if err := stale.Virt.DefineDomain(`<domain><name>vm1</name></domain>`); err != nil {
		t.Fatal(err)
	}
	stale.Virt.SetState("vm1", libvirtfake.StateShutdown)
	stale.Virt.SetStateReason("vm1", "destroyed")
	r := health.NewReconciler(stale.Name, t.TempDir(), stale.DB, stale.Virt)
	r.SetGate(epochGate{})
	r.ReconcileOnce(ctx)

	// The sync landed locally (the stale node believes what it believes)…
	if vm, _ := corrosion.GetVM(ctx, stale.DB, "vm1"); vm == nil || vm.State == "running" {
		t.Fatalf("stale node's local sync should have recorded the out-of-band stop locally, got %+v", vm)
	}

	// (4) …and now replicates. The owner and the bystander must be untouched.
	pumpMutations(t, c, stale, a)
	pumpMutations(t, c, stale, b)
	for _, n := range []*Node{a, b} {
		vm, _ := corrosion.GetVM(ctx, n.DB, "vm1")
		if vm == nil {
			t.Fatalf("%s: vm1 vanished", n.Name)
		}
		if vm.State != "running" || vm.HostName != a.Name || vm.OwnerEpoch != 3 {
			t.Errorf("%s: the stale node's generation-2 sync stomped the generation-3 owner row: %+v",
				n.Name, vm)
		}
	}
}

// TestFleet_OwnerEpoch_CurrentSyncStillApplies is the positive control: the
// SAME out-of-band sync from the node that genuinely owns the VM at the
// current generation must still record the stop everywhere — the guard keys
// on the generation, not on refusing syncs wholesale.
func TestFleet_OwnerEpoch_CurrentSyncStillApplies(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	owner, peer := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: "vm1", HostName: owner.Name, State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, owner.DB, owner.Name); err != nil { // 0→1
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // 1→3 via registered transfers
		if err := corrosion.TransferVMOwnerFresh(ctx, owner.DB, "vm1", owner.Name, "running"); err != nil {
			t.Fatal(err)
		}
	}
	pumpMutations(t, c, owner, peer)

	owner.Virt.DefineDomain(`<domain><name>vm1</name></domain>`)
	owner.Virt.SetState("vm1", libvirtfake.StateShutdown)
	owner.Virt.SetStateReason("vm1", "destroyed")
	r := health.NewReconciler(owner.Name, t.TempDir(), owner.DB, owner.Virt)
	r.SetGate(epochGate{})
	r.ReconcileOnce(ctx)

	pumpMutations(t, c, owner, peer)
	vm, _ := corrosion.GetVM(ctx, peer.DB, "vm1")
	if vm == nil || vm.State == "running" {
		t.Fatalf("the legitimate owner's current-generation sync must replicate: %+v", vm)
	}
	spec := map[string]any{}
	_ = json.Unmarshal([]byte(vm.Spec), &spec)
	if vm.OwnerEpoch != 3 {
		t.Fatalf("the sync must not disturb the generation: %+v", vm)
	}
}

// TestFleet_OwnerEpoch_QuorumlessRejoinDoesNotDualRun covers the OTHER live
// failure of 2026-08-01: the ~9s dual-run. A host that was down comes back
// while a VM it believes it owns is already running elsewhere, its local domain
// is gone (it rebooted), and its reconciler's "marked running but not in
// libvirt" branch restarts it — a second live copy.
//
// The pre-convergence window is the hard case: the rejoined node's row AND its
// runtime marker both still say the old generation, so nothing local
// contradicts. What holds that window is the quorum requirement — a node that
// has just rejoined and cannot reach a quorum must not take a runtime-ownership
// action from its own replica. This scenario pins that, and its control proves
// the refusal is not blanket.
func TestFleet_OwnerEpoch_QuorumlessRejoinDoesNotDualRun(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	owner, rejoined := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	// The rejoined node's stale replica: "vm1 is mine and running."
	if err := corrosion.InsertVM(ctx, rejoined.DB, corrosion.VMRecord{
		Name: "vm1", HostName: rejoined.Name, State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, rejoined.DB, rejoined.Name); err != nil {
		t.Fatal(err)
	}
	// Reality elsewhere: the owner runs it. (Not replicated to the rejoined
	// node — that is precisely the pre-convergence window.)
	owner.Virt.SetState("vm1", libvirtfake.StateRunning)

	// Its own libvirt has nothing (it rebooted): the self-heal trigger.
	r := health.NewReconciler(rejoined.Name, t.TempDir(), rejoined.DB, rejoined.Virt)
	r.SetGate(noQuorumGate{})
	r.ReconcileOnce(ctx)

	for _, e := range rejoined.Virt.EventLog() {
		if e.Domain == "vm1" && (e.Op == "define" || e.Op == "start") {
			t.Fatalf("a quorumless rejoined node started a second copy of vm1 (%s) — this is the dual-run", e.Op)
		}
	}

	// Control: with quorum restored, the same sweep proceeds — the refusal is
	// the quorum gate doing its job, not a blanket freeze.
	r.SetGate(epochGate{})
	r.ReconcileOnce(ctx)
	started := false
	for _, e := range rejoined.Virt.EventLog() {
		if e.Domain == "vm1" && (e.Op == "define" || e.Op == "start") {
			started = true
		}
	}
	if !started {
		t.Fatal("with quorum the self-heal restart must proceed (the refusal must not be blanket)")
	}
}

// noQuorumGate models a just-rejoined node: split-brain machinery latched, but
// this node cannot reach a quorum yet.
type noQuorumGate struct{ epochGate }

func (noQuorumGate) ExecutionGate(context.Context) health.GateResult {
	return health.GateResult{OK: false, Reason: health.ReasonNoQuorum}
}
