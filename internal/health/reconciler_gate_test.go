package health

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

type fakeGate struct {
	exec   GateResult
	active bool
	fenced bool
}

func (f fakeGate) ExecutionGate(context.Context) GateResult { return f.exec }
func (f fakeGate) CapabilityActive(context.Context, string) (bool, string) {
	if f.active {
		return true, ""
	}
	return false, ReasonActivationUnconfirm
}
func (f fakeGate) Enforced(context.Context, string) bool { return f.active }
func (f fakeGate) SelfFenced() bool                      { return f.fenced }

// mutableGate lets a test flip ExecutionGate between refuse (no quorum) and allow
// mid-test, to exercise the "gate refused, retried once quorum returns" path.
type mutableGate struct {
	mu     sync.Mutex
	execOK bool
	active bool
	fenced bool
}

func (g *mutableGate) setExecOK(ok bool) { g.mu.Lock(); g.execOK = ok; g.mu.Unlock() }
func (g *mutableGate) ExecutionGate(context.Context) GateResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.execOK {
		return GateResult{OK: true}
	}
	return GateResult{OK: false, Reason: ReasonNoQuorum}
}
func (g *mutableGate) CapabilityActive(context.Context, string) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active {
		return true, ""
	}
	return false, ReasonActivationUnconfirm
}
func (g *mutableGate) Enforced(context.Context, string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active
}
func (g *mutableGate) SelfFenced() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fenced
}

func startedOrDefined(fake *libvirtfake.Fake, name string) bool {
	for _, e := range fake.EventLog() {
		if e.Domain == name && (e.Op == "start" || e.Op == "define") {
			return true
		}
	}
	return false
}

// A pending VM carrying a proof marker is started only after the proof is
// claimed, and the proof is completed (single-use) with the pointer cleared.
func TestStartPendingVM_ProofHappyPath(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Coordinator decide-side: proof row + pending link in one batch.
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if !startedOrDefined(fake, "vm1") {
		t.Fatal("vm1 should have been started")
	}
	pr, ok, _ := corrosion.GetActionProof(ctx, db, "p1")
	if !ok || pr.Status != corrosion.ProofCompleted {
		t.Fatalf("proof status = %q (ok=%v); want completed", pr.Status, ok)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm.State != "running" || vm.PendingActionID != "" {
		t.Fatalf("vm state/pointer = %q/%q; want running/empty", vm.State, vm.PendingActionID)
	}
}

// A pending VM carrying a proof MARKER must run the ExecutionGate even when local
// enforcement is NOT latched (active=false): an asymmetric partition can deliver a
// valid marker to a target that itself lacks quorum, and it must not start. The
// proof stays unclaimed (the gate refuses before the claim).
func TestStartPendingVM_MarkerForcesExecutionGate(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")

	var refused []string
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	// NOT latched locally (active=false), but a marker is present and quorum is absent.
	r.SetGate(fakeGate{exec: GateResult{OK: false, Reason: ReasonNoQuorum}, active: false})
	r.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a proof marker must force the ExecutionGate even when enforcement isn't latched locally")
	}
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofPrepared {
		t.Fatalf("proof status=%q; want prepared (unclaimed — gate refused before the claim)", pr.Status)
	}
	if len(refused) != 1 || refused[0] != ReasonNoQuorum {
		t.Fatalf("refusal=%v; want [no_quorum]", refused)
	}
}

// A self-fenced node refuses a MARKERLESS, UNENFORCED start — the exact gap the
// per-loop legacy path left open: split_brain_gate_v1 is NOT latched (active=false) and
// there is no proof marker, so without the unconditional self-fence hard gate this would
// take the legacy (ungated) path and start the VM during the fence-timeout window.
// vip_demote_v1 (whose demote-failure path can self-fence when a watchdog is armed)
// latches independently of the Phase-1 gate.
func TestStartPendingVM_SelfFencedRefusesMarkerlessUnenforced(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	// A plain running VM assigned here (no pending_action_id, no proof) — the markerless
	// local-recovery/onboot start shape.
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	var refused []string
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	// Self-fenced, NOT enforced, ExecutionGate would even pass — the legacy path would
	// otherwise skip the gate entirely.
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: false, fenced: true})
	r.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a self-fenced node must not start a VM even on the markerless/unenforced legacy path")
	}
	if len(refused) != 1 || refused[0] != ReasonSelfFenced {
		t.Fatalf("refusal=%v; want [self_fenced]", refused)
	}
}

// Defense-in-depth: a pending VM carrying a proof marker with NO gate wired fails
// CLOSED — we can't verify quorum, and a marker implies enforcement was active when
// it was stamped. (Production wires the gate before the reconcile loops.)
func TestStartPendingVM_MarkerNilGateFailsClosed(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake) // NO gate wired

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a proof marker with no gate wired must fail closed (no start)")
	}
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofPrepared {
		t.Fatalf("proof status=%q; want prepared (unclaimed — refused before claim)", pr.Status)
	}
}

// Post-activation, a PENDING row with no proof marker is a stale / pre-activation /
// hand-mutated ownership transfer — it must be refused (proof_missing), even on a
// quorum-holding worker, never started proof-less.
func TestStartPendingVM_EnforcedMarkerlessPendingRefused(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil) // no pending_action_id

	var refused []string
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true}) // enforced + quorum held
	r.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("an enforced markerless PENDING start must be refused (proof_missing), not started")
	}
	if len(refused) != 1 || refused[0] != ReasonProofMissing {
		t.Fatalf("refusal=%v; want [proof_missing]", refused)
	}
}

// Pre-activation (not latched), a markerless pending row still starts via the legacy
// path — the proof_missing refusal is post-activation only.
func TestStartPendingVM_UnenforcedMarkerlessPendingLegacyStarts(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil)

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: false}) // NOT enforced → legacy

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if !startedOrDefined(fake, "vm1") {
		t.Fatal("pre-activation markerless pending must start via the legacy path")
	}
}

// A markerless "starting" row post-activation is a LOCAL start (onboot / domain-died
// recovery / crashed-mid-start), NOT an ownership transfer — it proceeds under the
// ExecutionGate and is NOT refused as proof_missing (which would strand recovery).
func TestStartPendingVM_EnforcedMarkerlessStartingAllowed(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "starting"}, nil, nil)

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true}) // enforced + quorum held

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if !startedOrDefined(fake, "vm1") {
		t.Fatal("a markerless starting re-drive must proceed under the ExecutionGate (local start), not be refused")
	}
}

// A VM stranded in "starting" (its start succeeded in libvirt but the final DB
// write / proof completion failed, or a daemon crashed mid-start) is recovered by
// the reconcile "starting" case: the already-running domain completes the proof and
// heals the row to running — no in_progress-proof + starting strand.
func TestReconcile_StartingWithRunningDomain_Heals(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")
	// Model the strand: proof claimed (in_progress), VM left in "starting".
	_ = corrosion.ClaimActionProof(ctx, db, "p1", "node-a")
	_ = db.Execute(ctx, `UPDATE vms SET state='starting', updated_at=? WHERE name='vm1'`, db.NowTS())

	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning) // domain already up (start had succeeded)
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	r.reconcile(ctx) // the "starting" case re-drives startPendingVM

	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm.State != "running" || vm.PendingActionID != "" {
		t.Fatalf("vm state/pointer=%q/%q; want running/'' (healed from starting)", vm.State, vm.PendingActionID)
	}
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofCompleted {
		t.Fatalf("proof status=%q; want completed (retried by the starting-case re-drive)", pr.Status)
	}
}

// Terminal-disagreement repair is STRICT: a `completed`⊕`failed` split must not be silently
// "repaired" by flipping failed→completed off a half-complete artifact. Here THIS host's
// proof is terminal `failed` (e.g. AE-merged from the host where the start failed) but the
// VM row still carries the marker and a domain happens to be running. startPendingVM must
// REFUSE at the single-use claim (the proof is spent) — a running domain must NOT complete a
// terminal failed proof. The split is left for AE/operator to resolve; no silent flip.
func TestStartPendingVM_FailedProofNotFlippedByRunningDomain(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")
	// Terminalize the proof to `failed` WITHOUT touching the VM row (empty vmName), so the
	// marker stays intact — modelling a failed⊕completed split where THIS side recorded failed.
	if err := corrosion.FailActionProof(ctx, db, "p1", "", "remote_failed", "simulated split"); err != nil {
		t.Fatal(err)
	}
	_ = db.Execute(ctx, `UPDATE vms SET state='starting', updated_at=? WHERE name='vm1'`, db.NowTS())

	var refused []string
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning) // the half-complete artifact: domain is up
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	r.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	// The failed proof must NOT be flipped to completed off the running domain.
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofFailed {
		t.Fatalf("proof status=%q; want failed (a running domain must NOT flip a terminal failed proof to completed)", pr.Status)
	}
	// Refused at the single-use claim; the marker is left intact for AE/operator repair.
	if len(refused) != 1 || refused[0] != ReasonProofTerminal {
		t.Fatalf("refusal=%v; want [proof_terminal]", refused)
	}
	if vm, _ := corrosion.GetVM(ctx, db, "vm1"); vm.PendingActionID != "p1" {
		t.Fatalf("pending_action_id=%q; want p1 (untouched — no silent completion)", vm.PendingActionID)
	}
}

// A TRANSIENT local failure (libvirt start hiccup) during a proof-gated start must
// NOT strand the proof: the VM reverts to pending (reconcile retries) and the proof
// stays in_progress (the same executor re-claims it) — never in_progress+error.
func TestStartPendingVM_TransientFailureRetryable(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")

	fake := libvirtfake.New()
	fake.FailStartDomain = func(string) error { return errFakeStart } // transient libvirt failure
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	// VM reverted to pending (retryable), NOT error.
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm.State != "pending" {
		t.Fatalf("vm state=%q; want pending (retryable after transient failure)", vm.State)
	}
	if vm.PendingActionID != "p1" {
		t.Fatalf("pending_action_id=%q; want p1 (still linked for retry)", vm.PendingActionID)
	}
	// Proof stays in_progress (claimed by us — the retry re-claims idempotently).
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofInProgress {
		t.Fatalf("proof status=%q; want in_progress (not stranded/terminal on a transient failure)", pr.Status)
	}
}

// A NON-retryable local failure (invalid spec JSON) during a proof-gated start
// terminalizes the proof (failed) and sets the VM to error with the pointer cleared
// — no in_progress strand, and no marker-less pending row.
func TestStartPendingVM_NonRetryableTerminalizes(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{not valid json", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm.State != "error" || vm.PendingActionID != "" {
		t.Fatalf("vm state/pointer=%q/%q; want error/'' (terminalized, pointer cleared)", vm.State, vm.PendingActionID)
	}
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofFailed {
		t.Fatalf("proof status=%q; want failed (terminal on a non-retryable failure)", pr.Status)
	}
}

// ExecutionGate refusal blocks the start entirely (nothing reaches libvirt) and
// leaves the proof unclaimed for a later retry.
func TestStartPendingVM_GateRefusesNoStart(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")

	var refused []string
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: false, Reason: ReasonNoQuorum}, active: true})
	r.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("gate refusal must prevent any start/define")
	}
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofPrepared {
		t.Fatalf("proof status = %q; want still prepared (unclaimed)", pr.Status)
	}
	if len(refused) != 1 || refused[0] != ReasonNoQuorum {
		t.Fatalf("refusal metric = %v; want [no_quorum]", refused)
	}
}

// A pending row pointing at a proof minted for a DIFFERENT VM must refuse — a
// proof id can only authorize the start it was minted for.
func TestStartPendingVM_ProofTargetMismatchRefuses(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	// Proof p1 targets a DIFFERENT vm ("other"); vm1 anomalously points at it.
	_ = corrosion.WriteActionProof(ctx, db, corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule,
		TargetKind: "vm", TargetName: "other", DestHost: "node-a", Coordinator: "node-a"})
	now := db.NowTS()
	_ = db.Execute(ctx, `UPDATE vms SET state='pending', pending_action_id='p1', updated_at=? WHERE name='vm1'`, now)

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a proof minted for another VM must not authorize vm1's start")
	}
	// The mismatched proof must remain unclaimed (prepared).
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofPrepared {
		t.Fatalf("proof status=%q; want prepared (unclaimed)", pr.Status)
	}
}

// A pending row whose linked proof is already terminal must refuse (single-use):
// the anomaly of a lingering pointer to a spent proof never re-runs the start.
func TestStartPendingVM_SpentProofRefuses(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	_ = corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil)
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	_ = corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a")
	_ = corrosion.ClaimActionProof(ctx, db, "p1", "node-a")
	// Force the proof terminal while (anomalously) leaving the VM pointer set.
	now := db.NowTS()
	_ = db.Execute(ctx, `UPDATE runtime_action_proofs SET status='completed', updated_at=? WHERE id='p1'`, now)
	_ = db.Execute(ctx, `UPDATE vms SET pending_action_id='p1', updated_at=? WHERE name='vm1'`, now)

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})

	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a spent (terminal) proof must not authorize a start")
	}
}

// An onboot autostart the gate refuses (enforced, no quorum) is NOT permanently
// stranded: it is remembered and reconcile() retries it, starting once quorum
// returns. A VM that is not onboot is never autostarted by the retry.
func TestStartOnbootVMs_GateRefusalRetriedByReconcile(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	// vm-onboot should autostart at boot; vm-plain is a plain stopped VM that must
	// never be autostarted (it never enters the onboot retry set).
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-onboot", HostName: "node-a", Spec: `{"onboot":true}`, State: "stopped"}, nil, nil); err != nil {
		t.Fatalf("InsertVM onboot: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-plain", HostName: "node-a", Spec: `{}`, State: "stopped"}, nil, nil); err != nil {
		t.Fatalf("InsertVM plain: %v", err)
	}

	fake := libvirtfake.New()
	gate := &mutableGate{active: true, execOK: false} // enforced, but no quorum yet
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(gate)

	// Boot-time pass: gate refuses → nothing starts, but the onboot VM is remembered.
	r.StartOnbootVMs(ctx)
	if startedOrDefined(fake, "vm-onboot") {
		t.Fatal("onboot VM must not start while the gate refuses (no quorum)")
	}
	r.onbootMu.Lock()
	_, remembered := r.onbootPending["vm-onboot"]
	r.onbootMu.Unlock()
	if !remembered {
		t.Fatal("a gate-refused onboot VM must be remembered for retry")
	}

	// Quorum returns; a reconcile tick retries the remembered onboot start.
	gate.setExecOK(true)
	r.reconcile(ctx)
	if !startedOrDefined(fake, "vm-onboot") {
		t.Fatal("onboot VM should start once quorum returns")
	}
	if startedOrDefined(fake, "vm-plain") {
		t.Fatal("a non-onboot stopped VM must never be autostarted by the retry")
	}
	// Duty discharged → dropped from the retry set.
	r.onbootMu.Lock()
	_, still := r.onbootPending["vm-onboot"]
	r.onbootMu.Unlock()
	if still {
		t.Fatal("a started onboot VM must be dropped from the retry set")
	}
}

// The onboot retry honors operator intent that changed WHILE quorum was absent: a
// VM the operator stopped, or whose onboot flag was cleared, must not be started
// when quorum returns — the stale remembered snapshot must not override it.
func TestOnbootRetry_DropsOnOperatorIntentChange(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-opstop", HostName: "node-a", Spec: `{"onboot":true}`, State: "stopped"}, nil, nil); err != nil {
		t.Fatalf("InsertVM opstop: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm-disabled", HostName: "node-a", Spec: `{"onboot":true}`, State: "stopped"}, nil, nil); err != nil {
		t.Fatalf("InsertVM disabled: %v", err)
	}

	fake := libvirtfake.New()
	gate := &mutableGate{active: true, execOK: false} // enforced, no quorum yet
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(gate)

	r.StartOnbootVMs(ctx) // gate refuses → both remembered

	// Operator changes intent while quorum is absent: stop one, disable onboot on the other.
	now := db.NowTS()
	if err := db.Execute(ctx, `UPDATE vms SET state_detail='operator-stop', updated_at=? WHERE name='vm-opstop'`, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET spec='{"onboot":false}', updated_at=? WHERE name='vm-disabled'`, now); err != nil {
		t.Fatal(err)
	}

	// Quorum returns; the retry must honor the NEW intent (start neither, drop both).
	gate.setExecOK(true)
	r.reconcile(ctx)

	if startedOrDefined(fake, "vm-opstop") {
		t.Fatal("operator-stopped VM must not be autostarted by the onboot retry")
	}
	if startedOrDefined(fake, "vm-disabled") {
		t.Fatal("a VM whose onboot was disabled must not be autostarted by the retry")
	}
	r.onbootMu.Lock()
	n := len(r.onbootPending)
	r.onbootMu.Unlock()
	if n != 0 {
		t.Fatalf("onbootPending should be drained (both dropped on intent change), have %d", n)
	}
}

// A pending VM whose proof id can't be read/found (GC'd / never replicated / hand-mutated
// pointer) must be REFUSED, not started — ClaimActionProof matches only by id+status, so
// skipping validation on a read error/miss would start it unvalidated (fail-open double-run).
func TestStartPendingVM_ProofUnreadableRefuses(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending", PendingActionID: "ghost"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)
	if startedOrDefined(fake, "vm1") {
		t.Fatal("a VM whose proof can't be read/found must NOT be started (fail closed)")
	}
	if vm, _ := corrosion.GetVM(ctx, db, "vm1"); vm.State == "running" {
		t.Fatalf("vm must not be marked running; state=%q", vm.State)
	}
}
