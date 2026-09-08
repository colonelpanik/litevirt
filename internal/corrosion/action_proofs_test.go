package corrosion

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func apTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func apInsertVM(t *testing.T, c *Client, name, host, state string) {
	t.Helper()
	now := c.NowTS()
	if err := c.Execute(context.Background(),
		`INSERT INTO vms (name, host_name, spec, state, created_at, updated_at)
		 VALUES (?, ?, '{}', ?, ?, ?)`, name, host, state, now, now); err != nil {
		t.Fatalf("insert vm: %v", err)
	}
}

func apProof(id, vm, dest string) ActionProof {
	return ActionProof{
		ID: id, Action: ActionReschedule, TargetKind: "vm", TargetName: vm,
		DestHost: dest, Coordinator: "coord-1", LeaseHolder: "coord-1",
		QuorumLive: 3, QuorumNeeded: 2,
	}
}

func TestWriteVMRescheduleProof_LinksPending(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	apInsertVM(t, c, "vm1", "host-a", "running")

	if err := WriteVMRescheduleProof(ctx, c, apProof("p1", "vm1", "host-b"), "vm1", "host-b"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}
	// VM moved to pending on the target, linked to the proof.
	vm, err := GetVM(ctx, c, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "pending" || vm.HostName != "host-b" {
		t.Fatalf("vm state/host = %q/%q; want pending/host-b", vm.State, vm.HostName)
	}
	pr, ok, err := GetActionProof(ctx, c, "p1")
	if err != nil || !ok {
		t.Fatalf("GetActionProof: ok=%v err=%v", ok, err)
	}
	if pr.Status != ProofPrepared || pr.TargetName != "vm1" || pr.DestHost != "host-b" {
		t.Fatalf("proof = %+v; want prepared/vm1/host-b", pr)
	}
}

func TestActionProof_LifecycleSingleUse(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	apInsertVM(t, c, "vm1", "host-b", "pending")
	if err := WriteVMRescheduleProof(ctx, c, apProof("p1", "vm1", "host-b"), "vm1", "host-b"); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Claim (prepared→in_progress).
	if err := ClaimActionProof(ctx, c, "p1", "host-b"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Re-claim is idempotent (in_progress→in_progress) so a retry resumes.
	if err := ClaimActionProof(ctx, c, "p1", "host-b"); err != nil {
		t.Fatalf("re-claim should be idempotent: %v", err)
	}

	// Complete: terminal + clears the pending pointer in the same mutation.
	if err := CompleteVMStartProof(ctx, c, "p1", "vm1", "host-b"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	vm, _ := GetVM(ctx, c, "vm1")
	if vm.State != "running" || vm.PendingActionID != "" {
		t.Fatalf("after complete: state=%q pending_action_id=%q; want running/empty", vm.State, vm.PendingActionID)
	}
	// Phase 4: completion is where the reschedule mints the new ownership
	// generation — claim happened at the old epoch, the increment lands in the
	// SAME mutation that clears pending, so a replayed proof is stale by
	// construction (read-old → prove → move → mint-new).
	if vm.OwnerEpoch != 1 {
		t.Fatalf("completion must mint the new owner epoch, got %d want 1", vm.OwnerEpoch)
	}

	// A completed proof can't be re-claimed → single use.
	if err := ClaimActionProof(ctx, c, "p1", "host-b"); !errors.Is(err, ErrProofSpent) {
		t.Fatalf("re-claim completed: err=%v; want ErrProofSpent", err)
	}
	// And completing again is a no-op (terminal never regresses).
	if err := CompleteVMStartProof(ctx, c, "p1", "vm1", "host-b"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("re-complete: err=%v; want ErrNoRowsAffected", err)
	}
}

// CompleteActionProof (the generic terminal used by promote/relocate) is
// single-use: a completed proof can't be re-claimed, and re-completing is a no-op.
func TestCompleteActionProof_SingleUse(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteActionProof(ctx, c, ActionProof{ID: "p1", Action: ActionPromote, TargetKind: "vm", TargetName: "vm1", DestHost: "h", Coordinator: "h"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ClaimActionProof(ctx, c, "p1", "h"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := CompleteActionProof(ctx, c, "p1", "h"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	pr, _, _ := GetActionProof(ctx, c, "p1")
	if pr.Status != ProofCompleted || pr.ExecutorHost != "h" {
		t.Fatalf("proof = %+v; want completed/executor=h", pr)
	}
	// A duplicate/retried promote with the same proof is refused (no double-promote).
	if err := ClaimActionProof(ctx, c, "p1", "h"); !errors.Is(err, ErrProofSpent) {
		t.Fatalf("re-claim completed: err=%v; want ErrProofSpent", err)
	}
	if err := CompleteActionProof(ctx, c, "p1", "h"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("re-complete: err=%v; want ErrNoRowsAffected", err)
	}
}

// A claim can't be stolen: once host-a holds an in_progress proof, host-b
// cannot re-claim it (single-holder), but host-a can (idempotent resume).
func TestClaimActionProof_SameExecutorOnly(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	apInsertVM(t, c, "vm1", "host-a", "pending")
	if err := WriteVMRescheduleProof(ctx, c, apProof("p1", "vm1", "host-a"), "vm1", "host-a"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ClaimActionProof(ctx, c, "p1", "host-a"); err != nil {
		t.Fatalf("host-a claim: %v", err)
	}
	if err := ClaimActionProof(ctx, c, "p1", "host-b"); !errors.Is(err, ErrProofSpent) {
		t.Fatalf("host-b steal: err=%v; want ErrProofSpent (single-holder)", err)
	}
	if err := ClaimActionProof(ctx, c, "p1", "host-a"); err != nil {
		t.Fatalf("host-a re-claim (idempotent resume): %v", err)
	}
}

// A reschedule proof is not minted for a VM that no longer exists (no orphan).
func TestWriteVMRescheduleProof_MissingVMRefuses(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteVMRescheduleProof(ctx, c, apProof("p1", "ghost", "host-a"), "ghost", "host-a"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("missing VM: err=%v; want ErrNoRowsAffected (no orphan proof)", err)
	}
	if _, ok, _ := GetActionProof(ctx, c, "p1"); ok {
		t.Fatal("no proof row should exist for a vanished VM")
	}
}

// The proof row and pending transition are one decision. If ownership advances
// after the coordinator's read but before this transaction, neither half may be
// written under the stale generation.
func TestWriteVMRescheduleProof_StaleOwnerEpochWritesNothing(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	apInsertVM(t, c, "vm1", "host-a", "running")
	if err := c.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
		t.Fatalf("seed owner epoch: %v", err)
	}
	p := apProof("p1", "vm1", "host-b")
	p.OwnerEpoch = "6"
	if err := WriteVMRescheduleProof(ctx, c, p, "vm1", "host-b"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("stale owner epoch: err=%v; want ErrNoRowsAffected", err)
	}
	if _, ok, _ := GetActionProof(ctx, c, "p1"); ok {
		t.Fatal("stale decision must not leave an orphan proof")
	}
	vm, _ := GetVM(ctx, c, "vm1")
	if vm == nil || vm.HostName != "host-a" || vm.State != "running" || vm.PendingActionID != "" {
		t.Fatalf("stale decision mutated VM: %+v", vm)
	}
}

// CompleteVMStartProof is atomic in BOTH preconditions: if the VM no longer
// points at the proof, neither the proof nor the VM is mutated (no half-write
// where the proof completes but the VM is untouched).
func TestCompleteVMStartProof_RequiresVMPointer(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	apInsertVM(t, c, "vm1", "host-b", "pending")
	if err := WriteVMRescheduleProof(ctx, c, apProof("p1", "vm1", "host-b"), "vm1", "host-b"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = ClaimActionProof(ctx, c, "p1", "host-b")
	// VM re-pointed away (pointer cleared) — completion must NOT apply.
	_ = c.Execute(ctx, `UPDATE vms SET pending_action_id='' WHERE name='vm1'`)

	if err := CompleteVMStartProof(ctx, c, "p1", "vm1", "host-b"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("complete with cleared pointer: err=%v; want ErrNoRowsAffected", err)
	}
	pr, _, _ := GetActionProof(ctx, c, "p1")
	if pr.Status != ProofInProgress {
		t.Fatalf("proof status=%q; want still in_progress (completion must not have applied)", pr.Status)
	}
}

// A relocation proof is found by its token (container relocation binds by token,
// not a VM pending pointer), and an absent/empty token yields no proof.
func TestGetActionProofByToken(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "p1", Action: ActionRelocate, TargetKind: "container", TargetName: "ct1",
		DestHost: "host-b", Coordinator: "coord", RelocationToken: "tok-xyz",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	pr, ok, err := GetActionProofByToken(ctx, c, "tok-xyz")
	if err != nil || !ok || pr.ID != "p1" || pr.TargetName != "ct1" {
		t.Fatalf("by-token: pr=%+v ok=%v err=%v; want p1/ct1", pr, ok, err)
	}
	if _, ok, _ := GetActionProofByToken(ctx, c, "nope"); ok {
		t.Fatal("unknown token must not resolve a proof")
	}
	if _, ok, _ := GetActionProofByToken(ctx, c, ""); ok {
		t.Fatal("empty token must not resolve a proof")
	}
}

// step_state accumulates forward-only, idempotent checkpoints for multi-step
// resume (promote: disk_built → started).
func TestAppendProofStep(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteActionProof(ctx, c, ActionProof{ID: "p1", Action: ActionPromote, TargetKind: "vm", TargetName: "vm1", DestHost: "h", Coordinator: "h"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := AppendProofStep(ctx, c, "p1", "disk_built"); err != nil {
		t.Fatalf("append disk_built: %v", err)
	}
	if err := AppendProofStep(ctx, c, "p1", "disk_built"); err != nil { // idempotent
		t.Fatalf("re-append disk_built: %v", err)
	}
	if err := AppendProofStep(ctx, c, "p1", "started"); err != nil {
		t.Fatalf("append started: %v", err)
	}
	pr, _, _ := GetActionProof(ctx, c, "p1")
	if !ProofStepDone(pr.StepState, "disk_built") || !ProofStepDone(pr.StepState, "started") {
		t.Fatalf("step_state=%q; want disk_built + started", pr.StepState)
	}
	if ProofStepDone(pr.StepState, "defined") {
		t.Fatalf("step_state=%q; must not contain an unrecorded step", pr.StepState)
	}
	if got := len(strings.Fields(pr.StepState)); got != 2 {
		t.Fatalf("step_state has %d steps (%q); want 2 (idempotent, no dup)", got, pr.StepState)
	}
}

func TestActionProof_MissingRefuses(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := ClaimActionProof(ctx, c, "nope", "host-b"); !errors.Is(err, ErrProofSpent) {
		t.Fatalf("claim missing: err=%v; want ErrProofSpent", err)
	}
}

func TestActionProof_FailIsTerminal(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	apInsertVM(t, c, "vm1", "host-b", "pending")
	_ = WriteVMRescheduleProof(ctx, c, apProof("p1", "vm1", "host-b"), "vm1", "host-b")
	_ = ClaimActionProof(ctx, c, "p1", "host-b")

	if err := FailActionProof(ctx, c, "p1", "vm1", "boot_failed", "domain define error"); err != nil {
		t.Fatalf("fail: %v", err)
	}
	pr, _, _ := GetActionProof(ctx, c, "p1")
	if pr.Status != ProofFailed || pr.ResultCode != "boot_failed" {
		t.Fatalf("proof = %+v; want failed/boot_failed", pr)
	}
	vm, _ := GetVM(ctx, c, "vm1")
	if vm.PendingActionID != "" {
		t.Fatalf("failed proof should clear pending pointer; got %q", vm.PendingActionID)
	}
	if vm.State != "error" {
		t.Fatalf("failed proof should exit pending (state=error, not markerless pending); got %q", vm.State)
	}
	// Terminal: can't claim or complete after fail.
	if err := ClaimActionProof(ctx, c, "p1", "host-b"); !errors.Is(err, ErrProofSpent) {
		t.Fatalf("claim after fail: err=%v; want ErrProofSpent", err)
	}
}

// TestActionProof_LeaseTermRoundTrips: the term must survive the write/read
// cycle. Without this the column can be added to the DDL and silently dropped
// by proofInsertParams or the GetActionProof scan, which the compiler permits.
func TestActionProof_LeaseTermRoundTrips(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	p := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 7,
	}
	if err := WriteActionProof(ctx, c, p); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok, err := GetActionProof(ctx, c, "p1")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if got.LeaseTerm != 7 {
		t.Errorf("lease_term = %d, want 7", got.LeaseTerm)
	}
}

// TestActionProof_LeaseTermDefaultsToZero: an existing row written by a
// pre-Phase-2 peer has no term. It must read back as 0 — the "pre-term proof"
// sentinel the executor refuses post-latch — and never as a valid term.
func TestActionProof_LeaseTermDefaultsToZero(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "p2", Action: ActionPromote, TargetKind: "vm", TargetName: "vm2",
		DestHost: "node-b", Coordinator: "node-a",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok, err := GetActionProof(ctx, c, "p2")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if got.LeaseTerm != 0 {
		t.Errorf("lease_term = %d on a proof minted without one, want 0", got.LeaseTerm)
	}
}

// TestSchemaV53FreshAndUpgradedColumnOrderMatch pins the reason lease_term sits
// LAST in the runtime_action_proofs CREATE TABLE, after deleted_at.
//
// The v1 state digest hashes SELECT * POSITIONALLY (sync.go tableRowKeys →
// encodeRowCells), and anti-entropy only prefers the order-invariant v2 hash
// when BOTH peers emit one (antientropy.go, useV2). ALTER TABLE always appends,
// so a column placed mid-DDL gives a freshly-initialised node a different
// physical order from an upgraded one — and those two then disagree about this
// table's digest forever, with byte-identical rows, wherever digest_v2 is off.
//
// Nothing else in the package catches that: the v44 column-order test covers
// only containers/hosts/notification_routes. Without this, the next additive
// column on this table reintroduces the divergence silently.
func TestSchemaV53FreshAndUpgradedColumnOrderMatch(t *testing.T) {
	ctx := context.Background()
	fresh := newTestDB(t)
	upgraded := newTestDB(t)

	// Rewind the upgraded DB to v52: drop the column and un-record its migration.
	if err := upgraded.execLocal(ctx,
		`ALTER TABLE runtime_action_proofs DROP COLUMN lease_term`); err != nil {
		t.Fatalf("simulate v52 drop runtime_action_proofs.lease_term: %v", err)
	}
	for _, m := range schemaMigrationLedger {
		if m.Version == 53 {
			if err := upgraded.execLocal(ctx,
				`DELETE FROM applied_migrations WHERE id = ?`, m.ID); err != nil {
				t.Fatalf("remove v53 ledger %s: %v", m.ID, err)
			}
		}
	}
	if err := upgraded.execLocal(ctx,
		`UPDATE schema_state SET version = 52 WHERE id = 1`); err != nil {
		t.Fatalf("stamp v52: %v", err)
	}
	if err := InitSchema(ctx, upgraded); err != nil {
		t.Fatalf("migrate v52 to v53: %v", err)
	}

	freshColumns := tableColumnOrder(t, fresh, "runtime_action_proofs")
	upgradedColumns := tableColumnOrder(t, upgraded, "runtime_action_proofs")
	if !slices.Equal(freshColumns, upgradedColumns) {
		t.Errorf("runtime_action_proofs column order differs — an additive column must go LAST "+
			"in the CREATE TABLE so it lands where ALTER TABLE appends it:\nfresh:    %v\nupgraded: %v",
			freshColumns, upgradedColumns)
	}
	if last := freshColumns[len(freshColumns)-1]; last != "lease_term" {
		t.Errorf("last column = %q, want lease_term", last)
	}
}
