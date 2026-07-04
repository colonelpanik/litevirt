package corrosion

import (
	"context"
	"errors"
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
