package corrosion

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
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

// TestActionProof_PreV52ShapeStillAppliesAndReadsAsTermless is a COMPATIBILITY
// test, not a plumbing one. It inserts through the pre-v53 22-column proof shape
// — the one a not-yet-upgraded peer still emits, retained as
// proof_insert_pre_lease_term_v51 in HistoricalShapes() — and requires it to
// (a) still apply against the v52 schema and (b) yield the termless sentinel.
//
// READ THIS BEFORE COUNTING IT AS COVERAGE. The 0 assertion is UNFALSIFIABLE by
// any mutation of the lease_term plumbing, and an earlier version of this test
// was written as though it were not. It used WriteActionProof with LeaseTerm
// unset and asserted the read-back was 0 — which passes with lease_term deleted
// from proofInsertParams AND from the GetActionProof SELECT, because Row.Int64
// maps an absent column to 0 and the column DEFAULT is also 0. Verified by
// mutation: the column was removed from both paths and this test still passed.
// A reviewer caught it; the mutation table had only ever mapped mutations onto
// LeaseTermRoundTrips, which is where the plumbing coverage actually lives.
//
// What this version does buy, which the old one did not: it is the only place
// the DEFAULT is on the path at all. Change the ALTER to NOT NULL without a
// default, or let the historical shape stop applying, and this goes red.
func TestActionProof_PreV52ShapeStillAppliesAndReadsAsTermless(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)

	// The pre-v53 shape verbatim: 22 columns, no lease_term. execLocal, because
	// this is a receive-side compatibility contract, not something to replicate.
	if err := c.execLocal(ctx,
		`INSERT OR IGNORE INTO runtime_action_proofs
			(id, action, target_kind, target_name, dest_host, coordinator, lease_holder, lease_expires_at,
			 quorum_live, quorum_needed, owner_epoch, fence_epoch, relocation_token,
			 status, step_state, result_code, result_detail, started_at, completed_at, executor_host,
			 created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', '', '', '', '', '', '', ?, ?)`,
		"p2", ActionPromote, "vm", "vm2", "node-b", "node-a", "", "", 0, 0, "", "", "",
		c.NowTS(), c.NowTS()); err != nil {
		t.Fatalf("apply the pre-v53 proof shape against a v53 schema: %v — a supported peer "+
			"still emits this and a receiver that cannot apply it back-pressures that peer's "+
			"whole stream", err)
	}

	// Ask SQL whether the cell is NULL, rather than reading it through Row.Int64.
	// This is the only assertion here that any mutation can reach. Row.Int64 maps
	// BOTH an absent column and a SQL NULL to 0, so through the accessor a column
	// declared `INTEGER` with no default is indistinguishable from
	// `INTEGER NOT NULL DEFAULT 0` — verified by mutation, which is how a SECOND
	// vacuous version of this test was caught after the first one was fixed.
	//
	// It matters beyond tidiness: 0 is the enforcement sentinel for "minted
	// without a term". If the column can arrive NULL, a proof with no term and a
	// proof whose term failed to decode both read as 0, and the executor cannot
	// tell a pre-v53 peer from a broken one.
	rows, err := c.Query(ctx,
		`SELECT lease_term IS NULL AS is_null, lease_term AS term
		   FROM runtime_action_proofs WHERE id = 'p2'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read lease_term column: err=%v rows=%d", err, len(rows))
	}
	if rows[0].Int("is_null") != 0 {
		t.Errorf("the pre-v53 shape left lease_term NULL; it must take a non-NULL DEFAULT 0, " +
			"or the termless sentinel is indistinguishable from a decode failure")
	}
	if n := rows[0].Int64("term"); n != 0 {
		t.Errorf("the pre-v53 shape left lease_term = %d, want the DEFAULT 0", n)
	}

	got, ok, err := GetActionProof(ctx, c, "p2")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if got.LeaseTerm != 0 {
		t.Errorf("lease_term = %d on a proof minted without one, want 0", got.LeaseTerm)
	}
}

// TestProofsFreshAndUpgradedColumnOrderMatch pins the reason every additive
// runtime_action_proofs column sits LAST in the CREATE TABLE, after deleted_at.
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
func TestProofsFreshAndUpgradedColumnOrderMatch(t *testing.T) {
	ctx := context.Background()
	fresh := newTestDB(t)
	upgraded := newTestDB(t)

	// Rewind the upgraded DB to v52: drop both additive columns and un-record
	// their migrations. Dropped in REVERSE order so each drop is the table's
	// last column, which is what an upgrade never has to do and what makes the
	// re-migration exercise the real append order.
	for _, col := range []string{"lease_key", "lease_term"} {
		if err := upgraded.execLocal(ctx,
			`ALTER TABLE runtime_action_proofs DROP COLUMN `+col); err != nil {
			t.Fatalf("simulate v52 drop runtime_action_proofs.%s: %v", col, err)
		}
	}
	for _, m := range schemaMigrationLedger {
		if m.Version == 53 || m.Version == 54 {
			if err := upgraded.execLocal(ctx,
				`DELETE FROM applied_migrations WHERE id = ?`, m.ID); err != nil {
				t.Fatalf("remove v53/v54 ledger %s: %v", m.ID, err)
			}
		}
	}
	if err := upgraded.execLocal(ctx,
		`UPDATE schema_state SET version = 52 WHERE id = 1`); err != nil {
		t.Fatalf("stamp v52: %v", err)
	}
	if err := InitSchema(ctx, upgraded); err != nil {
		t.Fatalf("migrate v52 to v54: %v", err)
	}

	freshColumns := tableColumnOrder(t, fresh, "runtime_action_proofs")
	upgradedColumns := tableColumnOrder(t, upgraded, "runtime_action_proofs")
	if !slices.Equal(freshColumns, upgradedColumns) {
		t.Errorf("runtime_action_proofs column order differs — an additive column must go LAST "+
			"in the CREATE TABLE so it lands where ALTER TABLE appends it:\nfresh:    %v\nupgraded: %v",
			freshColumns, upgradedColumns)
	}
	// The additive columns, in the order the ALTERs append them. Pinned as a
	// SUFFIX rather than "lease_term is last", which had to change the moment
	// v53 added another one — and the property was never about a particular
	// column, only about additive columns going after deleted_at.
	wantSuffix := []string{"deleted_at", "lease_term", "lease_key"}
	got := freshColumns[len(freshColumns)-len(wantSuffix):]
	if !slices.Equal(got, wantSuffix) {
		t.Errorf("the table's trailing columns are %v, want %v — an additive column must go "+
			"LAST in the CREATE TABLE, after deleted_at, in ALTER order", got, wantSuffix)
	}
}

// TestWriteActionProofValidated_ADivergentSeedIsNotReplicated is the point of
// the task, and it asserts on mutation_log rather than on the returned error.
//
// The error was ALREADY correct before this change, which is exactly why the
// hole went unnoticed: claimCarriedProof seeded the row from the untrusted proof
// and only then compared it, so the validating node refused correctly while the
// forged statement had already been committed to mutation_log and queued for
// every peer. ExecuteBatchGuarded writes mutation_log INSIDE the transaction and
// logs the whole batch — not only the statements that changed a row — so an
// INSERT OR IGNORE that is a local no-op still relays.
func TestWriteActionProofValidated_ADivergentSeedIsNotReplicated(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)

	// The genuine row, as the coordinator minted it.
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 3,
	}); err != nil {
		t.Fatalf("seed genuine: %v", err)
	}
	before := mutationLogCount(t, c)

	// A peer presents the same id at term 9.
	err := WriteActionProofValidated(ctx, c, ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 9,
	})
	if !errors.Is(err, ErrProofDiverges) {
		t.Fatalf("err = %v, want ErrProofDiverges", err)
	}
	if after := mutationLogCount(t, c); after != before {
		t.Errorf("a refused divergent proof queued %d statement(s) for replication; a peer that "+
			"has not yet received the genuine row would apply the forged term, and the real row "+
			"would then be dropped on the PK by INSERT OR IGNORE", after-before)
	}
	if got, _, _ := GetActionProof(ctx, c, "p1"); got.LeaseTerm != 3 {
		t.Errorf("local lease_term = %d, want the genuine 3", got.LeaseTerm)
	}
}

// TestWriteActionProofValidated_AMatchingProofSeedsAndReplicates: the ordinary
// path, and the reason this cannot simply refuse when no row exists. The
// coordinator's replicated row routinely arrives AFTER the direct RPC carrying
// the proof, so the carried fields must be able to seed it — and that write must
// replicate, or a peer never learns the proof at all.
func TestWriteActionProofValidated_AMatchingProofSeedsAndReplicates(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	before := mutationLogCount(t, c)

	p := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 5,
	}
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatalf("seed a fresh proof: %v", err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Error("the seeding write did not replicate; a peer would never learn the proof")
	}
	got, ok, _ := GetActionProof(ctx, c, "p1")
	if !ok || got.LeaseTerm != 5 {
		t.Fatalf("seeded proof = %+v, want term 5", got)
	}

	// A retry, and a replicated copy of the coordinator's own row, both land
	// here: an IDENTICAL proof is a no-op success, never a divergence. Treating
	// it as one would refuse every retried RPC.
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Errorf("re-presenting an identical proof failed: %v — a retry and a replicated "+
			"identical row must both be accepted", err)
	}
}

// TestProofBindingEqual_IgnoresTheEvidenceOnlyFields. lease_holder,
// lease_expires_at, quorum_live and quorum_needed are an honesty record the
// coordinator PERSISTS and does not carry — leaseSnapshot deliberately returns
// "" on a read error rather than fabricating a holder — so binding them would
// refuse valid proofs. The authorization-bearing fields are bound; the evidence
// is not.
func TestProofBindingEqual_IgnoresTheEvidenceOnlyFields(t *testing.T) {
	base := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 5,
	}
	withEvidence := base
	withEvidence.LeaseHolder = "node-a"
	withEvidence.LeaseExpiresAt = "2026-09-08T12:00:30Z"
	withEvidence.QuorumLive, withEvidence.QuorumNeeded = 3, 2
	if !ProofBindingEqual(base, withEvidence) {
		t.Error("the evidence-only fields are bound; a proof whose LeaseHolder is empty (the " +
			"documented behaviour on a read error) would be refused")
	}

	for name, mutate := range map[string]func(*ActionProof){
		"action":           func(p *ActionProof) { p.Action = ActionPromote },
		"target_kind":      func(p *ActionProof) { p.TargetKind = "container" },
		"target_name":      func(p *ActionProof) { p.TargetName = "vm2" },
		"dest_host":        func(p *ActionProof) { p.DestHost = "node-z" },
		"coordinator":      func(p *ActionProof) { p.Coordinator = "node-z" },
		"relocation_token": func(p *ActionProof) { p.RelocationToken = "tok" },
		"fence_epoch":      func(p *ActionProof) { p.FenceEpoch = "host=x;fence_id=1;ts=t" },
		"owner_epoch":      func(p *ActionProof) { p.OwnerEpoch = "7" },
		"lease_term":       func(p *ActionProof) { p.LeaseTerm = 9 },
	} {
		other := base
		mutate(&other)
		if ProofBindingEqual(base, other) {
			t.Errorf("%s is not part of the binding; a divergent same-id row could differ on it "+
				"and still be claimed", name)
		}
	}
}

// TestActionProof_LeaseKeyRoundTrips: same hazard as lease_term — the column can
// be added to the DDL and dropped by the insert params or the scan, and the
// compiler permits both.
//
// Unlike the termless test, this assertion IS falsifiable through the accessor,
// because a real key is a non-empty string and Row.String's failure value is "".
// That asymmetry is the whole reason lease_term needed a SQL-level NULL check
// and this does not.
func TestActionProof_LeaseKeyRoundTrips(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok, err := GetActionProof(ctx, c, "p1")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if got.LeaseKey != LeaseKeyFailover {
		t.Errorf("lease_key = %q, want %q", got.LeaseKey, LeaseKeyFailover)
	}
	if got.LeaseTerm != 7 {
		t.Errorf("lease_term = %d, want 7 — adding a column must not shift the others", got.LeaseTerm)
	}
}

// TestProofBindingEqual_BindsTheLeaseKey. A term is only interpretable together
// with its key, so a divergent same-id row differing ONLY on the key must be
// refused: term 4 under the rebalancer's ledger and term 4 under the failover
// coordinator's are different authorizations that happen to share a number.
func TestProofBindingEqual_BindsTheLeaseKey(t *testing.T) {
	base := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 4, LeaseKey: LeaseKeyFailover,
	}
	other := base
	other.LeaseKey = LeaseKeyRebalancer
	if ProofBindingEqual(base, other) {
		t.Error("two proofs differing only on lease_key compared equal; the same term number " +
			"under two different ledgers would be interchangeable")
	}
}

// TestWriteActionProofValidated_ADivergentLeaseKeyIsRefused closes the loop
// through the writer: the key must be part of the binding at the seed boundary
// too, not only at the executor, or a divergent key is persisted and relayed.
func TestWriteActionProofValidated_ADivergentLeaseKeyIsRefused(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 4, LeaseKey: LeaseKeyFailover,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := mutationLogCount(t, c)

	err := WriteActionProofValidated(ctx, c, ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 4, LeaseKey: LeaseKeyRebalancer,
	})
	if !errors.Is(err, ErrProofDiverges) {
		t.Fatalf("err = %v, want ErrProofDiverges", err)
	}
	if after := mutationLogCount(t, c); after != before {
		t.Errorf("the refused proof queued %d statement(s) for replication", after-before)
	}
}

// TestWriteActionProofValidated_AnIdenticalKeyedProofIsAccepted closes the gap a
// mutation found: the "identical row is a no-op success" property was only ever
// tested with an EMPTY lease_key.
//
// Dropping lease_key from the guard's SELECT leaves existing.LeaseKey always "",
// which still refuses a divergent key — so the divergence test passes — but
// wrongly refuses a valid retry of a proof that HAS a key. Since a retried RPC
// and the coordinator's own replicated row both take this path, that would fail
// every keyed proof-gated action closed on its second delivery.
func TestWriteActionProofValidated_AnIdenticalKeyedProofIsAccepted(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	p := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a", LeaseTerm: 4, LeaseKey: LeaseKeyFailover,
	}
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatalf("seed a keyed proof: %v", err)
	}
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatalf("re-presenting an IDENTICAL keyed proof was refused: %v — a retry and the "+
			"coordinator's own replicated row both land here, so this fails every keyed action "+
			"closed on second delivery", err)
	}
	got, ok, _ := GetActionProof(ctx, c, "p1")
	if !ok || got.LeaseKey != LeaseKeyFailover || got.LeaseTerm != 4 {
		t.Errorf("proof after the retry = %+v, want term 4 under %q", got, LeaseKeyFailover)
	}
}

// TestWriteActionProofValidated_ATombstonedRowStillBinds: a tombstone occupies
// the primary key, so its facts must bind exactly as a live row's do.
//
// The guard used to filter `deleted_at IS NULL`, and ReapSpentProofs tombstones
// every completed or failed proof and never hard-deletes — so every id ever
// spent was a permanently open hole. The guard saw no row, returned true, and
// the presented INSERT was relayed to every peer even though it no-ops locally
// on the PK. A peer that never received the genuine row applies the forged one
// at status 'prepared', and WriteActionProofValidated reports success with
// nothing persisted locally.
func TestWriteActionProofValidated_ATombstonedRowStillBinds(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	base := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "host-b", Coordinator: "node-a", LeaseTerm: 3, LeaseKey: LeaseKeyFailover,
	}
	if err := WriteActionProof(ctx, c, base); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Reaped, exactly as ReapSpentProofs leaves it.
	if err := c.Execute(ctx,
		`UPDATE runtime_action_proofs SET deleted_at = ? WHERE id = ?`, c.NowTS(), "p1"); err != nil {
		t.Fatalf("tombstone: %v", err)
	}

	before := mutationLogCount(t, c)
	forged := base
	forged.LeaseTerm = 9
	err := WriteActionProofValidated(ctx, c, forged)
	if !errors.Is(err, ErrProofDiverges) {
		t.Fatalf("err = %v, want ErrProofDiverges: a reaped id must not be a hole through which "+
			"a forged proof reaches every peer", err)
	}
	if after := mutationLogCount(t, c); after != before {
		t.Errorf("the refused proof wrote %d mutation_log row(s); a refusal must write nothing "+
			"AND log nothing, or peers apply the forged row", after-before)
	}
}

// TestClaimActionProofFenced_ConcurrentClaimantsRace runs the two claimants
// concurrently. Exactly one must win.
//
// A read-then-claim implementation passes every sequential test and fails this
// one: both goroutines read "no conflicting claim" before either writes.
// -race does not catch it either — there is no data race, just a lost update.
// The NOT EXISTS lives inside the claim's own UPDATE for this reason.
func TestClaimActionProofFenced_ConcurrentClaimantsRace(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	claimants := []struct{ id, coordinator string }{
		{"p-a", "node-a"}, {"p-z", "node-z"},
	}
	for _, tc := range claimants {
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: tc.id, Action: ActionReschedule, TargetKind: "vm", TargetName: tc.id,
			DestHost: "node-b", Coordinator: tc.coordinator,
			LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
		}); err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, len(claimants))
	start := make(chan struct{})
	for i, tc := range claimants {
		wg.Add(1)
		go func(i int, id, coordinator string) {
			defer wg.Done()
			<-start
			errs[i] = ClaimActionProofFenced(ctx, c, id, "node-b",
				&TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: coordinator})
		}(i, tc.id, tc.coordinator)
	}
	close(start)
	wg.Wait()

	var won int
	for _, err := range errs {
		if err == nil {
			won++
		}
	}
	// Deliberately NOT `won <= 1`, which passes when the fence refuses everyone
	// — the failure mode that would silently break every failover.
	if won != 1 {
		t.Fatalf("%d of 2 competing claimants at term 7 won the claim, want exactly 1 "+
			"(errs: %v) — a read before the claim lets both through", won, errs)
	}
}

// TestClaimActionProofFenced_AnotherExecutorsClaimDoesNotFenceThisOne: the
// guarantee is PER-EXECUTOR. Another host having acted at this term says
// nothing about what this host may do, and matching any host's claim would let
// one node's action fence the whole fleet.
func TestClaimActionProofFenced_AnotherExecutorsClaimDoesNotFenceThisOne(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	for _, tc := range []struct{ id, coordinator string }{
		{"p-elsewhere", "node-a"}, {"p-here", "node-z"},
	} {
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: tc.id, Action: ActionReschedule, TargetKind: "vm", TargetName: tc.id,
			DestHost: "node-b", Coordinator: tc.coordinator,
			LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
		}); err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
	}

	// A DIFFERENT executor claims node-a's proof at term 7.
	if err := ClaimActionProofFenced(ctx, c, "p-elsewhere", "node-OTHER",
		&TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: "node-a"}); err != nil {
		t.Fatalf("the other executor's claim: %v", err)
	}

	// This executor has bound nothing yet, so node-z's proof must claim.
	if err := ClaimActionProofFenced(ctx, c, "p-here", "node-b",
		&TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: "node-z"}); err != nil {
		t.Errorf("this executor was fenced by ANOTHER host's claim at term 7: %v — the "+
			"binding is per-executor, and a fleet-wide one would refuse every second "+
			"coordinator's work", err)
	}
}

// TestClaimActionProofFenced_IsScopedToItsLeaseKey: a claim at one lease's term
// must not fence a proof minted under a different lease at the same number.
//
// The three leases allocate terms independently, so their numbers COLLIDE by
// design — that is what TestLeaseTermHolder_IsScopedToItsKey pins one layer
// down. claimProofFencedSQL therefore scopes its NOT EXISTS by (lease_term,
// lease_key), and the key half is the half with nothing else backing it: drop it
// and the conflict subquery still reads perfectly plausibly, still passes every
// other fenced-claim test, and quietly refuses a legitimate rebalancer proof at
// term 7 because an unrelated failover proof at term 7 was claimed on this host.
// The operator-facing failure is the worst kind: ErrTermClaimantConflict names a
// split-brain that never happened.
//
// Both claims land on ONE executor deliberately. A different executor is already
// covered by _AnotherExecutorsClaimDoesNotFenceThisOne, and using two here would
// let the per-executor half of the binding carry the test on its own.
func TestClaimActionProofFenced_IsScopedToItsLeaseKey(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)

	for _, tc := range []struct{ id, coordinator, key string }{
		{"p-failover", "node-a", LeaseKeyFailover},
		{"p-rebalance", "node-z", LeaseKeyRebalancer},
	} {
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: tc.id, Action: ActionReschedule, TargetKind: "vm", TargetName: tc.id,
			DestHost: "node-b", Coordinator: tc.coordinator,
			LeaseTerm: 7, LeaseKey: tc.key,
		}); err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
	}

	// This executor binds itself to node-a for (failover, 7).
	if err := ClaimActionProofFenced(ctx, c, "p-failover", "node-b",
		&TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: "node-a"}); err != nil {
		t.Fatalf("the failover claim at term 7: %v", err)
	}

	// The rebalancer's term 7 is a different tenure of a different lease, so the
	// binding above says nothing about it.
	err := ClaimActionProofFenced(ctx, c, "p-rebalance", "node-b",
		&TermFence{Key: LeaseKeyRebalancer, Term: 7, Coordinator: "node-z"})
	if errors.Is(err, ErrTermClaimantConflict) {
		t.Fatalf("a rebalancer proof at term 7 was refused as a claimant conflict because an "+
			"unrelated FAILOVER proof at term 7 was claimed on this executor: %v — the "+
			"three ledgers advance independently, so this reports a split-brain that "+
			"never happened and strands legitimate work", err)
	}
	if err != nil {
		t.Fatalf("the rebalancer claim at term 7: %v", err)
	}
}

// TestWriteActionProof_PreLatchEmitsTheReleasedShape: mid-roll, a proof must go
// on the wire in the shape a previous-release peer can resolve.
//
// Widening insertProofSQL with lease_term and lease_key moved its fingerprint,
// and a fingerprint is a property of the BINARY, not of the schema. A peer on
// the previous release holds only the narrow one, so it cannot resolve the
// widened form: applyStatementLWW rejects it, the batch rolls back, and that
// peer's replication watermark stalls — head-of-line blocking the stream into
// it. Nothing prevented this. A proof write is gated by split_brain_gate_v1,
// which such a peer DOES advertise, so peerLacksProofSupport is false and
// dropUnsupportedProofEntries never fires; and runtime_action_proofs sits in
// stmtshapecheck's replicatedTableBaseline, so the first-shape guard skips the
// table altogether. Proofs mint far more often than lease terms.
//
// The assertion is on the mutation_log payload rather than on the row, because
// the row is identical either way — that is the point of the DEFAULTs, and it
// is also why nothing local can detect the problem.
func TestWriteActionProof_PreLatchEmitsTheReleasedShape(t *testing.T) {
	ctx := context.Background()

	emitted := func(t *testing.T, open bool) string {
		t.Helper()
		c := apTestClient(t)
		c.SetLeaseTermLedgerGate(func() bool { return open })
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
			DestHost: "node-b", Coordinator: "node-a",
			LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
		}); err != nil {
			t.Fatalf("WriteActionProof: %v", err)
		}
		var stmts string
		if err := c.db.QueryRow(
			`SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`).Scan(&stmts); err != nil {
			t.Fatalf("read mutation_log: %v", err)
		}
		return stmts
	}

	t.Run("gate closed emits the narrow shape", func(t *testing.T) {
		got := emitted(t, false)
		if strings.Contains(got, "lease_term") || strings.Contains(got, "lease_key") {
			t.Errorf("the replicated proof insert names the term columns while the ledger "+
				"latch is unformed, so its fingerprint is one a previous-release peer "+
				"cannot resolve — that peer's apply fails closed and its whole "+
				"replication stream stalls. Emitted:\n%s", got)
		}
	})

	t.Run("gate open emits the widened shape", func(t *testing.T) {
		got := emitted(t, true)
		if !strings.Contains(got, "lease_term") || !strings.Contains(got, "lease_key") {
			t.Errorf("the term columns are absent once every peer can decode them, so a "+
				"proof can never carry its fencing term. Emitted:\n%s", got)
		}
	})
}

// TestClaimActionProofFenced_ReapedClaimStillFences: garbage collection must not
// erase the fence.
//
// ReapSpentProofs tombstones terminal proofs on AGE alone — default 24h — and
// says nothing about whether their lease term is still current. A leader that
// holds its lease longer than the retention window is ordinary on a stable
// cluster, so the binding this executor formed at a still-live term aged out
// from under it. With the conflict subquery filtering deleted_at, the reap then
// let a SECOND coordinator at that same live term claim on a host that had
// already executed for the first — one host acting for two claimants of one
// tenure, which is the split the fence is the last line against.
//
// The proof is a consumable and the tombstone rightly makes it inert as one.
// The claim it records is EVIDENCE, and spending the proof is what creates the
// evidence, so a fence that ignores spent rows ignores nearly all of it.
func TestClaimActionProofFenced_ReapedClaimStillFences(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	for _, tc := range []struct{ id, coordinator string }{
		{"p-first", "node-a"}, {"p-second", "node-z"},
	} {
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: tc.id, Action: ActionReschedule, TargetKind: "vm", TargetName: tc.id,
			DestHost: "node-b", Coordinator: tc.coordinator,
			LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
		}); err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
	}

	// node-b executes for node-a at term 7 and the action finishes.
	if err := ClaimActionProofFenced(ctx, c, "p-first", "node-b",
		&TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: "node-a"}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, err := c.db.Exec(
		`UPDATE runtime_action_proofs SET status = 'completed' WHERE id = ?`, "p-first"); err != nil {
		t.Fatalf("terminalise p-first: %v", err)
	}

	// Retention elapses. The lease has NOT moved: term 7 is still current.
	n, err := ReapSpentProofs(ctx, c, 0)
	if err != nil {
		t.Fatalf("ReapSpentProofs: %v", err)
	}
	if n != 1 {
		t.Fatalf("reaped %d proofs, want 1 — the test needs the tombstone to exist", n)
	}

	err = ClaimActionProofFenced(ctx, c, "p-second", "node-b",
		&TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: "node-z"})
	if !errors.Is(err, ErrTermClaimantConflict) {
		t.Errorf("second claimant at the same live term got %v, want ErrTermClaimantConflict; "+
			"node-b already executed for node-a at (failover, 7), and reaping that proof "+
			"does not un-execute it", err)
	}
}

// TestClaimActionProofFenced_ANilFenceIsTodaysClaim: the pre-latch path must be
// byte-identical, and ClaimActionProof delegates here with nil.
func TestClaimActionProofFenced_ANilFenceIsTodaysClaim(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	for _, id := range []string{"p-a", "p-z"} {
		coordinator := "node-" + id[2:]
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: id, Action: ActionReschedule, TargetKind: "vm", TargetName: id,
			DestHost: "node-b", Coordinator: coordinator,
			LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	// Two competing claimants at one term BOTH claim when unfenced — that is
	// today's behaviour, and the rollout depends on it being unchanged.
	if err := ClaimActionProof(ctx, c, "p-a", "node-b"); err != nil {
		t.Fatalf("p-a: %v", err)
	}
	if err := ClaimActionProof(ctx, c, "p-z", "node-b"); err != nil {
		t.Errorf("p-z refused with no fence: %v — the unfenced claim must be exactly today's", err)
	}
}
