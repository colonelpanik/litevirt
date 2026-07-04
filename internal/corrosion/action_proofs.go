package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// runtime_action_proofs accessors (split-brain hardening, Phase 1).
//
// A proof is the durable, single-use authorization a coordinator (holding the
// failover lease + local quorum) writes BEFORE a dangerous runtime-ownership
// action, so the executing host — which does not hold the lease — can validate
// it. The row carries a monotone action lifecycle:
//
//	prepared → in_progress → {completed | failed}
//
// enforced here by GUARDED updates (WHERE status IN legal-predecessors) so a
// state can only move forward and a terminal state never regresses. Starting a
// VM is itself a side effect, so it uses this lifecycle too (claim in_progress
// before libvirt.Start, detect already-running on retry, then complete).
//
// Replication (see sync.go, authoritative): the non-LWW monotone merge runs on both
// paths, but they differ — WAL relay is receiver-capability-gated (proof mutations are
// suppressed to a peer lacking split_brain_gate_v1), while anti-entropy carries the table
// UNCONDITIONALLY on the peer-mTLS sensitive lane (per-receiver exclusion isn't structural
// there; safe because the merging node always runs the v38 resolver and proof rows exist
// only once the gate is cluster-wide). It is NOT wholesale "excluded from replication".

// Proof lifecycle states.
const (
	ProofPrepared   = "prepared"
	ProofInProgress = "in_progress"
	ProofCompleted  = "completed"
	ProofFailed     = "failed"
)

// Proof action kinds.
const (
	ActionReschedule  = "reschedule"
	ActionPromote     = "promote"
	ActionRelocate    = "relocate"
	ActionLBApply     = "lb_apply"
	ActionOwnerAssert = "owner_assert"
)

// ErrProofSpent is returned when a proof can't be claimed because it is already
// terminal (completed/failed) or missing — distinct from a transient error so the
// caller refuses the action rather than retrying blindly.
var ErrProofSpent = errors.New("runtime action proof is terminal or missing")

// ActionProof is the authorization a coordinator mints before a gated action.
// Lifecycle/result columns are managed by the transition helpers, not set here.
type ActionProof struct {
	ID              string
	Action          string
	TargetKind      string
	TargetName      string
	DestHost        string
	Coordinator     string
	LeaseHolder     string
	LeaseExpiresAt  string
	QuorumLive      int
	QuorumNeeded    int
	OwnerEpoch      string
	FenceEpoch      string
	RelocationToken string
}

// ProofRecord is a read-back proof row including lifecycle state.
type ProofRecord struct {
	ActionProof
	Status       string
	StepState    string
	ResultCode   string
	ResultDetail string
	ExecutorHost string
}

// Terminal reports whether the proof has reached a terminal state.
func (p ProofRecord) Terminal() bool {
	return p.Status == ProofCompleted || p.Status == ProofFailed
}

// WriteVMRescheduleProof atomically writes a 'prepared' proof AND stamps the VM's
// pending transition (host_name, state='pending', pending_action_id) in ONE
// batch, so the proof is linked to that exact pending transition — never matched
// by a weak tuple. Used by the failover coordinator at the decide site.
func WriteVMRescheduleProof(ctx context.Context, c *Client, p ActionProof, vmName, destHost string) error {
	now := c.NowTS()
	// Guard: only mint the proof + stamp the pending link if the VM row still
	// exists (not deleted) AND no proof already carries this id — so we never
	// leave an orphan proof for a vanished VM or (astronomically) point a VM at a
	// pre-existing proof on an id collision. applied=false → ErrNoRowsAffected.
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName).Scan(&n); err != nil {
			return false, err
		}
		if n == 0 {
			return false, nil
		}
		var existing int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM runtime_action_proofs WHERE id = ?`, p.ID).Scan(&existing); err != nil {
			return false, err
		}
		return existing == 0, nil
	}, []Statement{
		{SQL: insertProofSQL, Params: proofInsertParams(p, now)},
		{SQL: `UPDATE vms SET host_name = ?, state = 'pending', pending_action_id = ?, updated_at = ?
		        WHERE name = ? AND deleted_at IS NULL`,
			Params: []interface{}{destHost, p.ID, now, vmName}},
	})
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// WriteActionProof inserts a standalone 'prepared' proof (for direct-RPC actions
// that carry it in metadata rather than via a pending link). Idempotent by id.
func WriteActionProof(ctx context.Context, c *Client, p ActionProof) error {
	return c.Execute(ctx, insertProofSQL, proofInsertParams(p, c.NowTS())...)
}

const insertProofSQL = `INSERT OR IGNORE INTO runtime_action_proofs
	(id, action, target_kind, target_name, dest_host, coordinator, lease_holder, lease_expires_at,
	 quorum_live, quorum_needed, owner_epoch, fence_epoch, relocation_token,
	 status, step_state, result_code, result_detail, started_at, completed_at, executor_host,
	 created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', '', '', '', '', '', '', ?, ?)`

func proofInsertParams(p ActionProof, now string) []interface{} {
	return []interface{}{
		p.ID, p.Action, p.TargetKind, p.TargetName, p.DestHost, p.Coordinator,
		p.LeaseHolder, p.LeaseExpiresAt, p.QuorumLive, p.QuorumNeeded,
		p.OwnerEpoch, p.FenceEpoch, p.RelocationToken, now, now,
	}
}

// GetActionProof reads a proof by id. ok=false if absent.
func GetActionProof(ctx context.Context, c *Client, id string) (ProofRecord, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id, action, target_kind, target_name, dest_host, coordinator,
		        lease_holder, lease_expires_at, quorum_live, quorum_needed,
		        owner_epoch, fence_epoch, relocation_token,
		        status, step_state, result_code, result_detail, executor_host
		   FROM runtime_action_proofs WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return ProofRecord{}, false, err
	}
	if len(rows) == 0 {
		return ProofRecord{}, false, nil
	}
	r := rows[0]
	return ProofRecord{
		ActionProof: ActionProof{
			ID: r.String("id"), Action: r.String("action"), TargetKind: r.String("target_kind"),
			TargetName: r.String("target_name"), DestHost: r.String("dest_host"),
			Coordinator: r.String("coordinator"), LeaseHolder: r.String("lease_holder"),
			LeaseExpiresAt: r.String("lease_expires_at"), QuorumLive: r.Int("quorum_live"),
			QuorumNeeded: r.Int("quorum_needed"), OwnerEpoch: r.String("owner_epoch"),
			FenceEpoch: r.String("fence_epoch"), RelocationToken: r.String("relocation_token"),
		},
		Status: r.String("status"), StepState: r.String("step_state"),
		ResultCode: r.String("result_code"), ResultDetail: r.String("result_detail"),
		ExecutorHost: r.String("executor_host"),
	}, true, nil
}

// AppendProofStep records a completed step in a proof's step_state (a space-
// separated, forward-only, idempotent set) so a crashed multi-step action (e.g.
// promote: disk_built → defined → started) resumes past steps already done
// instead of re-running them destructively. Adding a step never removes one.
func AppendProofStep(ctx context.Context, c *Client, id, step string) error {
	now := c.NowTS()
	// Guard on status: proof rows are immutable except FORWARD transitions, so never
	// mutate a terminal proof's step_state/updated_at (a late step-append must not touch
	// a completed/failed row).
	_, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET step_state = TRIM(COALESCE(step_state,'') || ' ' || ?), updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL
		    AND status NOT IN ('completed','failed')
		    AND instr(' ' || COALESCE(step_state,'') || ' ', ' ' || ? || ' ') = 0`,
		step, now, id, step)
	return err
}

// ProofStepDone reports whether step is present in a space-separated step_state.
func ProofStepDone(stepState, step string) bool {
	for _, s := range strings.Fields(stepState) {
		if s == step {
			return true
		}
	}
	return false
}

// GetActionProofByToken reads the proof bound to a relocation token (container
// relocation binds by token, not by a VM pending pointer). ok=false if absent.
//
// A relocation token is single-mint (newID per relocation), so at most one live proof
// carries it — the LIMIT 1 is exact today. It is ORDER BY id'd so the pick is at least
// DETERMINISTIC if that ever failed to hold. TODO(schema): fold a partial UNIQUE index on
// relocation_token (non-empty tokens only) into the next schema migration to make the
// one-proof-per-token invariant structural rather than a mint-time convention.
func GetActionProofByToken(ctx context.Context, c *Client, token string) (ProofRecord, bool, error) {
	if token == "" {
		return ProofRecord{}, false, nil
	}
	rows, err := c.Query(ctx,
		`SELECT id FROM runtime_action_proofs WHERE relocation_token = ? AND deleted_at IS NULL ORDER BY id LIMIT 1`, token)
	if err != nil {
		return ProofRecord{}, false, err
	}
	if len(rows) == 0 {
		return ProofRecord{}, false, nil
	}
	return GetActionProof(ctx, c, rows[0].String("id"))
}

// ClaimActionProof transitions a proof to in_progress on `executor`, but only
// from a non-terminal state (prepared or in_progress — the latter makes a retry
// idempotent: the same executor re-claims and resumes). A terminal or missing
// proof returns ErrProofSpent so the caller refuses rather than re-running the
// side effect. Guarded so a completed/failed proof can never regress.
func ClaimActionProof(ctx context.Context, c *Client, id, executor string) error {
	now := c.NowTS()
	// The claim is single-holder: a fresh (prepared, executor_host='') proof may be
	// taken by anyone, but an in_progress proof may only be re-claimed by the SAME
	// executor (idempotent resume). A different executor gets zero rows → ErrProofSpent,
	// so a claim can't be stolen mid-flight.
	n, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET status = 'in_progress',
		        executor_host = ?,
		        started_at = CASE WHEN started_at = '' THEN ? ELSE started_at END,
		        updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')
		    AND (executor_host = '' OR executor_host = ?)`,
		executor, now, now, id, executor)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrProofSpent // terminal, missing, or held by another executor
	}
	return nil
}

// CompleteVMStartProof marks a VM-start proof completed (terminal) AND clears the
// VM's pending_action_id in the SAME mutation that moves it to 'running', so a
// crash can't leave state and pointer inconsistent. Guarded: only advances from a
// non-terminal proof; a no-op (already terminal / vm gone) reports ErrNoRowsAffected.
func CompleteVMStartProof(ctx context.Context, c *Client, id, vmName, executor string) error {
	now := c.NowTS()
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		// BOTH preconditions must hold atomically, or neither update runs:
		//   (1) the proof is still non-terminal, AND
		//   (2) the VM still points at THIS proof (pending_action_id = id).
		// Otherwise a stale proof could be marked completed while the VM pointer had
		// already changed/cleared — a half-write the caller can't detect (a zero-row
		// UPDATE inside a passing guard is silently "ok").
		var status string
		err := tx.QueryRow(`SELECT status FROM runtime_action_proofs WHERE id = ? AND deleted_at IS NULL`, id).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if status != ProofPrepared && status != ProofInProgress {
			return false, nil
		}
		var n int
		if err := tx.QueryRow(
			`SELECT COUNT(1) FROM vms WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
			vmName, id).Scan(&n); err != nil {
			return false, err
		}
		return n == 1, nil
	}, []Statement{
		{SQL: `UPDATE runtime_action_proofs SET status = 'completed', executor_host = ?, completed_at = ?, updated_at = ?
		        WHERE id = ?`, Params: []interface{}{executor, now, now, id}},
		{SQL: `UPDATE vms SET state = 'running', pending_action_id = '', updated_at = ?
		        WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`, Params: []interface{}{now, vmName, id}},
	})
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// CompleteActionProof marks a standalone proof completed (terminal) on `executor`
// — the generic counterpart to CompleteVMStartProof for direct-RPC actions
// (promote/relocate) that manage their own workload state. Guarded so a terminal
// proof never regresses; a no-op (already terminal / missing) reports
// ErrNoRowsAffected.
func CompleteActionProof(ctx context.Context, c *Client, id, executor string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET status = 'completed', executor_host = ?, completed_at = ?, updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')`,
		executor, now, now, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// FailActionProof marks a proof failed (terminal, non-retryable) with a result,
// and clears any VM pending pointer. Use ONLY for a known non-retryable point or
// explicit abort — a transient error should leave the proof in_progress so a retry
// resumes. Guarded so terminal never regresses.
func FailActionProof(ctx context.Context, c *Client, id, vmName, code, detail string) error {
	now := c.NowTS()
	stmts := []Statement{
		{SQL: `UPDATE runtime_action_proofs SET status = 'failed', result_code = ?, result_detail = ?,
		        completed_at = ?, updated_at = ?
		        WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')`,
			Params: []interface{}{code, detail, now, now, id}},
	}
	if vmName != "" {
		// Exit 'pending' AND clear the pointer together — clearing the pointer while
		// leaving state='pending' would create a MARKERLESS pending row, which
		// startPendingVM would (wrongly) treat as a legacy, ungated start. Move it to
		// 'error' so a failed proof-gated start is a dead end, not a legacy fallthrough.
		stmts = append(stmts, Statement{
			SQL: `UPDATE vms SET state = 'error', state_detail = ?, pending_action_id = '', updated_at = ?
			       WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
			Params: []interface{}{"failover proof failed: " + code, now, vmName, id},
		})
	}
	return c.ExecuteBatch(ctx, stmts)
}
