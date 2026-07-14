package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Operation-journal storage (F1, v41). The replicated tier of the crash-
// recoverable operation journal: an immutable `operations` header keyed by a
// DETERMINISTIC id, and append-only `operation_steps` keyed by
// (operation_id, owner_epoch, step_name). Both merge via the non-LWW
// immutable-row merge (sync.go). This file is the read/write API; the pure
// state-machine reduction lives in operations_state.go.

var (
	// ErrOperationHashConflict: the same deterministic operation id already
	// exists with a DIFFERENT request hash — two semantically-different requests
	// collided on one id (D4: reject rather than silently reuse).
	ErrOperationHashConflict = errors.New("operation id already exists with a different request hash")
	// ErrOperationStepConflict: the same step key already exists with DIFFERENT
	// facts — corruption (two executors recorded conflicting facts for one step).
	ErrOperationStepConflict = errors.New("operation step already exists with different facts")
)

// OperationRecord is the immutable operations header. It holds only the REQUESTED
// reservation vectors (reservation_json); actual reservation ids / authority
// epochs live in operation_steps, never here.
type OperationRecord struct {
	ID              string
	Method          string
	Principal       string
	Project         string
	ResourceKind    string
	ResourceID      string
	OperationKind   string
	RequestHash     string
	IdempotencyKey  string
	ReservationJSON string
	DesiredRef      string
	VMOwnerEpoch    int64
	CreatedAt       string
	UpdatedAt       string
	DeletedAt       string
}

// OperationStepRecord is one append-only step of an operation.
type OperationStepRecord struct {
	OperationID string
	OwnerEpoch  int64
	StepName    string
	Facts       string
	CreatedAt   string
	UpdatedAt   string
	DeletedAt   string
}

// DeterministicOperationID computes the stable operation id from its identity
// components. Length-prefixing each field makes the concatenation unambiguous
// (so method="ab",key="c" and method="a",key="bc" don't collide). Two entry
// nodes handed the same client idempotency key for the same principal/project/
// resource/method therefore mint the SAME id everywhere.
func DeterministicOperationID(method, principal, project, resourceID, idempotencyKey string) string {
	h := sha256.New()
	for _, f := range []string{method, principal, project, resourceID, idempotencyKey} {
		fmt.Fprintf(h, "%d:%s", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

const operationCols = `id, method, principal, project, resource_kind, resource_id,
	operation_kind, request_hash, idempotency_key, reservation_json, desired_ref,
	vm_owner_epoch, created_at, updated_at, deleted_at`

func scanOperation(r Row) OperationRecord {
	return OperationRecord{
		ID:              r.String("id"),
		Method:          r.String("method"),
		Principal:       r.String("principal"),
		Project:         r.String("project"),
		ResourceKind:    r.String("resource_kind"),
		ResourceID:      r.String("resource_id"),
		OperationKind:   r.String("operation_kind"),
		RequestHash:     r.String("request_hash"),
		IdempotencyKey:  r.String("idempotency_key"),
		ReservationJSON: r.String("reservation_json"),
		DesiredRef:      r.String("desired_ref"),
		VMOwnerEpoch:    r.Int64("vm_owner_epoch"),
		CreatedAt:       r.String("created_at"),
		UpdatedAt:       r.String("updated_at"),
		DeletedAt:       r.String("deleted_at"),
	}
}

// GetOperation returns the operation header by id, or nil if absent/tombstoned.
func GetOperation(ctx context.Context, c *Client, id string) (*OperationRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT `+operationCols+` FROM operations WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	op := scanOperation(rows[0])
	return &op, nil
}

// InsertOperation writes the immutable header. Fails on a primary-key conflict;
// callers that need claim-or-find idempotency use ClaimOrFindOperation.
func InsertOperation(ctx context.Context, c *Client, op OperationRecord) error {
	return c.Execute(ctx,
		`INSERT INTO operations (`+operationCols+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		op.ID, op.Method, op.Principal, op.Project, op.ResourceKind, op.ResourceID,
		op.OperationKind, op.RequestHash, op.IdempotencyKey, op.ReservationJSON,
		op.DesiredRef, op.VMOwnerEpoch, nowRFC3339(), c.NowTS())
}

// ClaimOrFindOperation implements the D4 idempotency contract: if no header with
// this id exists it inserts and returns (op, created=true); if one exists with
// the SAME request hash it returns the existing header (created=false); if one
// exists with a DIFFERENT request hash it returns ErrOperationHashConflict. The
// header id must already be set (DeterministicOperationID).
func ClaimOrFindOperation(ctx context.Context, c *Client, op OperationRecord) (*OperationRecord, bool, error) {
	if existing, err := GetOperation(ctx, c, op.ID); err != nil {
		return nil, false, err
	} else if existing != nil {
		if existing.RequestHash != op.RequestHash {
			return nil, false, ErrOperationHashConflict
		}
		return existing, false, nil
	}
	if err := InsertOperation(ctx, c, op); err != nil {
		// A concurrent writer may have inserted the same id — reconcile.
		if existing, gerr := GetOperation(ctx, c, op.ID); gerr == nil && existing != nil {
			if existing.RequestHash != op.RequestHash {
				return nil, false, ErrOperationHashConflict
			}
			return existing, false, nil
		}
		return nil, false, err
	}
	created := op
	return &created, true, nil
}

// AppendOperationStep appends a step idempotently: re-appending the SAME step key
// with identical facts is a no-op; the same key with DIFFERENT facts is
// corruption (ErrOperationStepConflict). Callers validate legality via
// IsLegalStep before appending.
func AppendOperationStep(ctx context.Context, c *Client, step OperationStepRecord) error {
	rows, err := c.Query(ctx,
		`SELECT facts FROM operation_steps
		 WHERE operation_id = ? AND owner_epoch = ? AND step_name = ? AND deleted_at IS NULL`,
		step.OperationID, step.OwnerEpoch, step.StepName)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		if rows[0].String("facts") != step.Facts {
			return ErrOperationStepConflict
		}
		return nil // idempotent re-append
	}
	return c.Execute(ctx,
		`INSERT INTO operation_steps (operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		step.OperationID, step.OwnerEpoch, step.StepName, step.Facts, nowRFC3339(), c.NowTS())
}

// ListOperationSteps returns an operation's steps for one owner epoch, in
// insertion (created_at) order.
func ListOperationSteps(ctx context.Context, c *Client, operationID string, ownerEpoch int64) ([]OperationStepRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at
		 FROM operation_steps
		 WHERE operation_id = ? AND owner_epoch = ? AND deleted_at IS NULL
		 ORDER BY created_at, step_name`,
		operationID, ownerEpoch)
	if err != nil {
		return nil, err
	}
	out := make([]OperationStepRecord, len(rows))
	for i, r := range rows {
		out[i] = OperationStepRecord{
			OperationID: r.String("operation_id"),
			OwnerEpoch:  r.Int64("owner_epoch"),
			StepName:    r.String("step_name"),
			Facts:       r.String("facts"),
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
			DeletedAt:   r.String("deleted_at"),
		}
	}
	return out, nil
}

// BeginVMOperation atomically claims a VM for an operation. In ONE transaction
// it verifies the VM's expected owner epoch + spec generation and that no OTHER
// operation holds the barrier, then sets the desired spec, bumps spec_generation,
// sets active_operation_id, and writes the operation header + its 'planned' step.
// Returns applied=false (no error) when the preconditions no longer hold — a
// concurrent operation holds the barrier, or the epoch/generation is stale — so
// the caller defers/retries. It is idempotent for the SAME operation id (a retry
// after this op already holds the barrier is a no-op that still reports applied).
// After a successful first claim the VM's spec_generation is expectedSpecGen+1;
// use that (with ownerEpoch) for CompleteVMOperation.
func (c *Client) BeginVMOperation(ctx context.Context, op OperationRecord, desiredSpec string, expectedOwnerEpoch, expectedSpecGen int64) (bool, error) {
	now := c.NowTS()
	guard := func(tx *sql.Tx) (bool, error) {
		var ownerEpoch, specGen int64
		var activeOp string
		err := tx.QueryRowContext(ctx,
			`SELECT vm_owner_epoch, spec_generation, active_operation_id FROM vms WHERE name = ? AND deleted_at IS NULL`,
			op.ResourceID).Scan(&ownerEpoch, &specGen, &activeOp)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if activeOp == op.ID {
			return true, nil // already begun (retry) — the guarded stmts below no-op
		}
		if activeOp != "" {
			return false, nil // barrier held by another operation
		}
		return ownerEpoch == expectedOwnerEpoch && specGen == expectedSpecGen, nil
	}
	stmts := []Statement{
		// Self-contained CAS so a retry (active_operation_id already set) is a no-op.
		{SQL: `UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, active_operation_id = ?, updated_at = ?
		       WHERE name = ? AND active_operation_id = '' AND vm_owner_epoch = ? AND spec_generation = ?`,
			Params: []interface{}{desiredSpec, op.ID, now, op.ResourceID, expectedOwnerEpoch, expectedSpecGen}},
		{SQL: `INSERT OR IGNORE INTO operations (` + operationCols + `)
		       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{op.ID, op.Method, op.Principal, op.Project, op.ResourceKind, op.ResourceID,
				op.OperationKind, op.RequestHash, op.IdempotencyKey, op.ReservationJSON, op.DesiredRef,
				expectedOwnerEpoch, nowRFC3339(), now}},
		{SQL: `INSERT OR IGNORE INTO operation_steps (operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
		       VALUES (?, ?, ?, '', ?, ?, NULL)`,
			Params: []interface{}{op.ID, expectedOwnerEpoch, OpStepPlanned, nowRFC3339(), now}},
	}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// CompleteVMOperation clears the VM's mutation barrier ONLY if this operation
// still holds it at the expected owner epoch + spec generation (so a stale writer
// whose op was superseded cannot clear a newer op's barrier), and records the
// 'completed' step — atomically. Returns applied=false when the CAS no longer
// matches.
func (c *Client) CompleteVMOperation(ctx context.Context, vmName, operationID string, ownerEpoch, expectedSpecGen int64) (bool, error) {
	now := c.NowTS()
	guard := func(tx *sql.Tx) (bool, error) {
		var oe, sg int64
		var activeOp string
		err := tx.QueryRowContext(ctx,
			`SELECT vm_owner_epoch, spec_generation, active_operation_id FROM vms WHERE name = ? AND deleted_at IS NULL`,
			vmName).Scan(&oe, &sg, &activeOp)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return activeOp == operationID && oe == ownerEpoch && sg == expectedSpecGen, nil
	}
	stmts := []Statement{
		{SQL: `UPDATE vms SET active_operation_id = '', updated_at = ?
		       WHERE name = ? AND active_operation_id = ? AND vm_owner_epoch = ? AND spec_generation = ?`,
			Params: []interface{}{now, vmName, operationID, ownerEpoch, expectedSpecGen}},
		{SQL: `INSERT OR IGNORE INTO operation_steps (operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
		       VALUES (?, ?, ?, '', ?, ?, NULL)`,
			Params: []interface{}{operationID, ownerEpoch, OpStepCompleted, nowRFC3339(), now}},
	}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// ReapTerminalOperations tombstones operations that are safely finished:
// terminal (completed/failed/cancelled/superseded) with their most recent step
// older than the retention horizon, AND not referenced by any live
// vms.active_operation_id. Both the header and all its steps are soft-deleted, so
// the immutable-merge tombstone-dominance keeps a delayed live copy (or a late
// pre-terminal step) from resurrecting a reaped operation. Retention MUST exceed
// the WAL/AE repair horizon so no in-flight step can still arrive. Local-
// deterministic (safe to run on every node); the replicated tombstone converges.
// Returns the number of operations reaped.
func ReapTerminalOperations(ctx context.Context, c *Client, retention time.Duration) (int, error) {
	cutoff := time.Now().Add(-retention)

	arows, err := c.Query(ctx,
		`SELECT DISTINCT active_operation_id FROM vms WHERE active_operation_id != '' AND deleted_at IS NULL`)
	if err != nil {
		return 0, err
	}
	active := make(map[string]bool, len(arows))
	for _, r := range arows {
		active[r.String("active_operation_id")] = true
	}

	orows, err := c.Query(ctx,
		`SELECT id, operation_kind FROM operations WHERE deleted_at IS NULL`)
	if err != nil {
		return 0, err
	}
	reaped := 0
	for _, r := range orows {
		id := r.String("id")
		if active[id] {
			continue // a live VM barrier still points at it
		}
		kind := OperationKind(r.String("operation_kind"))
		// All steps across every owner epoch (an owner transfer splits epochs).
		srows, err := c.Query(ctx,
			`SELECT step_name, updated_at FROM operation_steps WHERE operation_id = ? AND deleted_at IS NULL`, id)
		if err != nil {
			return reaped, err
		}
		names := make([]string, 0, len(srows))
		var last time.Time
		for _, sr := range srows {
			names = append(names, sr.String("step_name"))
			if t, ok := ParseUpdatedAt(sr.String("updated_at")); ok && t.After(last) {
				last = t
			}
		}
		state, _ := ReduceOperationState(kind, names)
		if !IsOperationTerminal(state) || last.IsZero() || last.After(cutoff) {
			continue
		}
		now, marker := c.NowTS(), nowRFC3339()
		if err := c.ExecuteBatch(ctx, []Statement{
			{SQL: `UPDATE operations SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
				Params: []interface{}{marker, now, id}},
			{SQL: `UPDATE operation_steps SET deleted_at = ?, updated_at = ? WHERE operation_id = ? AND deleted_at IS NULL`,
				Params: []interface{}{marker, now, id}},
		}); err != nil {
			return reaped, err
		}
		reaped++
	}
	return reaped, nil
}

// OperationCurrentState reduces an operation's recorded steps (for the given
// owner epoch) to its authoritative current state + safety-fault flag.
func OperationCurrentState(ctx context.Context, c *Client, operationID string, ownerEpoch int64, kind OperationKind) (state string, faulted bool, err error) {
	steps, err := ListOperationSteps(ctx, c, operationID, ownerEpoch)
	if err != nil {
		return "", false, err
	}
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.StepName
	}
	state, faulted = ReduceOperationState(kind, names)
	return state, faulted, nil
}
