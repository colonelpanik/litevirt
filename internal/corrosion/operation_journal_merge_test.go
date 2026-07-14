package corrosion

import (
	"context"
	"testing"
)

// insertOp writes an operations row directly (no F1 helper yet). deletedAt=""
// means live; a non-empty value tombstones it.
func insertOp(t *testing.T, c *Client, id, requestHash, updatedAt, deletedAt string) {
	t.Helper()
	_, err := c.db.Exec(
		`INSERT INTO operations
		   (id, method, principal, project, resource_kind, resource_id, operation_kind,
		    request_hash, idempotency_key, reservation_json, desired_ref, vm_owner_epoch,
		    created_at, updated_at, deleted_at)
		 VALUES (?, 'UpdateVM', 'user:alice@local', '', 'vm', 'vm1', 'resource_update',
		    ?, 'k1', '', '', 1, ?, ?, ?)`,
		id, requestHash, updatedAt, updatedAt, deletedAt)
	if err != nil {
		t.Fatalf("insert op %s: %v", id, err)
	}
}

func opField(t *testing.T, c *Client, id, col string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), "SELECT "+col+" FROM operations WHERE id = ?", id)
	if err != nil {
		t.Fatalf("query op %s.%s: %v", id, col, err)
	}
	if len(rows) == 0 {
		return "<absent>"
	}
	return rows[0].String(col)
}

// A first-seen operation row replicates in (no local row → take incoming).
func TestOperationsMerge_TakeIncomingWhenAbsent(t *testing.T) {
	src, dst := testClient(t), testClient(t)
	insertOp(t, src, "op1", "hashA", "2026-06-03T18:40:00Z", "")
	dst.MergeStateBytesLWW(src.DumpStateBytes())
	if got := opField(t, dst, "op1", "request_hash"); got != "hashA" {
		t.Fatalf("absent local → take incoming; request_hash=%q want hashA", got)
	}
	if dst.UnresolvedTieCount() != 0 {
		t.Fatalf("no conflict expected, unresolved=%d", dst.UnresolvedTieCount())
	}
}

// Identical rows merge idempotently — no change, no unresolved tie.
func TestOperationsMerge_Idempotent(t *testing.T) {
	src, dst := testClient(t), testClient(t)
	insertOp(t, src, "op1", "hashA", "2026-06-03T18:40:00Z", "")
	insertOp(t, dst, "op1", "hashA", "2026-06-03T18:40:00Z", "")
	dst.MergeStateBytesLWW(src.DumpStateBytes())
	if got := opField(t, dst, "op1", "request_hash"); got != "hashA" {
		t.Fatalf("idempotent merge changed the row: request_hash=%q", got)
	}
	if dst.UnresolvedTieCount() != 0 {
		t.Fatalf("identical rows must not be a conflict, unresolved=%d", dst.UnresolvedTieCount())
	}
}

// The SAME operation id with a DIFFERENT request hash is a genuine conflict
// (D4: two entry nodes minted the same id from different requests). Keep local,
// flag unresolved, never coin-flip.
func TestOperationsMerge_FactsConflictUnresolved(t *testing.T) {
	src, dst := testClient(t), testClient(t)
	insertOp(t, src, "op1", "hashSRC", "2026-06-03T18:40:00Z", "")
	insertOp(t, dst, "op1", "hashDST", "2026-06-03T18:40:00Z", "")
	dst.MergeStateBytesLWW(src.DumpStateBytes())
	if got := opField(t, dst, "op1", "request_hash"); got != "hashDST" {
		t.Fatalf("immutable conflict must keep local (hashDST), got %q", got)
	}
	if dst.UnresolvedTieCount() != 1 {
		t.Fatalf("facts conflict must be tracked unresolved, count=%d", dst.UnresolvedTieCount())
	}
}

// A tombstone (GC of a terminal operation) dominates a delayed live copy.
func TestOperationsMerge_TombstoneDominates(t *testing.T) {
	src, dst := testClient(t), testClient(t)
	// src holds the tombstoned copy; dst still has it live.
	insertOp(t, src, "op1", "hashA", "2026-06-03T18:41:00Z", "2026-06-03T18:41:00Z")
	insertOp(t, dst, "op1", "hashA", "2026-06-03T18:40:00Z", "")
	dst.MergeStateBytesLWW(src.DumpStateBytes())
	if got := opField(t, dst, "op1", "deleted_at"); got == "" {
		t.Fatalf("incoming tombstone must dominate the live local row; deleted_at=%q", got)
	}
}
