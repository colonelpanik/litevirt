package corrosion

import (
	"context"
	"testing"
	"time"
)

func ageOperationSteps(t *testing.T, c *Client, operationID, ts string) {
	t.Helper()
	if _, err := c.db.Exec(`UPDATE operation_steps SET updated_at = ? WHERE operation_id = ?`, ts, operationID); err != nil {
		t.Fatalf("age steps: %v", err)
	}
}

func TestReapTerminalOperations(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{ID: DeterministicOperationID("UpdateVM", "p", "", "vm1", "k1"),
		Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if _, err := c.BeginVMOperation(ctx, op, `{"cpu":2}`, 0, 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := c.CompleteVMOperation(ctx, "vm1", op.ID, 0, 1); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Terminal but FRESH → not reaped (retention not elapsed).
	if n, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 0 {
		t.Fatalf("fresh terminal op should not be reaped: n=%d err=%v", n, err)
	}

	// Age the steps past the horizon → reaped, header + steps tombstoned.
	ageOperationSteps(t, c, op.ID, "2020-01-01T00:00:00Z")
	if n, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 1 {
		t.Fatalf("aged terminal op should be reaped once: n=%d err=%v", n, err)
	}
	if got, _ := GetOperation(ctx, c, op.ID); got != nil {
		t.Fatal("header should be tombstoned after reap")
	}
	if steps, _ := ListOperationSteps(ctx, c, op.ID, 0); len(steps) != 0 {
		t.Fatalf("steps should be tombstoned after reap, got %d", len(steps))
	}
	// Idempotent: a second sweep reaps nothing.
	if n, _ := ReapTerminalOperations(ctx, c, time.Hour); n != 0 {
		t.Fatalf("second sweep should reap nothing, got %d", n)
	}
}

func TestReapTerminalOperations_SkipsActiveAndNonTerminal(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	op := OperationRecord{ID: "opActive", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	// Begin but do NOT complete → barrier held, state is non-terminal (planned).
	if _, err := c.BeginVMOperation(ctx, op, `{"cpu":2}`, 0, 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	ageOperationSteps(t, c, op.ID, "2020-01-01T00:00:00Z") // old, but must still be skipped
	if n, err := ReapTerminalOperations(ctx, c, time.Hour); err != nil || n != 0 {
		t.Fatalf("an active, non-terminal op must never be reaped: n=%d err=%v", n, err)
	}
	if got, _ := GetOperation(ctx, c, op.ID); got == nil {
		t.Fatal("active operation must not be tombstoned")
	}
}

// putReapedOperation writes one operation header and one step on c, already
// tombstoned at (deletedAt, updatedAt) — what a reaper leaves behind. Written
// beneath the replicator: these tests are about the merge.
func putReapedOperation(t *testing.T, c *Client, id, requestHash, deletedAt, updatedAt string) {
	t.Helper()
	if _, err := c.db.Exec(`INSERT INTO operations (`+operationCols+`)
		VALUES (?, 'UpdateVM', 'p', '_default', 'capacity', '', 'resource_update_running', ?, '', '', '', 0,
		        '2026-01-01T00:00:00Z', ?, ?)`, id, requestHash, updatedAt, deletedAt); err != nil {
		t.Fatalf("put operation %s: %v", id, err)
	}
	if _, err := c.db.Exec(`INSERT INTO operation_steps
		(operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
		VALUES (?, 0, 'completed', '', '2026-01-01T00:00:00Z', ?, ?)`, id, updatedAt, deletedAt); err != nil {
		t.Fatalf("put step %s: %v", id, err)
	}
}

func reapedRow(t *testing.T, c *Client, table, idCol, id string) string {
	t.Helper()
	var u, d string
	if err := c.db.QueryRow(`SELECT updated_at, COALESCE(deleted_at, '') FROM `+table+
		` WHERE `+idCol+` = ?`, id).Scan(&u, &d); err != nil {
		t.Fatalf("read %s %s: %v", table, id, err)
	}
	return u + "/" + d
}

// TestImmutableMerge_TwoTombstonesConverge is lab finding F6 at the merge: two
// nodes reaped one finished operation before either heard of the other, so each
// holds its own tombstone with equal facts. Anti-entropy must bring both to ONE
// copy, whichever direction it runs first, and that copy must be the later
// tombstone (a row's updated_at never moves backwards).
func TestImmutableMerge_TwoTombstonesConverge(t *testing.T) {
	cases := []struct {
		name        string
		early, late [2]string // (deleted_at, updated_at)
	}{
		{"rfc3339 nanos", [2]string{"2026-10-12T00:01:47Z", "2026-10-12T00:01:47.992937697Z"},
			[2]string{"2026-10-12T00:01:48Z", "2026-10-12T00:01:48.012523066Z"}},
		{"same updated_at, deleted_at decides", [2]string{"2026-10-12T00:01:47Z", "2026-10-12T00:01:48.000000000Z"},
			[2]string{"2026-10-12T00:01:48Z", "2026-10-12T00:01:48.000000000Z"}},
	}
	for _, tc := range cases {
		for _, earlyFirst := range []bool{true, false} {
			order := "/late-node-merges-first"
			if earlyFirst {
				order = "/early-node-merges-first"
			}
			t.Run(tc.name+order, func(t *testing.T) {
				a, b := testClient(t), testClient(t)
				putReapedOperation(t, a, "op1", "h", tc.early[0], tc.early[1])
				putReapedOperation(t, b, "op1", "h", tc.late[0], tc.late[1])
				if !earlyFirst {
					a, b = b, a
				}
				// The real anti-entropy merge path, in both directions (the
				// helper is named for its first user; nothing in it is lease-specific).
				gossipLeaseTerms(t, a, b)
				want := tc.late[1] + "/" + tc.late[0]
				for _, c := range []*Client{a, b} {
					if got := reapedRow(t, c, "operations", "id", "op1"); got != want {
						t.Errorf("operations: got %s, want the later tombstone %s", got, want)
					}
					if got := reapedRow(t, c, "operation_steps", "operation_id", "op1"); got != want {
						t.Errorf("operation_steps: got %s, want the later tombstone %s", got, want)
					}
				}
				if n := a.UnresolvedTieCount() + b.UnresolvedTieCount(); n != 0 {
					t.Errorf("two tombstones of one row were flagged as %d unresolved conflicts", n)
				}
			})
		}
	}
}

// TestImmutableMerge_TombstonesWithDifferentFactsStayFlagged: the tie-break is
// for equal facts only. Two tombstoned headers that disagree on a fact are a
// genuine conflict and are still kept apart and flagged, never coin-flipped.
func TestImmutableMerge_TombstonesWithDifferentFactsStayFlagged(t *testing.T) {
	a, b := testClient(t), testClient(t)
	putReapedOperation(t, a, "op1", "h-a", "2026-10-12T00:01:47Z", "2026-10-12T00:01:47.9Z")
	putReapedOperation(t, b, "op1", "h-b", "2026-10-12T00:01:48Z", "2026-10-12T00:01:48.1Z")
	gossipLeaseTerms(t, a, b)
	if got := reapedRow(t, a, "operations", "id", "op1"); got != "2026-10-12T00:01:47.9Z/2026-10-12T00:01:47Z" {
		t.Errorf("a's conflicting header was overwritten: %s", got)
	}
	if a.UnresolvedTieCount() == 0 {
		t.Error("a conflicting immutable header was not flagged")
	}
}
