package corrosion

import (
	"context"
	"strings"
	"testing"
)

// InsertAuditLog is INSERT OR IGNORE on id, and it moved the in-memory chain
// tail whether or not the row went in. A duplicate caller-supplied id inserted
// nothing, yet the tail took that row's hash and seq, so the next real row was
// chained onto a row that is not in the table: a hash break and a sequence gap
// that `lv audit verify` reports as tampering, on a log nobody touched.
func TestInsertAuditLog_ADuplicateIDDoesNotMoveTheChainTail(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "r1", Username: "u", HostName: "node-0",
		Action: "vm.delete", Target: "dup-target-0929", Result: "ok", Timestamp: "2026-07-29T10:00:02Z",
	}); err != nil {
		t.Fatalf("a duplicate id is the documented idempotent no-op, got %v", err)
	}
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:03Z")

	if got := oneCol(t, c, `SELECT action FROM audit_log WHERE id = 'r1'`); got != "vm.start" {
		t.Fatalf("r1 was overwritten by the duplicate (action %q)", got)
	}
	if got := oneCol(t, c, `SELECT seq FROM audit_log WHERE id = 'r2'`); got != "2" {
		t.Errorf("r2 has seq %s, want 2: the ignored duplicate consumed a sequence number", got)
	}
	res := verify(t, c)
	if res.BrokenAt != "" || len(res.SeqGaps) > 0 || res.Tampered() {
		t.Fatalf("an ignored duplicate left the chain looking tampered: %+v", res)
	}
	// Nor is the no-op relayed (relayStatement drops a create-only statement
	// that changed nothing). A peer that has not yet received r1 would apply the
	// duplicate's content under r1's id, and then ignore the real r1.
	if strings.Contains(mutationLogText(t, c), "dup-target-0929") {
		t.Error("the ignored duplicate was written to mutation_log and will be replayed by peers")
	}
}

func mutationLogText(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.String("stmts"))
		b.WriteByte('\n')
	}
	return b.String()
}
