package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A replicated INSERT into a table that has NO updated_at column (sessions) must apply. The LWW
// gate (shouldSkipLWW) reads the local row's updated_at to decide skip/apply; on a table without
// that column SQLite returns "no such column: updated_at", which the receiver surfaces as an
// apply error and back-pressures — head-of-line-blocking the whole WAL stream. The gate must
// recognize a no-updated_at table has no LWW clock and apply the incoming write (the INSERT
// upsert rewrite already handles the missing column).
//
// Regression: a UI login creates a session row via this exact builder; on v1.4.0 the session
// INSERT stalled outbound replication from whatever node the login landed on.
func TestApplyRemoteMutations_SessionsInsertNoUpdatedAt(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})

	// The exact InsertSession builder shape (auth.go), so it resolves to the registered
	// DispPlainInsert ledger entry and reaches applyLWWGated → shouldSkipLWW.
	stmts := `[{"SQL":"INSERT INTO sessions (id, username, realm, ip, user_agent, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)","Params":["sid1","alice","pam","198.51.100.9","agent","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z","2026-01-02T00:00:00Z"]}]`
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: "2000000000000-0000-n2", Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("sessions INSERT (no updated_at) must apply, got back-pressure: %v", err)
	}
	rows, err := c.Query(ctx, "SELECT username FROM sessions WHERE id = ?", "sid1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("session row not applied: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("username"); got != "alice" {
		t.Fatalf("username = %q, want alice", got)
	}

	// Idempotent re-apply (a re-replicated creation) must not error either.
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("re-applied sessions INSERT must not back-pressure, got: %v", err)
	}
}
