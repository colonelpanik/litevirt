package corrosion

import (
	"context"
	"testing"
)

func tokenDeletedAt(t *testing.T, c *Client, id string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), "SELECT deleted_at FROM tokens WHERE id = ?", id)
	if err != nil || len(rows) == 0 {
		t.Fatalf("lookup token %q: err=%v rows=%d", id, err, len(rows))
	}
	return rows[0].String("deleted_at")
}

// TestTokenRevocation_SurvivesStaleMerge: a revoked token must not be resurrected
// by an anti-entropy merge of a stale peer dump that still has it live. A peer on
// the old schema dumps tokens WITHOUT updated_at; once tokens has updated_at the
// merge skips that table (can't LWW-arbitrate), so the revocation stands.
// Red before the fix (no updated_at → blind INSERT OR REPLACE un-revokes).
func TestTokenRevocation_SurvivesStaleMerge(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertToken(ctx, c, TokenRecord{
		ID: "tkn1", Username: "u", Name: "n", TokenHash: "h",
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if err := RevokeToken(ctx, c, "tkn1"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if tokenDeletedAt(t, c, "tkn1") == "" {
		t.Fatal("precondition: token should be revoked (deleted_at set)")
	}

	// Stale peer dump (old format, no updated_at) carrying the token still LIVE.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "tokens",
		Columns: []string{"id", "username", "name", "token_hash", "expires_at", "last_used_at", "scope_paths", "created_at", "deleted_at"},
		Rows:    [][]interface{}{{"tkn1", "u", "n", "h", "", "", "", "2020-01-01T00:00:00Z", nil}},
	}}})

	if tokenDeletedAt(t, c, "tkn1") == "" {
		t.Error("token revocation was undone by a stale peer merge (token un-revoked)")
	}
}
