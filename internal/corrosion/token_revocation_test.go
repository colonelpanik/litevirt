package corrosion

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func tokenField(t *testing.T, c *Client, id, col string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), "SELECT "+col+" FROM tokens WHERE id = ?", id)
	if err != nil || len(rows) == 0 {
		t.Fatalf("lookup token %q.%s: err=%v rows=%d", id, col, err, len(rows))
	}
	return rows[0].String(col)
}

func tokenDeletedAt(t *testing.T, c *Client, id string) string {
	t.Helper()
	return tokenField(t, c, id, "deleted_at")
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

// TestTokenRevocation_BeatsOlderLiveDump exercises the LWW arbitration itself (not
// the missing-column skip guard the test above covers): a v29-shape peer dump that
// carries the token still LIVE must lose to the local revoke because RevokeToken
// bumps updated_at to now. This is the security-critical path — a stale-but-
// correctly-shaped peer must not un-revoke a token.
//
// The token's updated_at is pre-aged to 2020 so the test has real teeth: the merged
// dump sits at 2021 (newer than the aged row, older than the now-stamped revoke). If
// RevokeToken did NOT bump updated_at, the row would stay at 2020 and the 2021 dump
// would win and un-revoke it.
func TestTokenRevocation_BeatsOlderLiveDump(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertToken(ctx, c, TokenRecord{ID: "tkn1", Username: "u", Name: "n", TokenHash: "h"}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE tokens SET updated_at = ? WHERE id = ?`, "2020-01-01T00:00:00Z", "tkn1"); err != nil {
		t.Fatalf("age token: %v", err)
	}
	if err := RevokeToken(ctx, c, "tkn1"); err != nil { // bumps updated_at to now (>2021)
		t.Fatalf("RevokeToken: %v", err)
	}

	// v29-shape dump (HAS updated_at) carrying the token LIVE (deleted_at nil) at
	// 2021 → only the revoke's bumped (now) updated_at keeps the revocation.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "tokens",
		Columns: []string{"id", "username", "name", "token_hash", "expires_at", "last_used_at", "scope_paths", "created_at", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"tkn1", "u", "n", "h", "", "", "", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z", nil}},
	}}})

	if tokenDeletedAt(t, c, "tkn1") == "" {
		t.Error("revocation lost LWW to a live token dump (token un-revoked)")
	}
}

// TestValidateToken_DoesNotBumpUpdatedAt locks in that a token USE only touches
// last_used_at, never updated_at — otherwise a high-frequency token could keep
// out-timestamping (and thus undoing) a concurrent revoke under anti-entropy LWW.
//
// updated_at is pre-aged to 2020 so the assertion has teeth at RFC3339 (second)
// resolution: if ValidateToken bumped updated_at it would jump to ~now, which the
// equality check would catch (insert-then-validate within the same second would not).
func TestValidateToken_DoesNotBumpUpdatedAt(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	raw := strings.Repeat("ab", 32) // 64 lowercase hex chars: passes looksLikeAPIToken
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := InsertUser(ctx, c, "u", "admin", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "tkn1", Username: "u", Name: "n", TokenHash: string(hash)}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	const aged = "2020-01-01T00:00:00Z"
	if err := c.Execute(ctx, `UPDATE tokens SET updated_at = ? WHERE id = ?`, aged, "tkn1"); err != nil {
		t.Fatalf("age token: %v", err)
	}

	rec, err := ValidateToken(ctx, c, raw)
	if err != nil || rec == nil {
		t.Fatalf("ValidateToken: rec=%v err=%v", rec, err)
	}

	if after := tokenField(t, c, "tkn1", "updated_at"); after != aged {
		t.Errorf("ValidateToken bumped updated_at %q -> %q; a token use must not out-timestamp a revoke", aged, after)
	}
	if tokenField(t, c, "tkn1", "last_used_at") == "" {
		t.Error("ValidateToken did not record last_used_at (the validate path didn't run)")
	}
}
