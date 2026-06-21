package corrosion

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func bcryptHash(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func TestInsertAndGetUser(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "alice", "admin", "hash123"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	u, err := GetUser(ctx, c, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u == nil {
		t.Fatal("GetUser returned nil")
	}
	if u.Username != "alice" {
		t.Errorf("Username = %q, want alice", u.Username)
	}
	if u.Role != "admin" {
		t.Errorf("Role = %q, want admin", u.Role)
	}
	if u.PasswordHash != "hash123" {
		t.Errorf("PasswordHash = %q, want hash123", u.PasswordHash)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	c := testClient(t)
	u, err := GetUser(context.Background(), c, "nobody")
	if err != nil {
		t.Fatalf("GetUser error: %v", err)
	}
	if u != nil {
		t.Errorf("expected nil for missing user, got %+v", u)
	}
}

func TestListUsers(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertUser(ctx, c, "alice", "admin", "h1")
	InsertUser(ctx, c, "bob", "viewer", "h2")

	users, err := ListUsers(ctx, c)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	// Results ordered by username
	if users[0].Username != "alice" {
		t.Errorf("users[0] = %q, want alice", users[0].Username)
	}
	if users[1].Username != "bob" {
		t.Errorf("users[1] = %q, want bob", users[1].Username)
	}
}

func TestDeleteUser(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertUser(ctx, c, "alice", "admin", "h1")

	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	u, _ := GetUser(ctx, c, "alice")
	if u != nil {
		t.Error("user should be nil after deletion")
	}

	users, _ := ListUsers(ctx, c)
	if len(users) != 0 {
		t.Errorf("ListUsers after delete: expected 0, got %d", len(users))
	}
}

func TestValidateToken_Valid(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertUser(ctx, c, "alice", "admin", "hash")

	// Real tokens are always 64 lowercase hex chars (hex of 32 random bytes);
	// ValidateToken now fast-rejects anything else, so tests use that shape.
	const validToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hash, err := bcryptHash(validToken)
	if err != nil {
		t.Fatalf("bcryptHash: %v", err)
	}

	tok := TokenRecord{
		ID:        "tok-valid",
		Username:  "alice",
		Name:      "ci-token",
		TokenHash: hash,
	}
	if err := InsertToken(ctx, c, tok); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	user, err := ValidateToken(ctx, c, validToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user == nil {
		t.Fatal("ValidateToken returned nil for valid token")
	}
	if user.Username != "alice" {
		t.Errorf("Username = %q, want alice", user.Username)
	}
	if user.Role != "admin" {
		t.Errorf("Role = %q, want admin", user.Role)
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertUser(ctx, c, "alice", "admin", "hash")

	// Both correctly-shaped (64 hex) but different, so this exercises the
	// bcrypt-mismatch path, not the malformed fast-reject.
	const correctToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const wrongToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	hash, _ := bcryptHash(correctToken)
	InsertToken(ctx, c, TokenRecord{
		ID: "tok1", Username: "alice", Name: "ci", TokenHash: hash,
	})

	user, err := ValidateToken(ctx, c, wrongToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil for invalid token, got %+v", user)
	}
}

func TestLooksLikeAPIToken(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{valid, true},
		{"", false},
		{"my-secret-token", false},                    // too short, has dashes
		{valid[:63], false},                            // 63 chars
		{valid + "0", false},                           // 65 chars
		{"0123456789ABCDEF" + valid[16:], false},       // uppercase not emitted by CreateToken
		{"lvs_0123456789abcdef", false},                // session bearer, not an API token
		{"g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false}, // 'g' is not hex
	} {
		if got := looksLikeAPIToken(tc.in); got != tc.want {
			t.Errorf("looksLikeAPIToken(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestValidateToken_MalformedFastReject confirms a garbage bearer is rejected
// without consulting the tokens table (the DoS short-circuit).
func TestValidateToken_MalformedFastReject(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	user, err := ValidateToken(ctx, c, "not-a-real-token")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil for malformed token, got %+v", user)
	}
}

func TestValidateToken_RevokedToken(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertUser(ctx, c, "alice", "admin", "hash")

	const revToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hash, _ := bcryptHash(revToken)
	InsertToken(ctx, c, TokenRecord{
		ID: "tok-rev", Username: "alice", Name: "ci", TokenHash: hash,
	})
	RevokeToken(ctx, c, "tok-rev")

	user, err := ValidateToken(ctx, c, revToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil for revoked token, got %+v", user)
	}
}

func TestValidateToken_DeletedUser(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertUser(ctx, c, "alice", "admin", "hash")
	const delToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hash, _ := bcryptHash(delToken)
	InsertToken(ctx, c, TokenRecord{
		ID: "tok-del", Username: "alice", Name: "ci", TokenHash: hash,
	})
	DeleteUser(ctx, c, "alice")

	user, err := ValidateToken(ctx, c, delToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil for deleted user's token, got %+v", user)
	}
}

func TestInsertAndRevokeToken(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	tok := TokenRecord{
		ID:        "tok1",
		Username:  "alice",
		Name:      "ci-token",
		TokenHash: "hash",
	}
	if err := InsertToken(ctx, c, tok); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	// Verify it was stored
	rows, err := c.Query(ctx, `SELECT id, username, name FROM tokens WHERE id = ?`, "tok1")
	if err != nil {
		t.Fatalf("query token: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 token, got %d", len(rows))
	}
	if rows[0].String("username") != "alice" {
		t.Errorf("username = %q, want alice", rows[0].String("username"))
	}

	// Revoke
	if err := RevokeToken(ctx, c, "tok1"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// After revoke, deleted_at should be set
	rows2, _ := c.Query(ctx, `SELECT deleted_at FROM tokens WHERE id = ?`, "tok1")
	if len(rows2) != 1 || rows2[0].String("deleted_at") == "" {
		t.Error("token should have deleted_at set after revoke")
	}
}
