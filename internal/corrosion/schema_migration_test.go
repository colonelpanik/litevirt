package corrosion

import (
	"errors"
	"testing"
)

func TestIsBenignMigrationError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, true},
		{errors.New("duplicate column name: foo"), true},
		{errors.New("table users already exists"), true},
		{errors.New("DUPLICATE COLUMN NAME"), true},  // case-insensitive
		{errors.New("syntax error near 'SELECT'"), false},
		{errors.New("constraint failed"), false},
		{errors.New("no such table: bogus"), false},
	}
	for _, c := range cases {
		got := isBenignMigrationError(c.err)
		if got != c.want {
			t.Errorf("isBenignMigrationError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// TestInitSchema_IdempotentOnSecondCall verifies that running InitSchema
// twice (the on-restart case) succeeds without error — every ALTER
// reports "duplicate column" the second time and we swallow only those.
func TestInitSchema_IdempotentOnSecondCall(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := t.Context()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("first InitSchema: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("second InitSchema (idempotent): %v", err)
	}
}

// TestInitSchema_RefusesDowngrade verifies the daemon refuses to start when
// the DB's persisted schema_version is higher than the binary expects (the
// "old binary onto forward-migrated DB" footgun).
func TestInitSchema_RefusesDowngrade(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := t.Context()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("first InitSchema: %v", err)
	}
	// Simulate a future binary forward-migrating the DB.
	if err := c.Execute(ctx,
		`UPDATE schema_state SET version = ?, updated_at = datetime('now') WHERE id = 1`,
		CurrentSchemaVersion+5); err != nil {
		t.Fatalf("simulate forward-migrate: %v", err)
	}
	err = InitSchema(ctx, c)
	if err == nil {
		t.Fatal("InitSchema should refuse to run against a forward-migrated DB")
	}
	if !containsFold(err.Error(), "downgrade") {
		t.Errorf("error should mention downgrade; got: %v", err)
	}
}
