package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func resetAdminTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// `lv user reset-admin` must not resurrect a deliberately deleted admin.
//
// GetUser filters `deleted_at IS NULL`, so a tombstoned admin reads as absent.
// The old create-if-missing branch then called InsertUser, whose first branch
// reactivates a soft-deleted row (`SET deleted_at = NULL`) — replicating a
// revoked account back to life cluster-wide, with a fresh password, from a
// command whose documented job is to *reset* an existing one.
//
// The daemon's own seed path was given a tombstone-aware guard; this is the
// second mint site, and it had none.
func TestResetAdminPassword_DoesNotResurrectADeletedAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := corrosion.DeleteUser(ctx, db, "admin"); err != nil {
		t.Fatalf("delete admin: %v", err)
	}

	err := resetAdminPassword(ctx, db, pw)
	if err == nil {
		t.Fatal("reset-admin succeeded against a deleted admin; it either resurrected the " +
			"revoked account or minted a new one, and that replicates cluster-wide")
	}
	if u, gErr := corrosion.GetUser(ctx, db, "admin"); gErr != nil || u != nil {
		t.Errorf("the admin account is live again after reset-admin (%v, err %v)", u, gErr)
	}
	if _, sErr := os.Stat(pw); sErr == nil {
		t.Error("a password file was written for an account that must not exist")
	}
}

// A cluster that genuinely has no admin must get a clear refusal, not a silent
// mint — on a joining node the credential arrives by replication.
func TestResetAdminPassword_RefusesWhenThereIsNoAdminAtAll(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	err := resetAdminPassword(ctx, db, pw)
	if err == nil {
		t.Fatal("reset-admin minted an admin on a cluster that has none; that row wins LWW " +
			"and replaces the real credential on every peer once replication converges")
	}
	if !strings.Contains(err.Error(), "replicat") {
		t.Errorf("the refusal does not tell the operator where the credential comes from: %v", err)
	}
}

// The ordinary case still works.
func TestResetAdminPassword_ResetsALiveAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := resetAdminPassword(ctx, db, pw); err != nil {
		t.Fatalf("resetAdminPassword: %v", err)
	}

	u, err := corrosion.GetUser(ctx, db, "admin")
	if err != nil || u == nil {
		t.Fatalf("admin missing after a reset: %v %v", u, err)
	}
	if u.PasswordHash == "$2a$10$stub" {
		t.Error("the password hash was not changed")
	}
	b, err := os.ReadFile(pw)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	if len(strings.TrimSpace(string(b))) != 32 {
		t.Errorf("password file holds %q, want a 32-char hex password", strings.TrimSpace(string(b)))
	}
	if fi, _ := os.Stat(pw); fi != nil && fi.Mode().Perm() != 0600 {
		t.Errorf("password file mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// A failing lookup must not read as "there is no admin".
//
// This is the same class as the merged "a read that fails must not read as
// absence" work: with the error discarded, a transient local database failure is
// indistinguishable from an empty users table, and whatever the nil branch does
// then happens for the wrong reason.
func TestResetAdminPassword_AFailedLookupIsNotAnAbsentAdmin(t *testing.T) {
	ctx := context.Background()
	db := resetAdminTestDB(t)
	pw := filepath.Join(t.TempDir(), "admin-password")

	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "$2a$10$stub"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	// Make the read fail: a closed client cannot answer.
	db.Close()

	err := resetAdminPassword(ctx, db, pw)
	if err == nil {
		t.Fatal("reset-admin succeeded although the admin lookup could not run")
	}
	if strings.Contains(err.Error(), "no live admin account") {
		t.Errorf("a failed lookup was reported as an absent admin: %v\n"+
			"the database was unreadable, not empty — those need different answers", err)
	}
}
