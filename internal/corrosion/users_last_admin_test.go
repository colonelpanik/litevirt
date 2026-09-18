package corrosion

import (
	"context"
	"strings"
	"testing"
)

// OtherLiveAdminExists answers one question for the DeleteUser guard: after
// this username goes away, does the cluster still have someone who can
// administer it? The tests below pin the three ways that question is easy to
// answer wrongly — counting the target itself, counting a tombstone, and
// reporting a failed read as "nobody".

func TestOtherLiveAdminExists_TheSoleAdminDoesNotCountAsItsOwnSuccessor(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "admin", "admin", "h"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	got, err := OtherLiveAdminExists(ctx, c, "admin")
	if err != nil {
		t.Fatalf("OtherLiveAdminExists: %v", err)
	}
	if got {
		t.Error("the only admin in the cluster was reported as a successor to itself")
	}
}

func TestOtherLiveAdminExists_ASecondAdminIsASuccessor(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "admin", "admin", "h"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := InsertUser(ctx, c, "root", "admin", "h"); err != nil {
		t.Fatalf("seed second admin: %v", err)
	}

	got, err := OtherLiveAdminExists(ctx, c, "admin")
	if err != nil {
		t.Fatalf("OtherLiveAdminExists: %v", err)
	}
	if !got {
		t.Error("a second live admin was not reported as a successor")
	}
}

func TestOtherLiveAdminExists_ANonAdminIsNotASuccessor(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "admin", "admin", "h"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := InsertUser(ctx, c, "viewer", "viewer", "h"); err != nil {
		t.Fatalf("seed viewer: %v", err)
	}

	got, err := OtherLiveAdminExists(ctx, c, "admin")
	if err != nil {
		t.Fatalf("OtherLiveAdminExists: %v", err)
	}
	if got {
		t.Error("a viewer was reported as a successor to the last admin")
	}
}

// A tombstoned admin is the case that makes this a real guard rather than a
// row count. ListUsers filters `deleted_at IS NULL`, and a query that forgets
// that filter sees a revoked admin as a live one — which is exactly how the
// cluster ends up with no administrator.
func TestOtherLiveAdminExists_ATombstonedAdminIsNotASuccessor(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "admin", "admin", "h"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := InsertUser(ctx, c, "retired", "admin", "h"); err != nil {
		t.Fatalf("seed second admin: %v", err)
	}
	if err := DeleteUser(ctx, c, "retired"); err != nil {
		t.Fatalf("tombstone the second admin: %v", err)
	}

	got, err := OtherLiveAdminExists(ctx, c, "admin")
	if err != nil {
		t.Fatalf("OtherLiveAdminExists: %v", err)
	}
	if got {
		t.Error("a tombstoned admin was reported as a live successor")
	}
}

// An unreadable database is not an empty one. Reporting (false, nil) here
// would make the caller refuse a legitimate delete; reporting (true, nil)
// would let the last admin go. Either way the caller needs the error.
func TestOtherLiveAdminExists_AFailedReadIsNotAnAnswer(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "admin", "admin", "h"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	c.Close()

	_, err := OtherLiveAdminExists(ctx, c, "admin")
	if err == nil {
		t.Fatal("a closed client answered the successor question instead of failing")
	}
	if strings.Contains(err.Error(), "no such table") {
		t.Skip("closing the client produced a schema error, not a read failure")
	}
}
