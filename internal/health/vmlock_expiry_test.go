package health

import (
	"context"
	"testing"
	"time"
)

// TestReconciler_VMLockTakeoverWhenExpired guards the RFC3339-vs-datetime('now')
// string-compare bug in the reconciler's vm_lock: expires_at is RFC3339, and
// the acquire compared it against datetime('now') as a string — same-day,
// 'T' > ' ' makes a lock never look expired, so a crashed holder's vm_lock
// would block another host from reconciling that VM until the UTC date rolled.
func TestReconciler_VMLockTakeoverWhenExpired(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)

	// Expired lock held by another host (same UTC day) → takeover.
	exp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES ('vm1','other',?,?)`,
		exp, exp); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	if !r.acquireVMLock(ctx, "vm1") {
		t.Fatal("must take over an expired same-day vm_lock")
	}

	// Valid lock held by another host → not stolen.
	valid := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES ('vm2','other',?,?)`,
		valid, valid); err != nil {
		t.Fatalf("seed valid lock: %v", err)
	}
	if r.acquireVMLock(ctx, "vm2") {
		t.Error("must NOT steal a still-valid vm_lock")
	}
}
