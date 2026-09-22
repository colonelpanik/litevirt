package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func lockDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

func lockHolder(t *testing.T, db *corrosion.Client, vm string) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT holder FROM vm_locks WHERE vm_name = ?`, vm)
	if err != nil {
		t.Fatalf("read vm_locks: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("holder")
}

// The per-VM lease exists to stop two QEMU processes writing one disk. Both
// the reconciler's start path and the restart-policy path take it, and both
// passed the bare host name as the holder.
//
// The upsert's guard is `... WHERE expires_at < ? OR holder = excluded.holder`,
// so the same-holder clause matched unconditionally and the restart path
// acquired the lease the reconciler was already holding for a start in
// progress. Its deferred release then DELETEs by holder, freeing a lease the
// reconciler still depends on — after which a peer reading host_name=self can
// take it and call StartDomain on the same disk.
func TestVMLock_RestartPathCannotStealTheReconcilersLease(t *testing.T) {
	db := testStartDB(t)
	ctx := context.Background()
	seedRestartPolicyVM(t, db, "vm1", "node1")

	// The reconciler holds the lease for a start already in flight on THIS
	// host. Held via the reconciler's own identity, exactly as startPendingVM
	// takes it.
	if !acquireVMLockFor(ctx, db, reconcilerLockHolder("node1"), "vm1", time.Now()) {
		t.Fatal("reconciler could not take the lease")
	}

	// Drive the REAL restart path, not the helper — the defect is which
	// identity vmcheck passes, so a test that calls the helper itself would
	// pass whatever vmcheck does.
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	v.maybeRestartVM(ctx, *vm, time.Now())

	if got := restartAttempts(t, db, "vm1"); got != 0 {
		t.Fatalf("restart attempts = %d, want 0 — the reconciler holds the lease for a "+
			"start in flight; two starters for one disk is the corruption it prevents", got)
	}
	if got := lockHolder(t, db, "vm1"); got != reconcilerLockHolder("node1") {
		t.Fatalf("holder after the restart pass = %q, want the reconciler still holding it; "+
			"a freed lease lets a peer start the same VM", got)
	}
}

// And the mirror: a release from the restart path must not free a lease the
// reconciler holds.
func TestVMLock_RestartReleaseCannotFreeTheReconcilersLease(t *testing.T) {
	db := lockDB(t)
	ctx := context.Background()

	if !acquireVMLockFor(ctx, db, reconcilerLockHolder("node1"), "vm1", time.Now()) {
		t.Fatal("reconciler could not take the lease")
	}
	releaseVMLockFor(ctx, db, vmcheckLockHolder("node1"), "vm1")

	if got := lockHolder(t, db, "vm1"); got != reconcilerLockHolder("node1") {
		t.Fatalf("after a restart-path release the holder is %q, want the reconciler still holding it; "+
			"a freed lease lets a peer start the same VM", got)
	}
}

// The reverse direction matters too: while the restart path is rebooting a
// VM, the reconciler must not start it underneath.
func TestVMLock_ReconcilerCannotStealTheRestartPathsLease(t *testing.T) {
	db := lockDB(t)
	ctx := context.Background()
	now := time.Now()

	if !acquireVMLockFor(ctx, db, vmcheckLockHolder("node1"), "vm1", now) {
		t.Fatal("restart path could not take the lease")
	}
	if acquireVMLockFor(ctx, db, reconcilerLockHolder("node1"), "vm1", now) {
		t.Fatal("the reconciler acquired a lease the restart path holds")
	}
}

// Each component must still be able to RE-take its own lease — the
// same-holder clause is what makes acquire idempotent across passes.
func TestVMLock_EachHolderIsStillIdempotent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	for _, holder := range []string{reconcilerLockHolder("node1"), vmcheckLockHolder("node1")} {
		db := lockDB(t)
		if !acquireVMLockFor(ctx, db, holder, "vm1", now) {
			t.Fatalf("%s: first acquire failed", holder)
		}
		if !acquireVMLockFor(ctx, db, holder, "vm1", now.Add(time.Second)) {
			t.Fatalf("%s: re-acquiring its OWN lease must succeed", holder)
		}
	}
}

// A different HOST is still refused, whichever component is asking — the
// component suffix must not accidentally make two hosts look distinct enough
// to both hold it.
func TestVMLock_ADifferentHostIsStillRefused(t *testing.T) {
	db := lockDB(t)
	ctx := context.Background()
	now := time.Now()

	if !acquireVMLockFor(ctx, db, reconcilerLockHolder("node1"), "vm1", now) {
		t.Fatal("node1 could not take the lease")
	}
	if acquireVMLockFor(ctx, db, reconcilerLockHolder("node2"), "vm1", now) {
		t.Fatal("node2 acquired a lease node1 holds")
	}
	if acquireVMLockFor(ctx, db, vmcheckLockHolder("node2"), "vm1", now) {
		t.Fatal("node2's restart path acquired a lease node1 holds")
	}
}

// Mid-upgrade, a lease row on disk may have been written by an older binary
// that used the bare host name as the holder. The reconciler must still
// recognise that row as its own, or a rolling upgrade strands every in-flight
// lease for the full vmLockTTL while the new binary refuses to re-take a lease
// it actually holds.
//
// This is why reconcilerLockHolder is the identity function and only the
// restart path took a new suffix. Giving BOTH components a suffix would be
// tidier and would break exactly this.
func TestVMLock_ReconcilerRecognisesAPreUpgradeLease(t *testing.T) {
	db := lockDB(t)
	ctx := context.Background()
	now := time.Now()

	// Written the way an older binary wrote it: holder == bare host name.
	if err := db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES (?,?,?,?)`,
		"vm1", "node1",
		now.Add(vmLockTTL).UTC().Format(time.RFC3339),
		now.UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed pre-upgrade lease: %v", err)
	}

	if !acquireVMLockFor(ctx, db, reconcilerLockHolder("node1"), "vm1", now) {
		t.Fatal("the reconciler could not re-take a lease written by an older binary on this " +
			"same host; a rolling upgrade would strand every in-flight lease for vmLockTTL")
	}
}
