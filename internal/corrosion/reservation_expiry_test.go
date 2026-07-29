package corrosion

import (
	"context"
	"testing"
	"time"
)

// insertAgedOp writes an operation with a chosen created_at so expiry can be tested
// without sleeping.
func insertAgedOp(t *testing.T, db *Client, id, kind, resourceKind string, age time.Duration, cpu, mem int) {
	t.Helper()
	ctx := context.Background()
	rv := ReservationVector{TargetHost: "h1", TargetCPU: cpu, TargetMemMiB: mem}
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := InsertOperation(ctx, db, OperationRecord{
		ID: id, Method: "CreateVM", ResourceKind: resourceKind,
		OperationKind: kind, ReservationJSON: enc,
	}); err != nil {
		t.Fatalf("InsertOperation %s: %v", id, err)
	}
	when := time.Now().Add(-age).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx, `UPDATE operations SET created_at = ? WHERE id = ?`, when, id); err != nil {
		t.Fatalf("age %s: %v", id, err)
	}
}

// TestExpireStaleCapacityReservations_ReleasesOrphans: reserve-then-verify made a
// crash between reserve and release leak capacity permanently — the terminal reaper
// cannot collect a lease that never became terminal, so it consumed headroom with
// no workload behind it.
func TestExpireStaleCapacityReservations_ReleasesOrphans(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertAgedOp(t, db, "orphaned", string(OpResourceUpdateRunning), CapacityResourceKind, time.Hour, 2, 2048)

	held, _, err := HostReserved(ctx, db, "h1")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if held != 2 {
		t.Fatalf("reserved vCPU = %d before expiry, want 2 (the orphan must be counted, or this proves nothing)", held)
	}

	n, err := ExpireStaleCapacityReservations(ctx, db, 15*time.Minute)
	if err != nil {
		t.Fatalf("ExpireStaleCapacityReservations: %v", err)
	}
	if n != 1 {
		t.Errorf("expired %d leases, want 1", n)
	}
	after, _, err := HostReserved(ctx, db, "h1")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if after != 0 {
		t.Errorf("reserved vCPU = %d after expiry, want 0 — the orphan still consumes capacity", after)
	}
}

// TestExpireStaleCapacityReservations_LeavesFreshLeasesAlone: expiring a lease a
// live admission is still deciding against would free capacity out from under it —
// worse than leaking one.
func TestExpireStaleCapacityReservations_LeavesFreshLeasesAlone(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertAgedOp(t, db, "fresh", string(OpResourceUpdateRunning), CapacityResourceKind, time.Second, 2, 2048)

	n, err := ExpireStaleCapacityReservations(ctx, db, 15*time.Minute)
	if err != nil {
		t.Fatalf("ExpireStaleCapacityReservations: %v", err)
	}
	if n != 0 {
		t.Errorf("expired %d fresh leases, want 0", n)
	}
	held, _, _ := HostReserved(ctx, db, "h1")
	if held != 2 {
		t.Errorf("reserved vCPU = %d, want 2 — a live admission's lease was freed under it", held)
	}
}

// TestExpireStaleCapacityReservations_NeverTouchesSpecBackedOperations is the
// property the F2 item names directly: expiry must never free capacity backed by a
// persisted spec or runtime.
//
// A resize or migration legitimately stays nonterminal for a long time, and its
// reservation IS spoken for. A blanket "cancel old nonterminal operations" sweep
// would eventually free it and let the cluster admit capacity that is already
// committed — which is why the sweep is scoped by resource kind, not just by age.
func TestExpireStaleCapacityReservations_NeverTouchesSpecBackedOperations(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// An ancient, still-running resize — far older than the horizon.
	insertAgedOp(t, db, "long-resize", string(OpResourceUpdateRunning), "vm", 24*time.Hour, 4, 4096)

	n, err := ExpireStaleCapacityReservations(ctx, db, time.Minute)
	if err != nil {
		t.Fatalf("ExpireStaleCapacityReservations: %v", err)
	}
	if n != 0 {
		t.Fatalf("expired %d spec-backed operations, want 0 — freeing a committed resize's reservation lets the cluster admit capacity that is already spoken for", n)
	}
	held, _, _ := HostReserved(ctx, db, "h1")
	if held != 4 {
		t.Errorf("reserved vCPU = %d, want 4 — the resize's reservation was released", held)
	}
}
