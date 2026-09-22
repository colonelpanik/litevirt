package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// epochServer is a 2-host detector with owner_epoch_v1 latched.
func epochServer(t *testing.T) *Server {
	t.Helper()
	s := dualRunTestServer(t, 2)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.OwnerEpochV1: true}})
	return s
}

// twice runs the detector the two passes a condition needs to CONFIRM.
func twice(s *Server) {
	ctx := context.Background()
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
}

// ── Lever 1: state = 'migrating' ─────────────────────────────────────────

// A migration state legitimately excuses the epoch check while a cutover is in
// flight. Left unbounded it is the cheapest permanent suppression there is:
// ONE write of state='migrating', nothing to renew, and the VM is never
// examined again.
//
// Past migrationGrace a VM still parked in the state is a wedged migration,
// and the suppression itself must surface.
func TestEpochSuppression_WedgedMigrationSurfaces(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "migrating")
	// Epoch 7 in the DB, marker says 3 — a mismatch the check would page if
	// the migration state were not hiding it.
	stale := time.Now().Add(-2 * migrationGrace).UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = 7, updated_at = ? WHERE name = 'vmA'`, stale); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 3, status: MarkerValid}}},
		"h2": {},
	})
	twice(s)

	if !confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("a VM parked in 'migrating' well past migrationGrace still suppressed the " +
			"owner-epoch check; one write of state='migrating' disables it permanently")
	}
}

// A migration actually in flight must stay exempt — this is the false positive
// the grace exists to avoid.
func TestEpochSuppression_FreshMigrationStaysExempt(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "migrating")
	fresh := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = 7, updated_at = ? WHERE name = 'vmA'`, fresh); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 3, status: MarkerValid}}},
		"h2": {},
	})
	twice(s)

	if confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("a migration that started moments ago must stay exempt — cutover lag is legitimate")
	}
}

// ── Lever 2: deleted_at ──────────────────────────────────────────────────

// ListVMs filters `deleted_at IS NULL`, so one write of deleted_at removes the
// VM from the detector's index entirely — no epoch check, no owner check, and
// nothing to renew. A tombstoned row whose runtime is STILL RUNNING is not a
// deleted VM; it is an unexamined running workload.
func TestEpochSuppression_TombstonedButStillRunning(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")
	if err := s.db.Execute(ctx,
		`UPDATE vms SET deleted_at = ? WHERE name = 'vmA'`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	// The runtime disagrees: h1 is still running it.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 3, status: MarkerValid}}},
		"h2": {},
	})
	twice(s)

	if !confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("a tombstoned VM still running on a host did not surface; setting deleted_at " +
			"removes it from the detector's view permanently")
	}
}

// A tombstoned VM that is genuinely gone from every runtime is a normal
// delete and must stay silent.
func TestEpochSuppression_TombstonedAndActuallyGone(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")
	if err := s.db.Execute(ctx,
		`UPDATE vms SET deleted_at = ? WHERE name = 'vmA'`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {},
	})
	twice(s)

	if confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("an ordinary completed delete must not page")
	}
}

// ── Lever 3: host_name pointing at a host that does not exist ────────────

// The epoch check skips a VM whose owner was not probed, deferring to the
// coverage signal. That is right for a real host we could not reach — but a
// host_name naming a host that is not in the cluster at all is never going to
// be probed, so the skip is permanent and no coverage finding names the VM.
func TestEpochSuppression_OwnerIsNotAKnownHost(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")
	if err := s.db.Execute(ctx,
		`UPDATE vms SET host_name = 'ghost-host', vm_owner_epoch = 7 WHERE name = 'vmA'`); err != nil {
		t.Fatalf("repoint: %v", err)
	}
	// It is really running on h2, which we can see.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 3, status: MarkerValid}}},
	})
	twice(s)

	if !confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("a VM whose host_name names a non-existent host escaped the epoch check " +
			"permanently — it can never be probed, so the coverage deferral never resolves")
	}
}

// A real host that simply could not be reached this pass must still defer to
// the coverage signal, not page as a suppression.
func TestEpochSuppression_UnreachableRealOwnerDefersToCoverage(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h2", "running")
	if err := s.db.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vmA'`); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	// h2 is a genuine cluster host, just unreachable this pass — and the VM IS
	// visibly running, on h1. The runtime evidence has to be present or this
	// test cannot tell the ghost-owner branch from the holder guard: with no
	// holder anywhere, both the real and the mutated predicate skip, and the
	// assertion below passes without exercising anything.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 3, status: MarkerValid}}},
	}, "h2")
	twice(s)

	if confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("an unreachable but REAL owner must defer to the coverage finding, not page as suppression")
	}
	if !confirmedCond(s, kindDualRunCoverage, "h2") {
		t.Fatal("the unreachable host must still raise a coverage finding")
	}
}

// ── The boundary itself ──────────────────────────────────────────────────

// A stamp far in the future must not buy indefinite suppression. withinGrace
// bounds the window in BOTH directions for exactly this reason.
func TestEpochSuppression_FutureStampDoesNotSuppressForever(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "migrating")
	future := time.Now().Add(100 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = 7, updated_at = ? WHERE name = 'vmA'`, future); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 3, status: MarkerValid}}},
		"h2": {},
	})
	twice(s)

	if !confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("an updated_at a century in the future kept the migration exemption open; " +
			"the grace must be bounded on the future side too")
	}
}

// Sanity: a healthy VM trips none of this.
func TestEpochSuppression_HealthyVMIsSilent(t *testing.T) {
	s := epochServer(t)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")
	if err := s.db.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = 9 WHERE name = 'vmA'`); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 9, status: MarkerValid}}},
		"h2": {},
	})
	twice(s)

	if confirmedCond(s, kindEpochSuppressed, "vmA") {
		t.Fatal("a healthy owner-epoch match raised a suppression finding")
	}
	if confirmedCond(s, kindEpochMismatch, "vmA") {
		t.Fatal("a healthy owner-epoch match raised a mismatch finding")
	}
}

var _ = corrosion.SeverityCritical
