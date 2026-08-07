package corrosion

import (
	"context"
	"errors"
	"testing"
)

// The tri-state outcome is what keeps a delete's callers honest: absent is the
// idempotent success, contended means the row is STILL LIVE and the delete did
// not land. Conflating them (the pre-fix probe re-read did, structurally) let
// grpcapi report "already absent" success for a live row.

func TestGuardedDeleteOutcomeClassification(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// Absent: no row at all.
	if outcome, err := deleteContainerGuarded(ctx, c, "h1", "nope"); err != nil || outcome != deleteAbsent {
		t.Fatalf("missing row: outcome=%v err=%v, want deleteAbsent", outcome, err)
	}

	// Applied: a live row deletes cleanly.
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "ct1", State: "running", Image: "alpine"}); err != nil {
		t.Fatal(err)
	}
	if outcome, err := deleteContainerGuarded(ctx, c, "h1", "ct1"); err != nil || outcome != deleteApplied {
		t.Fatalf("live row: outcome=%v err=%v, want deleteApplied", outcome, err)
	}

	// Absent again: the tombstone left behind is not a live row.
	if outcome, err := deleteContainerGuarded(ctx, c, "h1", "ct1"); err != nil || outcome != deleteAbsent {
		t.Fatalf("tombstoned row: outcome=%v err=%v, want deleteAbsent", outcome, err)
	}

	// Contended: the guard snapshot moved before the CAS. The row must stay
	// LIVE — a contended delete that still tombstoned would be worse than the
	// bug it fixes.
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "ct2", State: "running", Image: "alpine"}); err != nil {
		t.Fatal(err)
	}
	stale, err := GetContainer(ctx, c, "h1", "ct2")
	if err != nil || stale == nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if _, err := c.db.Exec(`UPDATE containers SET spec_generation = spec_generation + 1 WHERE host_name = 'h1' AND name = 'ct2'`); err != nil {
		t.Fatal(err)
	}
	if outcome, err := deleteContainerGuardedFrom(ctx, c, *stale); err != nil || outcome != deleteContended {
		t.Fatalf("stale snapshot: outcome=%v err=%v, want deleteContended", outcome, err)
	}
	if ct, _ := GetContainer(ctx, c, "h1", "ct2"); ct == nil {
		t.Fatal("a contended delete must leave the row live")
	}

	// Same classification on the VM side.
	if outcome, err := deleteVMGuarded(ctx, c, "novm"); err != nil || outcome != deleteAbsent {
		t.Fatalf("missing VM: outcome=%v err=%v, want deleteAbsent", outcome, err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	staleVM, err := GetVM(ctx, c, "vm1")
	if err != nil || staleVM == nil {
		t.Fatalf("read VM snapshot: %v", err)
	}
	if _, err := c.db.Exec(`UPDATE vms SET spec_generation = spec_generation + 1 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	if outcome, err := deleteVMGuardedFrom(ctx, c, *staleVM); err != nil || outcome != deleteContended {
		t.Fatalf("stale VM snapshot: outcome=%v err=%v, want deleteContended", outcome, err)
	}
	if vm, _ := GetVM(ctx, c, "vm1"); vm == nil {
		t.Fatal("a contended VM delete must leave the row live")
	}
}

// retriedDelete: transient contention is absorbed with a fresh attempt;
// persistent contention is reported, bounded by deleteGuardAttempts.
func TestRetriedDelete(t *testing.T) {
	calls := 0
	outcome, err := retriedDelete(func() (deleteOutcome, error) {
		calls++
		if calls < 2 {
			return deleteContended, nil
		}
		return deleteApplied, nil
	})
	if err != nil || outcome != deleteApplied || calls != 2 {
		t.Fatalf("transient contention: outcome=%v err=%v calls=%d, want applied after 2", outcome, err, calls)
	}

	calls = 0
	outcome, err = retriedDelete(func() (deleteOutcome, error) {
		calls++
		return deleteContended, nil
	})
	if err != nil || outcome != deleteContended || calls != deleteGuardAttempts {
		t.Fatalf("persistent contention: outcome=%v err=%v calls=%d, want contended after %d",
			outcome, err, calls, deleteGuardAttempts)
	}
}

// deleteOutcomeError is the whole caller-visible contract in one place:
// contended is ALWAYS an error — for the strict writers AND the plain ones —
// and absent maps to the strict/idempotent split.
func TestDeleteOutcomeError(t *testing.T) {
	for _, tc := range []struct {
		outcome deleteOutcome
		strict  bool
		want    error
	}{
		{deleteApplied, false, nil},
		{deleteApplied, true, nil},
		{deleteAbsent, false, nil},
		{deleteAbsent, true, ErrNoRowsAffected},
		{deleteContended, false, ErrDeleteContended},
		{deleteContended, true, ErrDeleteContended},
	} {
		got := deleteOutcomeError(tc.outcome, tc.strict)
		if !errors.Is(got, tc.want) && !(got == nil && tc.want == nil) {
			t.Errorf("deleteOutcomeError(%v, strict=%v) = %v, want %v", tc.outcome, tc.strict, got, tc.want)
		}
	}
}

// The epoch-carried heal writers must match NOTHING when the row's ownership
// generation has moved past the writer's decision — that is their whole point
// (a stale node's heal must not stamp state onto a recreated/re-owned row).
func TestSetContainerStateDetailAtEpoch_EpochPredicate(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "ct1", State: "running", Image: "alpine"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`UPDATE containers SET owner_epoch = 2 WHERE host_name = 'h1' AND name = 'ct1'`); err != nil {
		t.Fatal(err)
	}

	// Stale decision (epoch 1): must change nothing; strict must say so.
	if err := SetContainerStateDetailAtEpoch(ctx, c, "h1", "ct1", "stopped", "stale", 1); err != nil {
		t.Fatalf("stale plain write errored: %v", err)
	}
	err := SetContainerStateDetailStrictAtEpoch(ctx, c, "h1", "ct1", "stopped", "stale", 1)
	if !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("stale strict write: err=%v, want ErrNoRowsAffected", err)
	}
	ct, _ := GetContainer(ctx, c, "h1", "ct1")
	if ct == nil || ct.State != "running" || ct.StateDetail != "" {
		t.Fatalf("a stale-epoch heal must not land: %+v", ct)
	}

	// Current decision (epoch 2): lands.
	if err := SetContainerStateDetailStrictAtEpoch(ctx, c, "h1", "ct1", "stopped", "current", 2); err != nil {
		t.Fatalf("current strict write: %v", err)
	}
	ct, _ = GetContainer(ctx, c, "h1", "ct1")
	if ct == nil || ct.State != "stopped" || ct.StateDetail != "current" {
		t.Fatalf("the current-epoch heal must land: %+v", ct)
	}
}
