package corrosion

import (
	"context"
	"testing"
)

func TestGetRestartState_NotFound(t *testing.T) {
	c := testClient(t)

	got, err := GetRestartState(context.Background(), c, "nonexistent-vm")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing VM, got %+v", got)
	}
}

func TestIncrementRestart_FirstAttempt(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := IncrementRestart(ctx, c, "vm-crash"); err != nil {
		t.Fatalf("IncrementRestart: %v", err)
	}

	got, err := GetRestartState(ctx, c, "vm-crash")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil restart state")
	}
	if got.VMName != "vm-crash" {
		t.Errorf("VMName = %q, want vm-crash", got.VMName)
	}
	if got.AttemptCount != 1 {
		t.Errorf("AttemptCount = %d, want 1", got.AttemptCount)
	}
	if got.WindowStart.IsZero() {
		t.Error("WindowStart should be set")
	}
	if got.LastRestart.IsZero() {
		t.Error("LastRestart should be set")
	}
}

func TestIncrementRestart_MultipleAttempts(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := IncrementRestart(ctx, c, "vm-flaky"); err != nil {
			t.Fatalf("IncrementRestart #%d: %v", i+1, err)
		}
	}

	got, err := GetRestartState(ctx, c, "vm-flaky")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil restart state")
	}
	if got.AttemptCount != 5 {
		t.Errorf("AttemptCount = %d, want 5", got.AttemptCount)
	}
}

func TestResetRestartState(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Increment a few times first
	for i := 0; i < 3; i++ {
		IncrementRestart(ctx, c, "vm-reset")
	}

	if err := ResetRestartState(ctx, c, "vm-reset"); err != nil {
		t.Fatalf("ResetRestartState: %v", err)
	}

	got, err := GetRestartState(ctx, c, "vm-reset")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil restart state after reset")
	}
	if got.AttemptCount != 0 {
		t.Errorf("AttemptCount = %d after reset, want 0", got.AttemptCount)
	}
	if got.WindowStart.IsZero() {
		t.Error("WindowStart should be set after reset")
	}
}

func TestResetRestartState_NoExistingState(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Reset without prior increment should create a zero-count row
	if err := ResetRestartState(ctx, c, "vm-new"); err != nil {
		t.Fatalf("ResetRestartState: %v", err)
	}

	got, err := GetRestartState(ctx, c, "vm-new")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil restart state")
	}
	if got.AttemptCount != 0 {
		t.Errorf("AttemptCount = %d, want 0", got.AttemptCount)
	}
}

func TestDeleteRestartState(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	IncrementRestart(ctx, c, "vm-gone")

	if err := DeleteRestartState(ctx, c, "vm-gone"); err != nil {
		t.Fatalf("DeleteRestartState: %v", err)
	}

	got, err := GetRestartState(ctx, c, "vm-gone")
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

func TestDeleteRestartState_Nonexistent(t *testing.T) {
	c := testClient(t)

	// Deleting a non-existent record should not error
	if err := DeleteRestartState(context.Background(), c, "no-such-vm"); err != nil {
		t.Fatalf("DeleteRestartState on missing VM: %v", err)
	}
}

func TestIncrementRestart_IsolatedPerVM(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	IncrementRestart(ctx, c, "vm-a")
	IncrementRestart(ctx, c, "vm-a")
	IncrementRestart(ctx, c, "vm-b")

	a, _ := GetRestartState(ctx, c, "vm-a")
	b, _ := GetRestartState(ctx, c, "vm-b")

	if a == nil || a.AttemptCount != 2 {
		t.Errorf("vm-a AttemptCount = %v, want 2", a)
	}
	if b == nil || b.AttemptCount != 1 {
		t.Errorf("vm-b AttemptCount = %v, want 1", b)
	}
}
