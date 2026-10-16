package corrosion

import (
	"context"
	"testing"
)

// TestUpdateHostStateFrom_OnlyFromRecordedState proves the write lands only
// while the host is recorded in the expected state: a fence or drain recorded
// first is kept, not overwritten.
func TestUpdateHostStateFrom_OnlyFromRecordedState(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		recorded    string
		wantApplied bool
		wantState   string
	}{
		{"upgrading", true, "active"},
		{"fenced", false, "fenced"},
		{"draining", false, "draining"},
		{"offline", false, "offline"},
	} {
		t.Run(tc.recorded, func(t *testing.T) {
			db, err := NewTestClient()
			if err != nil {
				t.Fatalf("NewTestClient: %v", err)
			}
			t.Cleanup(func() { db.Close() })
			if err := InitSchema(ctx, db); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			if err := InsertHost(ctx, db, HostRecord{
				Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: tc.recorded,
			}); err != nil {
				t.Fatalf("InsertHost: %v", err)
			}
			applied, err := UpdateHostStateFrom(ctx, db, "h", "upgrading", "active")
			if err != nil {
				t.Fatalf("UpdateHostStateFrom: %v", err)
			}
			if applied != tc.wantApplied {
				t.Fatalf("applied = %v, want %v", applied, tc.wantApplied)
			}
			h, err := GetHost(ctx, db, "h")
			if err != nil || h == nil {
				t.Fatalf("GetHost: %v", err)
			}
			if h.State != tc.wantState {
				t.Fatalf("state = %q, want %q", h.State, tc.wantState)
			}
		})
	}
}

// TestUpdateHostStateFrom_AbsentHost declines without error.
func TestUpdateHostStateFrom_AbsentHost(t *testing.T) {
	ctx := context.Background()
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	applied, err := UpdateHostStateFrom(ctx, db, "nope", "upgrading", "active")
	if err != nil || applied {
		t.Fatalf("applied=%v err=%v, want false, nil", applied, err)
	}
}
