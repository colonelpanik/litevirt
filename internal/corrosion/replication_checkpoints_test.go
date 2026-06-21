package corrosion

import (
	"context"
	"testing"
)

// TestReplicationCheckpoint covers the v22 per-VM anchor table: per-(vm,repo)
// keying (so fan-out VMs don't share/clobber one anchor — bug-sweep #6), and
// reset-then-reuse.
func TestReplicationCheckpoint(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if cp, _ := GetReplicationCheckpoint(ctx, c, "vm1", "dr"); cp != "" {
		t.Fatalf("expected empty before set, got %q", cp)
	}
	if err := SetReplicationCheckpoint(ctx, c, "vm1", "dr", "lvrepl-root-ts1"); err != nil {
		t.Fatal(err)
	}
	// A different real VM under the SAME repo persists independently (the
	// fan-out case that used to clobber via the shared sentinel row).
	if err := SetReplicationCheckpoint(ctx, c, "vm2", "dr", "lvrepl-root-ts2"); err != nil {
		t.Fatal(err)
	}
	if cp, _ := GetReplicationCheckpoint(ctx, c, "vm1", "dr"); cp != "lvrepl-root-ts1" {
		t.Errorf("vm1 anchor = %q, want lvrepl-root-ts1 (no cross-VM contamination)", cp)
	}
	if cp, _ := GetReplicationCheckpoint(ctx, c, "vm2", "dr"); cp != "lvrepl-root-ts2" {
		t.Errorf("vm2 anchor = %q, want lvrepl-root-ts2", cp)
	}

	// Upsert advances the same row.
	if err := SetReplicationCheckpoint(ctx, c, "vm1", "dr", "lvrepl-root-ts3"); err != nil {
		t.Fatal(err)
	}
	if cp, _ := GetReplicationCheckpoint(ctx, c, "vm1", "dr"); cp != "lvrepl-root-ts3" {
		t.Errorf("after upsert vm1 anchor = %q, want lvrepl-root-ts3", cp)
	}

	// Reset (empty) tombstones → next read empty; then re-set works.
	if err := SetReplicationCheckpoint(ctx, c, "vm1", "dr", ""); err != nil {
		t.Fatal(err)
	}
	if cp, _ := GetReplicationCheckpoint(ctx, c, "vm1", "dr"); cp != "" {
		t.Errorf("after reset vm1 anchor = %q, want empty", cp)
	}
	if err := SetReplicationCheckpoint(ctx, c, "vm1", "dr", "lvrepl-root-ts4"); err != nil {
		t.Fatal(err)
	}
	if cp, _ := GetReplicationCheckpoint(ctx, c, "vm1", "dr"); cp != "lvrepl-root-ts4" {
		t.Errorf("re-set after reset = %q, want lvrepl-root-ts4", cp)
	}
}
