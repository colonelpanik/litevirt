package corrosion

import (
	"context"
	"testing"
)

// failContainerInserts installs a trigger that aborts any INSERT into
// containers, so the relocation's TARGET write fails while the source
// tombstone (an UPDATE) is unaffected. That is the exact shape of the failure
// #215 describes — a tick deadline, SQLITE_BUSY or a restart landing between
// the two writes.
func failContainerInserts(t *testing.T, c *Client) func() {
	t.Helper()
	if _, err := c.db.Exec(`CREATE TRIGGER fail_ct_insert BEFORE INSERT ON containers
		BEGIN SELECT RAISE(ABORT, 'injected target-insert failure'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	return func() {
		if _, err := c.db.Exec(`DROP TRIGGER fail_ct_insert`); err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
	}
}

func seedRelocatableContainer(t *testing.T, c *Client, host, name string, lifecycle bool) {
	t.Helper()
	rec := ContainerRecord{
		HostName: host, Name: name, State: "running", Image: "alpine",
		CPULimit: 1, MemMiB: 256, Project: "_default",
	}
	if err := UpsertContainer(context.Background(), c, rec); err != nil {
		t.Fatalf("UpsertContainer(%s/%s): %v", host, name, err)
	}
	if !lifecycle {
		return
	}
	// UpsertContainer does not carry the lifecycle columns, and they are what
	// select the guarded relocation shape over the retained pre-epoch one. Set
	// them directly so the two paths are genuinely both covered.
	if _, err := c.db.Exec(
		`UPDATE containers SET owner_epoch = 3, spec_generation = 2 WHERE host_name = ? AND name = ?`,
		host, name); err != nil {
		t.Fatalf("set lifecycle columns: %v", err)
	}
}

// TestRelocateContainerWithToken_FailedTargetLeavesTheSourceLive is the #215
// regression.
//
// The relocation tombstoned the source and created the target in TWO separate
// transactions. A failure in between — a tick deadline, SQLITE_BUSY, a restart
// — left NO live row at either host, with the source tombstone already
// replicated. The sweep that would retry iterates LIVE containers on the dead
// host and finds nothing, so the container is simply gone from cluster state.
//
// Delete-first is the worse of the two orderings: insert-first would at least
// leave a recoverable duplicate. Both siblings in this file are atomic, and
// CreateContainerAtomic's comment says why.
func TestRelocateContainerWithToken_FailedTargetLeavesTheSourceLive(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "web", true)

	restore := failContainerInserts(t, c)
	err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok-1")
	restore()

	if err == nil {
		t.Fatal("expected the injected target-insert failure to surface")
	}
	src, gErr := GetContainer(ctx, c, "host-a", "web")
	if gErr != nil {
		t.Fatalf("GetContainer(source): %v", gErr)
	}
	if src == nil {
		t.Fatal("the container vanished: the source was tombstoned and the target never " +
			"landed, so no live row exists at either host and nothing will retry")
	}
	if dst, _ := GetContainer(ctx, c, "host-b", "web"); dst != nil {
		t.Errorf("a failed relocation left a target row: %+v", dst)
	}
}

// The same for a pre-epoch source, which takes the retained wire-compatible
// upsert rather than the guarded insert — both are INSERTs, and both must be
// in the same transaction as the source tombstone.
func TestRelocateContainerWithToken_PreEpochFailureAlsoLeavesTheSourceLive(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "legacy", false)

	restore := failContainerInserts(t, c)
	err := RelocateContainerWithToken(ctx, c, "host-a", "legacy", "host-b", "tok-2")
	restore()

	if err == nil {
		t.Fatal("expected the injected target-insert failure to surface")
	}
	if src, _ := GetContainer(ctx, c, "host-a", "legacy"); src == nil {
		t.Fatal("pre-epoch relocation lost the container on a failed target insert")
	}
}

// The success path is unchanged: source tombstoned, target live and pending,
// carrying the relocation token and the source's lifecycle columns.
func TestRelocateContainerWithToken_SuccessMovesTheRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "web", true)

	if err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok-3"); err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if src, _ := GetContainer(ctx, c, "host-a", "web"); src != nil {
		t.Errorf("source row still live after a successful relocation: %+v", src)
	}
	dst, err := GetContainer(ctx, c, "host-b", "web")
	if err != nil || dst == nil {
		t.Fatalf("target row missing: %+v err=%v", dst, err)
	}
	if dst.State != "pending" {
		t.Errorf("target state = %q, want pending", dst.State)
	}
	if dst.RelocateToken != "tok-3" {
		t.Errorf("target relocate_token = %q, want tok-3", dst.RelocateToken)
	}
	if dst.OwnerEpoch != 3 {
		t.Errorf("target owner_epoch = %d, want the source's 3 — the relocation proof "+
			"binds to it", dst.OwnerEpoch)
	}
}

// Refusing to clobber a live same-named container on the target still happens
// BEFORE anything is deleted.
func TestRelocateContainerWithToken_RefusesALiveTargetWithoutTouchingTheSource(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "web", true)
	seedRelocatableContainer(t, c, "host-b", "web", true)

	if err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok-4"); err == nil {
		t.Fatal("expected a refusal when the target already holds a live container")
	}
	if src, _ := GetContainer(ctx, c, "host-a", "web"); src == nil {
		t.Error("the refused relocation deleted the source anyway")
	}
}
