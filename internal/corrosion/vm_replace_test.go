package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The four receiver behaviours a guarded VM-name replacement has to get right.
// Each was a way the transition broke when it was built out of the pre-existing
// statement shapes — the shapes are compatible, but compatibility is not the
// guarantee this operation needs.

func replaceWAL(t *testing.T, c *Client, from int) []*pb.MutationEntry {
	t.Helper()
	all := walEntries(t, c, "source")
	if len(all) <= from {
		t.Fatalf("no mutations after index %d", from)
	}
	return all[from:]
}

// A stale copy of the replaced VM must not overwrite its replacement, even when
// the replaced VM had the HIGHER authority of the two — which is the normal case,
// since it has been running longer than the replacement that replaces it.
//
// A both-live conflict at the contested name is decided on owner/generation
// alone; the anti-entropy merge never consults the name a tombstone was moved to.
// So the transition has to write authority above BOTH inputs at the name itself.
func TestReplacedVMsStaleSnapshotCannotOverwriteItsReplacement(t *testing.T) {
	c := testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{"name":"app","cpu":2}`, State: "stopped"}, nil, nil)
	if err := TransferVMOwner(ctx, c, "app", "h1", "stopped", 0); err != nil {
		t.Fatalf("TransferVMOwner: %v", err)
	}
	stale := c.DumpStateBytes()
	mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{"name":"app-next","cpu":4}`, State: "stopped"}, nil, nil)

	cutover(t, c, "app", "app-next")

	if err := c.MergeStateBytesLWW(stale); err != nil {
		t.Fatalf("merge the replaced VM's stale snapshot: %v", err)
	}
	vm, err := GetVM(ctx, c, "app")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm == nil || vm.Spec != `{"cpu":4,"name":"app"}` {
		t.Fatalf("the replaced VM's stale snapshot overwrote its replacement: %+v", vm)
	}
}

// A receiver that advanced the replaced VM's ownership itself made the sender's
// delete decline THERE, so it still holds that VM live. The whole transition must
// decline with it: nothing may move its live VM aside, and the replacement must
// stay put under its own name.
func TestReplaceDeclinesWhereTheDeleteDidNotApply(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}
	if err := TransferVMOwner(ctx, dst, "app", "h2", "stopped", 0); err != nil {
		t.Fatalf("advance the receiver's ownership: %v", err)
	}

	before := len(walEntries(t, src, "source"))
	cutover(t, src, "app", "app-next")
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, replaceWAL(t, src, before)); err != nil {
		t.Fatalf("apply the replace: %v", err)
	}

	held, err := GetVM(ctx, dst, "app")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if held == nil || held.HostName != "h2" {
		t.Fatalf("the receiver's newer-authority VM was moved or destroyed: %+v", held)
	}
	next, err := GetVM(ctx, dst, "app-next")
	if err != nil {
		t.Fatalf("GetVM replacement: %v", err)
	}
	if next == nil {
		t.Fatal("the replacement was retired on a receiver that declined the transition")
	}
}

// The transition must never half-apply. Every statement carries the SAME guard,
// so a receiver reaches one decision for the batch — rather than gating each
// statement on its own clock, which could commit the replacement's retirement
// while skipping the write that gives it the new name, leaving NO row at all.
func TestReplaceNeverLeavesTheNameEmpty(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}
	// The receiver has its own NEWER write to the replacement, so a per-statement
	// clock gate would skip the statement that installs the new name.
	if err := UpdateVMState(ctx, dst, "app-next", "stopped", "receiver is ahead"); err != nil {
		t.Fatalf("advance the receiver's replacement row: %v", err)
	}

	before := len(walEntries(t, src, "source"))
	cutover(t, src, "app", "app-next")
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, replaceWAL(t, src, before)); err != nil {
		t.Fatalf("apply the replace: %v", err)
	}

	rows, err := dst.Query(ctx, `SELECT name, deleted_at FROM vms WHERE name IN ('app', 'app-next')`)
	if err != nil {
		t.Fatalf("read both names: %v", err)
	}
	live := 0
	for _, r := range rows {
		if r.String("deleted_at") == "" {
			live++
		}
	}
	if live == 0 {
		t.Fatalf("the transition left no live row under either name: %+v", rows)
	}
}

// A full-state sync can install the finished transition BEFORE the WAL entry that
// performs it arrives. Replaying it then has to be a no-op, not a primary-key
// collision that back-pressures the sender's stream forever.
func TestReplaceIsIdempotentAfterFullStateArrivesFirst(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}

	before := len(walEntries(t, src, "source"))
	cutover(t, src, "app", "app-next")
	// The finished state first…
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("merge the finished state: %v", err)
	}
	// …then the entry that performed it.
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, replaceWAL(t, src, before)); err != nil {
		t.Fatalf("replaying an already-applied replace must be a no-op: %v", err)
	}
	vm, err := GetVM(ctx, dst, "app")
	if err != nil || vm == nil {
		t.Fatalf("VM %q after the replay: %+v err=%v", "app", vm, err)
	}
}

// A receiver that has NOT latched vm_replace_v1 must refuse the shapes rather
// than apply them under a disposition that was never designed for them. That
// refusal is why the sender is gated too: it back-pressures, which is exactly
// what the cluster-wide latch requirement exists to make unreachable.
func TestReplaceRefusedByAReceiverWithoutTheCapability(t *testing.T) {
	src, dst := testClient(t), testClient(t) // dst has NOT latched
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}

	before := len(walEntries(t, src, "source"))
	cutover(t, src, "app", "app-next")
	_, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, replaceWAL(t, src, before))
	if err == nil {
		t.Fatal("a receiver without vm_replace_v1 applied the guarded replace")
	}
	// And it changed nothing: the replacement is still under its own name.
	if vm, gErr := GetVM(ctx, dst, "app-next"); gErr != nil || vm == nil {
		t.Fatalf("refusing receiver lost the replacement: %+v err=%v", vm, gErr)
	}
}

// A delayed replay of the REPLACED VM's own deletion must not kill the
// replacement that took its name.
//
// A delete is terminal for its INCARNATION, and created_at is the incarnation
// identity the merge decides from — so if the row at the contested name inherited
// the replaced VM's stamp, that tombstone would read as "the same incarnation,
// already deleted" and sweep the replacement away. The transition therefore
// carries the REPLACEMENT's created_at onto the name, which makes the arriving
// tombstone an older incarnation that cannot kill a newer one.
func TestDelayedTombstoneOfTheReplacedVMCannotKillTheReplacement(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{"name":"app","cpu":2}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{"name":"app-next","cpu":4}`, State: "stopped"}, nil, nil)
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}

	// A snapshot of the moment the replaced VM was tombstoned, held back.
	if err := DeleteVM(ctx, src, "app"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	tombstoned := src.DumpStateBytes()

	// The receiver learns the finished cutover first…
	if err := ReplaceVM(ctx, src, "app-next", "app", prepareCutover(t, src, "app", "app-next")); err != nil {
		t.Fatalf("ReplaceVM: %v", err)
	}
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("merge the finished cutover: %v", err)
	}
	// …and only then the snapshot that still carries the replaced VM's tombstone.
	// This is the anti-entropy path, where the merge decides live-vs-tombstone from
	// created_at — so it is the one that can actually be fooled.
	if err := dst.MergeStateBytesLWW(tombstoned); err != nil {
		t.Fatalf("merge the delayed tombstone: %v", err)
	}

	vm, err := GetVM(ctx, dst, "app")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm == nil {
		t.Fatal("a delayed tombstone of the REPLACED VM killed its replacement")
	}
	if vm.Spec != `{"cpu":4,"name":"app"}` {
		t.Fatalf("VM %q carries %q, want the replacement's spec", "app", vm.Spec)
	}
}

// The batch is ONE decision, so a receiver may not take the parent transition and
// drop a child on its own clock: the contested name would end up holding the
// replaced VM's device rows while claiming to be the replacement.
//
// The receiver here has a NEWER write at the very child key the replacement is
// about to claim, which is exactly what a per-row LWW gate would defer to.
func TestReplaceAppliesEveryChildOrNone(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"},
		nil, []DiskRecord{{VMName: "app", DiskName: "root", HostName: "h1", Path: "/disks/old.qcow2", StorageType: "local"}})
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"},
		nil, []DiskRecord{{VMName: "app-next", DiskName: "root", HostName: "h1", Path: "/disks/new.qcow2", StorageType: "local"}})
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}
	before := len(walEntries(t, src, "source"))
	cutover(t, src, "app", "app-next")
	// AFTER the batch was built, so the receiver's row is strictly newer than the
	// write the batch carries for that key — which is what a per-row clock gate
	// would defer to.
	if err := dst.Execute(ctx,
		`UPDATE vm_disks SET path = ?, updated_at = ? WHERE vm_name = ? AND disk_name = ?`,
		"/disks/receiver-is-ahead.qcow2", dst.NowTS(), "app", "root"); err != nil {
		t.Fatalf("advance the receiver's child row: %v", err)
	}
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, replaceWAL(t, src, before)); err != nil {
		t.Fatalf("apply the replace: %v", err)
	}

	disks, err := GetVMDisks(ctx, dst, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].Path != "/disks/new.qcow2" {
		t.Fatalf("the name holds %+v, want exactly the replacement's disk — a child write was "+
			"skipped on the receiver's own clock while the parent transition landed", disks)
	}
}
