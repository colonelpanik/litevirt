package corrosion

import (
	"context"
	"testing"
)

// The guard is a LOCAL predicate too, not only a receiver one.
//
// ReplaceVM reads both rows, builds the batch, then writes. Without the guard
// evaluated inside that write transaction, the reads are a plain
// time-of-check-to-time-of-use window.
func TestReplaceRefusesWhenTheReplacementMovesUnderIt(t *testing.T) {
	c := testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	if err := DeleteVM(ctx, c, "app"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	prepared := prepareCutover(t, c, "app", "app-next")

	// The replacement's ownership advances after the manifest was journaled — the
	// interleaving a stale in-flight cutover races.
	if err := TransferVMOwnerFresh(ctx, c, "app-next", "h2", "stopped"); err != nil {
		t.Fatalf("TransferVMOwnerFresh: %v", err)
	}

	err := ReplaceVM(ctx, c, "app-next", "app", prepared)
	if err == nil {
		t.Fatal("the transition committed against a replacement that had moved under it")
	}

	// Nothing may have happened: the replacement is still live under its own name,
	// the contested name is still only a tombstone, and no cleanup is authorized.
	if vm, gErr := GetVM(ctx, c, "app-next"); gErr != nil || vm == nil {
		t.Fatalf("the replacement was retired by a refused transition: %+v err=%v", vm, gErr)
	}
	if vm, gErr := GetVM(ctx, c, "app"); gErr != nil || vm != nil {
		t.Fatalf("a refused transition left a live VM at the contested name: %+v err=%v", vm, gErr)
	}
	owed, oErr := ListVMReplaceCleanups(ctx, c, "h1")
	if oErr != nil {
		t.Fatalf("ListVMReplaceCleanups: %v", oErr)
	}
	if len(owed) != 0 {
		t.Fatalf("a refused transition authorized destruction: %+v", owed)
	}
}

// The replacement's own rows and its IPAM leases have to move with the same
// single decision as everything else. Applied through ordinary per-row
// last-writer-wins, a receiver with a newer clock on one of them commits the
// parent transition and leaves that row behind — the replacement still owning a
// disk under a name the transition retired, or a lease still assigned to it.
func TestReplaceRetiresTheReplacementsOwnRowsAndLeases(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, src, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, src, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"},
		nil, []DiskRecord{{VMName: "app-next", DiskName: "root", HostName: "h1", Path: "/disks/new.qcow2", StorageType: "local"}})
	if err := src.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('default', '10.0.0.5', '52:54:00:aa:bb:01', 'app-next', 'vm', 'h1', ?, ?)`,
		nowRFC3339(), src.NowTS()); err != nil {
		t.Fatalf("seed the lease: %v", err)
	}
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("seed the receiver: %v", err)
	}

	before := len(walEntries(t, src, "source"))
	cutover(t, src, "app", "app-next")
	// AFTER the batch was built, so the receiver's clocks on exactly these rows are
	// newer than the writes the batch carries for them.
	if err := dst.Execute(ctx,
		`UPDATE vm_disks SET updated_at = ? WHERE vm_name = 'app-next' AND disk_name = 'root'`,
		dst.NowTS()); err != nil {
		t.Fatalf("advance the receiver's source disk clock: %v", err)
	}
	if err := dst.Execute(ctx,
		`UPDATE ip_allocations SET updated_at = ? WHERE network = 'default' AND ip = '10.0.0.5'`,
		dst.NowTS()); err != nil {
		t.Fatalf("advance the receiver's lease clock: %v", err)
	}
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, replaceWAL(t, src, before)); err != nil {
		t.Fatalf("apply the replace: %v", err)
	}

	// The replacement must own nothing under its temporary name any more.
	left, err := GetVMDisks(ctx, dst, "app-next")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("the replacement still owns %+v under the name the transition retired", left)
	}
	// And its lease must have moved onto the contested name.
	rows, err := dst.Query(ctx,
		`SELECT vm_name FROM ip_allocations WHERE network = 'default' AND ip = '10.0.0.5'`)
	if err != nil {
		t.Fatalf("read the lease: %v", err)
	}
	if len(rows) != 1 || rows[0].String("vm_name") != "app" {
		t.Errorf("the lease is still assigned to %+v, want the contested name", rows)
	}
}

// Two successive deployments must be two operations. Both names are reused by the
// second one, and the first one's header is still there until the retention
// sweep, so an identity built from names alone collides — and does so only after
// the current VM has been torn down.
func TestReplaceOperationIdentityIsPerIncarnation(t *testing.T) {
	c := testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)

	first := prepareCutover(t, c, "app", "app-next")
	// The same attempt again must reuse the SAME operation: a retry is not a
	// second deployment.
	if again := prepareCutover(t, c, "app", "app-next"); again.OperationID != first.OperationID {
		t.Fatalf("a retry minted a new operation: %q then %q", first.OperationID, again.OperationID)
	}

	cutover(t, c, "app", "app-next")

	// A second deployment: a fresh replacement, and therefore a fresh incarnation.
	mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{"gen":2}`, State: "stopped"}, nil, nil)
	second := prepareCutover(t, c, "app", "app-next")
	if second.OperationID == first.OperationID {
		t.Fatalf("the second deployment reused the first operation's identity %q — a header from a "+
			"previous cutover would conflict, after the current VM was already torn down",
			first.OperationID)
	}
	if err := ReplaceVM(ctx, c, "app-next", "app", second); err == nil {
		t.Fatal("the second transition ran without its predecessor being tombstoned")
	}
	if err := DeleteVM(ctx, c, "app"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if err := ReplaceVM(ctx, c, "app-next", "app", prepareCutover(t, c, "app", "app-next")); err != nil {
		t.Fatalf("second deployment: %v", err)
	}
	vm, err := GetVM(ctx, c, "app")
	if err != nil || vm == nil {
		t.Fatalf("VM after the second deployment: %+v err=%v", vm, err)
	}
	if vm.Spec != `{"gen":2,"name":"app"}` {
		t.Fatalf("VM %q carries %q, want the second replacement's spec", "app", vm.Spec)
	}
}

// The window the write-transaction guard closes.
//
// ReplaceVM reads both rows, builds the batch, then writes. If the write does not
// re-evaluate the guard, those reads are a plain time-of-check-to-time-of-use
// window: an ownership change landing in it lets the stale target upsert — and
// the cleanup authorization travelling with it — commit, while the source
// retirement CAS matches nothing and leaves both names live.
func TestReplaceGuardIsEvaluatedInTheWriteTransaction(t *testing.T) {
	c := testClientVMReplace(t)
	ctx := context.Background()
	mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
	if err := DeleteVM(ctx, c, "app"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	prepared := prepareCutover(t, c, "app", "app-next")

	// Move the replacement's ownership in the window between the build and the write.
	replaceInterleaveHook = func() {
		replaceInterleaveHook = nil // once
		if err := TransferVMOwnerFresh(ctx, c, "app-next", "h2", "stopped"); err != nil {
			t.Fatalf("TransferVMOwnerFresh: %v", err)
		}
	}
	t.Cleanup(func() { replaceInterleaveHook = nil })

	if err := ReplaceVM(ctx, c, "app-next", "app", prepared); err == nil {
		t.Fatal("the transition committed against a replacement that moved inside the write window")
	}

	// Nothing may have been written: the contested name is still only a tombstone,
	// the replacement is still live under its own name, and — the part that makes
	// this more than an untidy failure — no destruction is authorized.
	if vm, gErr := GetVM(ctx, c, "app"); gErr != nil || vm != nil {
		t.Fatalf("a declined transition left a live VM at the contested name: %+v err=%v", vm, gErr)
	}
	if vm, gErr := GetVM(ctx, c, "app-next"); gErr != nil || vm == nil {
		t.Fatalf("a declined transition retired the replacement: %+v err=%v", vm, gErr)
	}
	owed, oErr := ListVMReplaceCleanups(ctx, c, "h1")
	if oErr != nil {
		t.Fatalf("ListVMReplaceCleanups: %v", oErr)
	}
	if len(owed) != 0 {
		t.Fatalf("a declined transition authorized destruction: %+v", owed)
	}
}
