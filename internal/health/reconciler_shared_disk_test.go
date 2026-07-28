package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// sharedDiskReconciler builds a reconciler with the shared-storage fence enforced
// and a fake libvirt, plus a captured refusal list. diskPath is created on disk so
// the post-gate os.Stat existence check passes for the "proceeds" cases.
func sharedDiskReconciler(t *testing.T, db *corrosion.Client) (*Reconciler, *libvirtfake.Fake, *[]string) {
	t.Helper()
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true}) // split-brain + shared-storage latched
	r.SetSharedStorageFenceEnforce(true)
	var refused []string
	r.SetGateRefusedObserver(func(_, reason string) { refused = append(refused, reason) })
	return r, fake, &refused
}

// seedSharedDiskVM inserts a VM with a single SHARED (nfs) disk whose file exists.
func seedSharedDiskVM(t *testing.T, ctx context.Context, db *corrosion.Client, name string) {
	t.Helper()
	diskPath := filepath.Join(t.TempDir(), name+".img")
	if err := os.WriteFile(diskPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write disk file: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: name, HostName: "node-a", Spec: "{}", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "node-a",
			Path: diskPath, StorageType: "nfs", SizeBytes: 1 << 30, StorageVolume: "pool"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
}

func hasReason(refused []string, want string) bool {
	for _, r := range refused {
		if r == want {
			return true
		}
	}
	return false
}

// stageReschedule writes the coordinator's reschedule proof (pending + link) with
// the given fence_epoch, re-pointing the VM to this host.
func stageReschedule(t *testing.T, ctx context.Context, db *corrosion.Client, vm, fenceEpoch string) {
	t.Helper()
	proof := corrosion.ActionProof{ID: "pf-" + vm, Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: vm, DestHost: "node-a", Coordinator: "node-old", FenceEpoch: fenceEpoch}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, vm, "node-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}
}

// TestStartPendingVM_SharedDiskRejectWithoutProofGradeFence: a shared-disk transfer
// whose proof carries no proof-grade fence (empty fence_epoch) is REFUSED terminally
// (storage_unverified) — the VM goes to error, not started.
func TestStartPendingVM_SharedDiskRejectWithoutProofGradeFence(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	seedSharedDiskVM(t, ctx, db, "vm1")
	stageReschedule(t, ctx, db, "vm1", "") // no proof-grade fence bound

	r, fake, refused := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("shared-disk transfer without a proof-grade fence must NOT start")
	}
	if !hasReason(*refused, ReasonStorageUnverified) {
		t.Errorf("want a storage_unverified refusal, got %v", *refused)
	}
	if vm, _ := corrosion.GetVM(ctx, db, "vm1"); vm == nil || vm.State != "error" {
		t.Errorf("rejected shared-disk transfer must terminalize the VM to error, got %+v", vm)
	}
}

// TestStartPendingVM_SharedDiskRetryOnUnreplicatedFence: a fence_epoch whose
// fencing_log row hasn't replicated here yet is RETRYABLE — the VM is left pending
// (not errored, not started, no refusal), for the next reconcile tick.
func TestStartPendingVM_SharedDiskRetryOnUnreplicatedFence(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	seedSharedDiskVM(t, ctx, db, "vm1")
	// Reference a fencing_log row that does not exist here yet.
	epoch := corrosion.FenceEpochRef{Host: "node-old", FenceID: "not-yet-replicated", TS: time.Now().UTC().Format(time.RFC3339)}.String()
	stageReschedule(t, ctx, db, "vm1", epoch)

	r, fake, refused := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a not-yet-replicated fence must not start the transfer")
	}
	if hasReason(*refused, ReasonStorageUnverified) {
		t.Errorf("a retryable fence must NOT be a terminal storage_unverified refusal, got %v", *refused)
	}
	if vm, _ := corrosion.GetVM(ctx, db, "vm1"); vm == nil || vm.State == "error" {
		t.Errorf("retryable shared-disk fence must leave the VM retryable (not error), got %+v", vm)
	}
}

// TestStartPendingVM_SharedDiskProceedsWithProofGradeFence: a fence_epoch bound to a
// proof-grade (IPMI) fencing_log row passes the gate and the transfer starts.
func TestStartPendingVM_SharedDiskProceedsWithProofGradeFence(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	seedSharedDiskVM(t, ctx, db, "vm1")
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "fx1", HostName: "node-old", Method: "ipmi", Result: "fenced"}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
	epoch := corrosion.FenceEpochRef{Host: "node-old", FenceID: "fx1", TS: time.Now().UTC().Format(time.RFC3339)}.String()
	stageReschedule(t, ctx, db, "vm1", epoch)

	r, fake, refused := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if hasReason(*refused, ReasonStorageUnverified) {
		t.Fatalf("a proof-grade fence must NOT be refused, got %v", *refused)
	}
	if !startedOrDefined(fake, "vm1") {
		t.Error("shared-disk transfer with a proof-grade fence must start")
	}
}

// TestStartPendingVM_MarkerlessSharedDiskLocalStartUnaffected: a MARKERLESS local
// start (clean reboot: state running, no proof) of a shared-disk VM is NOT gated —
// there's no ownership transfer, so it autostarts without a proof-grade fence.
func TestStartPendingVM_MarkerlessSharedDiskLocalStartUnaffected(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	seedSharedDiskVM(t, ctx, db, "vm1") // state "running", no pending_action_id, no proof

	r, fake, refused := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	if hasReason(*refused, ReasonStorageUnverified) {
		t.Fatalf("a markerless local start must NOT hit the shared-disk transfer gate, got %v", *refused)
	}
	if !startedOrDefined(fake, "vm1") {
		t.Error("markerless shared-disk local start (clean reboot) must autostart")
	}
}
