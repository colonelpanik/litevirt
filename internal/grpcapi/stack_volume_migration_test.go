package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// seedStackVM inserts a VM (with a single "root" disk) belonging to a stack.
func seedStackVM(t *testing.T, s *Server, ctx context.Context, stack, vm, state, diskPool, diskPath string, size int64) {
	t.Helper()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: vm, StackName: stack, HostName: s.hostName, State: state},
		nil,
		[]corrosion.DiskRecord{{
			VMName: vm, DiskName: "root", HostName: s.hostName,
			Path: diskPath, SizeBytes: size,
			StorageType: "local", StorageVolume: diskPool,
		}},
	); err != nil {
		t.Fatalf("InsertVM %s: %v", vm, err)
	}
}

// seedPool registers a pool both in the corrosion table (so preflight's
// GetStoragePool finds it) and in the in-memory map (so moveOneVolume can
// resolve it).
func seedPool(t *testing.T, s *Server, ctx context.Context, name, driver, target string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: driver, Target: target, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool %s: %v", name, err)
	}
}

func framesByStage(sent []*pb.StackVolumeProgress, stage pb.StackVolumeProgress_Stage) []*pb.StackVolumeProgress {
	var out []*pb.StackVolumeProgress
	for _, f := range sent {
		if f.Stage == stage {
			out = append(out, f)
		}
	}
	return out
}

func TestOrderStackVMs(t *testing.T) {
	vms := []corrosion.VMRecord{{Name: "a"}, {Name: "b"}, {Name: "c"}}

	// No explicit order → listing order preserved.
	got, err := orderStackVMs(vms, nil)
	if err != nil || len(got) != 3 || got[0].Name != "a" || got[2].Name != "c" {
		t.Fatalf("default order = %+v, err %v", got, err)
	}

	// Explicit partial order → listed first, rest follow.
	got, err = orderStackVMs(vms, []string{"c"})
	if err != nil {
		t.Fatalf("partial order err: %v", err)
	}
	if got[0].Name != "c" || got[1].Name != "a" || got[2].Name != "b" {
		t.Fatalf("partial order = %v, want [c a b]", names(got))
	}

	// Unknown VM in order → error.
	if _, err := orderStackVMs(vms, []string{"zzz"}); status.Code(err) == codes.OK && err == nil {
		t.Fatalf("expected error for unknown VM in order")
	}
}

func names(vms []corrosion.VMRecord) []string {
	out := make([]string, len(vms))
	for i, v := range vms {
		out[i] = v.Name
	}
	return out
}

func TestMigrateStackVolumes_PlacementResolution(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()

	// pg-1 has root on "hot"; pg-2 has root on "warm" (already on target).
	seedStackVM(t, s, ctx, "pg", "pg-1", "stopped", "hot", "/x/pg-1.qcow2", 1)
	seedStackVM(t, s, ctx, "pg", "pg-2", "stopped", "warm", "/x/pg-2.qcow2", 1)

	vms, _ := corrosion.ListVMs(ctx, s.db, "pg", "")
	ordered, _ := orderStackVMs(vms, []string{"pg-1", "pg-2"})

	req := &pb.MigrateStackVolumesRequest{
		StackName:   "pg",
		DefaultPool: "warm",
		// Disk-level override beats default for pg-1/root.
		Placements: []*pb.VolumePlacement{
			{VmName: "pg-1", DiskName: "root", TargetPool: "archive"},
		},
	}
	plans, err := s.resolveStackPlan(ctx, ordered, req)
	if err != nil {
		t.Fatalf("resolveStackPlan: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("want 2 vmPlans, got %d", len(plans))
	}
	// pg-1/root → archive (disk-level placement wins).
	if got := plans[0].disks[0].targetPool; got != "archive" {
		t.Errorf("pg-1/root target = %q, want archive", got)
	}
	if plans[0].disks[0].skip {
		t.Errorf("pg-1/root should not be skipped")
	}
	// pg-2/root → warm (default), already on warm → skipped.
	if got := plans[1].disks[0].targetPool; got != "warm" {
		t.Errorf("pg-2/root target = %q, want warm", got)
	}
	if !plans[1].disks[0].skip {
		t.Errorf("pg-2/root is already on warm and should be skipped")
	}
}

func TestMigrateStackVolumes_DryRun(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()

	seedPool(t, s, ctx, "warm", "local", filepath.Join(s.dataDir, "warm"))
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: filepath.Join(s.dataDir, "warm")}})
	seedStackVM(t, s, ctx, "pg", "pg-1", "stopped", "hot", filepath.Join(s.dataDir, "pg-1.qcow2"), 1)
	seedStackVM(t, s, ctx, "pg", "pg-2", "stopped", "hot", filepath.Join(s.dataDir, "pg-2.qcow2"), 1)

	rec := &streamRecorder[pb.StackVolumeProgress]{ctx: adminCtx()}
	if err := s.MigrateStackVolumes(&pb.MigrateStackVolumesRequest{
		StackName: "pg", DefaultPool: "warm", DryRun: true,
	}, rec); err != nil {
		t.Fatalf("MigrateStackVolumes dry-run: %v", err)
	}

	if plan := framesByStage(rec.Sent, pb.StackVolumeProgress_PLANNING); len(plan) != 2 {
		t.Errorf("want 2 PLANNING frames, got %d", len(plan))
	}
	last := rec.Sent[len(rec.Sent)-1]
	if last.Stage != pb.StackVolumeProgress_COMPLETE {
		t.Errorf("final stage = %v, want COMPLETE", last.Stage)
	}
	// Dry-run must not touch disk records.
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "pg-1")
	if disks[0].StorageVolume != "hot" {
		t.Errorf("dry-run mutated disk pool: %q", disks[0].StorageVolume)
	}
}

func TestMigrateStackVolumes_OfflineRollout(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()

	dstDir := filepath.Join(s.dataDir, "warm")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seedPool(t, s, ctx, "warm", "local", dstDir)
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})

	// Two stopped VMs, each with a real (tiny) qcow2 so the offline
	// convert path has something to copy.
	for _, vm := range []string{"pg-1", "pg-2"} {
		path := filepath.Join(s.dataDir, vm+".qcow2")
		if err := qcow2.Create(path, 1<<20, nil); err != nil {
			t.Fatalf("qcow2.Create %s: %v", vm, err)
		}
		st, _ := os.Stat(path)
		seedStackVM(t, s, ctx, "pg", vm, "stopped", "hot", path, st.Size())
	}

	rec := &streamRecorder[pb.StackVolumeProgress]{ctx: adminCtx()}
	if err := s.MigrateStackVolumes(&pb.MigrateStackVolumesRequest{
		StackName: "pg", DefaultPool: "warm", Parallel: 1,
		Order: []string{"pg-1", "pg-2"}, DeleteSource: true,
	}, rec); err != nil {
		t.Fatalf("MigrateStackVolumes: %v", err)
	}

	// Both VMs reported done, in order (parallel=1 ⇒ sequential).
	done := framesByStage(rec.Sent, pb.StackVolumeProgress_VM_DONE)
	if len(done) != 2 || done[0].VmName != "pg-1" || done[1].VmName != "pg-2" {
		t.Fatalf("VM_DONE order = %v, want [pg-1 pg-2]", done)
	}
	last := rec.Sent[len(rec.Sent)-1]
	if last.Stage != pb.StackVolumeProgress_COMPLETE || last.VmsDone != 2 {
		t.Fatalf("final = %v vms_done=%d, want COMPLETE/2", last.Stage, last.VmsDone)
	}

	// Both disk records now point at the warm pool.
	for _, vm := range []string{"pg-1", "pg-2"} {
		disks, _ := corrosion.GetVMDisks(ctx, s.db, vm)
		if disks[0].StorageVolume != "warm" {
			t.Errorf("%s disk pool = %q, want warm", vm, disks[0].StorageVolume)
		}
		if disks[0].Path != filepath.Join(dstDir, vm+"-root.qcow2") {
			t.Errorf("%s disk path = %q", vm, disks[0].Path)
		}
	}
}

func TestMigrateStackVolumes_PreflightUnknownPool(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	// Pool "warm" exists in the in-memory map but NOT in the corrosion
	// table for this host → preflight must reject.
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: t.TempDir()}})
	seedStackVM(t, s, ctx, "pg", "pg-1", "stopped", "hot", filepath.Join(s.dataDir, "pg-1.qcow2"), 1)

	rec := &streamRecorder[pb.StackVolumeProgress]{ctx: adminCtx()}
	err := s.MigrateStackVolumes(&pb.MigrateStackVolumesRequest{
		StackName: "pg", DefaultPool: "warm",
	}, rec)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for unknown pool, got %v", err)
	}
}

func TestMigrateStackVolumes_PreflightBlockDriver(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	seedPool(t, s, ctx, "warm", "local", t.TempDir())
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: t.TempDir()}})

	// Source disk is on a block driver (ceph) → unsupported today.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "pg-1", StackName: "pg", HostName: s.hostName, State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "pg-1", DiskName: "root", HostName: s.hostName,
			Path: "rbd:pool/pg-1", SizeBytes: 1, StorageType: "ceph", StorageVolume: "rbd",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.StackVolumeProgress]{ctx: adminCtx()}
	err := s.MigrateStackVolumes(&pb.MigrateStackVolumesRequest{
		StackName: "pg", DefaultPool: "warm",
	}, rec)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for block-driver source, got %v", err)
	}
}

func TestMigrateStackVolumes_EmptyStack(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	rec := &streamRecorder[pb.StackVolumeProgress]{ctx: adminCtx()}
	err := s.MigrateStackVolumes(&pb.MigrateStackVolumesRequest{
		StackName: "ghost", DefaultPool: "warm",
	}, rec)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for empty stack, got %v", err)
	}
}
