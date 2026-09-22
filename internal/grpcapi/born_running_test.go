package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// cloneSourceTemplate builds the stopped template a clone needs, with a real
// qcow2 so both linked and full modes reach the durable write.
func cloneSourceTemplate(t *testing.T) *Server {
	t.Helper()
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	ctx := adminCtx()

	srcDisk := s.images.DiskPath("tpl", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 2, MemoryMib: 2048})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", IsTemplate: true, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM tpl: %v", err)
	}
	return s
}

// TestCloneVM_AStartedCloneIsBornProvable.
//
// A clone with Start inserts its row at State: "running" — born running at the
// column default of 0, exactly the state CreateVM was in before the create path
// graduated. Nothing downstream repairs it: convergeOwnerEpochMarker
// early-returns on a zero epoch, and BackfillOwnerEpochs is gated behind
// enforcement.owner_epoch, which is false by default. So a started clone would
// stay unprovable indefinitely on a stock fleet.
func TestCloneVM_AStartedCloneIsBornProvable(t *testing.T) {
	s := cloneSourceTemplate(t)
	ctx := adminCtx()

	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{
		Source: "tpl", Target: "hot1", Mode: "linked", Start: true,
	}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	row, err := corrosion.GetVM(ctx, s.db, "hot1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" {
		t.Fatalf("state = %q, want running — this test does not exercise the born-running path", row.State)
	}
	if row.OwnerEpoch < 1 {
		t.Errorf("row epoch = %d, want >= 1 — a clone started at create is born running at "+
			"epoch 0 and nothing on a default-configured fleet ever graduates it", row.OwnerEpoch)
	}
	if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "hot1"); !ok || epoch != row.OwnerEpoch {
		t.Errorf("file marker = (%d,%v), want (%d,true)", epoch, ok, row.OwnerEpoch)
	}
}

// TestCloneVM_AStoppedCloneIsNotGraduated: the guard is on the state actually
// inserted. A stopped clone has no runtime to prove, and stamping a generation
// it did not earn would make the row and the marker disagree the moment
// whatever starts it mints one.
func TestCloneVM_AStoppedCloneIsNotGraduated(t *testing.T) {
	s := cloneSourceTemplate(t)
	ctx := adminCtx()

	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{
		Source: "tpl", Target: "cold1", Mode: "linked",
	}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	row, err := corrosion.GetVM(ctx, s.db, "cold1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "stopped" {
		t.Fatalf("state = %q, want stopped", row.State)
	}
	if row.OwnerEpoch != 0 {
		t.Errorf("row epoch = %d, want 0 — a stopped clone has no runtime to prove", row.OwnerEpoch)
	}
	if _, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "cold1"); ok {
		t.Error("a marker was written for a clone that is not running")
	}
}

// TestPromoteReplica_ARenamedPromotionIsBornProvable.
//
// promote.go's two commit branches are mutually EXCLUSIVE: `if renamed` inserts
// a fresh row at State: "running", and only the `else` calls
// TransferVMOwnerFresh. The transfer therefore never follows the insert, so a
// renamed promotion mints nothing — it is born running at epoch 0 and stays
// there, because convergence early-returns on zero and the backfill that would
// graduate it is off by default.
//
// Reading the two writes as sequential is what made an earlier plan withhold the
// graduation call from this branch on the stated grounds that ":900 mints right
// after". It does not.
func TestPromoteReplica_ARenamedPromotionIsBornProvable(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir() // testServer has none, and an empty dataDir skips the file marker
	s.virt = libvirtfake.New()
	ctx := adminCtx()

	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})

	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	replicaPath := filepath.Join(poolDir, "vm1-root-20260101000000.raw")
	if err := os.WriteFile(replicaPath, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write replica: %v", err)
	}

	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}

	row, err := corrosion.GetVM(ctx, s.db, "vm1-promoted")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" {
		t.Fatalf("state = %q, want running — this test does not exercise the born-running path", row.State)
	}
	if row.OwnerEpoch < 1 {
		t.Errorf("row epoch = %d, want >= 1 — the renamed branch inserts and never mints, so "+
			"without an explicit graduation the promoted VM can never prove its generation",
			row.OwnerEpoch)
	}
	if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1-promoted"); !ok || epoch != row.OwnerEpoch {
		t.Errorf("file marker = (%d,%v), want (%d,true)", epoch, ok, row.OwnerEpoch)
	}
}

// TestRestoreLive_AutoStart_IsBornProvable.
//
// A live-restore with AutoStart inserts its row at State: "running" — the third
// born-running producer, alongside a started clone and a renamed promotion. Like
// them it lands at the column default of 0, and like them nothing on a
// default-configured fleet graduates it afterwards.
func TestRestoreLive_AutoStart_IsBornProvable(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir() // testServer has none, and an empty dataDir skips the file marker
	fake := libvirtfake.New()
	s.virt = fake

	specJSON, err := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 2, MemoryMib: 2048,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, string(specJSON))
	target := filepath.Join(t.TempDir(), "live.qcow2")

	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer cancel()

	ctx := context.Background()
	row, gerr := corrosion.GetVM(ctx, s.db, "vm1")
	if gerr != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, gerr)
	}
	if row.State != "running" {
		t.Fatalf("state = %q, want running — this test does not exercise the born-running path", row.State)
	}
	if row.OwnerEpoch < 1 {
		t.Errorf("row epoch = %d, want >= 1 — a live-restore autostart is born running at "+
			"epoch 0 and nothing on a default-configured fleet graduates it", row.OwnerEpoch)
	}
	if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); !ok || epoch != row.OwnerEpoch {
		t.Errorf("file marker = (%d,%v), want (%d,true)", epoch, ok, row.OwnerEpoch)
	}

	cancel()
	<-done
}

// TestImportVM_StartedImportIsProvable.
//
// An import inserts its row at "stopped" with vm_owner_epoch at the column
// default of 0, then starts the VM and publishes it running. The chokepoint
// writes NOTHING for a pre-epoch row — a marker against an epoch-0 row is the
// one mismatch convergence returns early on and never repairs — so routing that
// publish accomplished nothing on its own: the started VM was exactly as
// unprovable as before, for as long as the default-off backfill stayed off. The
// import has to graduate its own VM, like the other born-running producers.
func TestImportVM_StartedImportIsProvable(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	fake := libvirtfake.New()
	s.virt = fake

	if err := importSmallVM(t, s, "imp1", "", 512, true); err != nil {
		t.Fatalf("ImportVM: %v", err)
	}
	ctx := context.Background()
	row, err := corrosion.GetVM(ctx, s.db, "imp1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" {
		t.Fatalf("state = %q, want running — this test does not exercise the started path", row.State)
	}
	if row.OwnerEpoch < 1 {
		t.Errorf("row epoch = %d, want >= 1 — an imported-and-started VM publishes running, so "+
			"it must carry a generation the markers can name", row.OwnerEpoch)
	}
	if epoch, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "imp1"); !ok || epoch != row.OwnerEpoch {
		t.Errorf("file marker = (%d,%v), want (%d,true)", epoch, ok, row.OwnerEpoch)
	}
}
