package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Moving a disk for a VM that belongs to a stack must update the stack's stored
// compose YAML so `lv stack export` reflects the new pool (and re-deploy is
// idempotent). Offline path (stopped VM).
func TestMoveVolume_SyncsStackComposeYAML(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()

	dstDir := filepath.Join(s.dataDir, "warm")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(s.dataDir, "vm1-root.qcow2")
	if err := qcow2.Create(srcFile, 1<<20, nil); err != nil {
		t.Fatalf("qcow2.Create: %v", err)
	}
	st, _ := os.Stat(srcFile)

	s.SetStoragePoolsByName(map[string]StoragePoolRef{"warm": {Driver: "local", Target: dstDir}})

	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped", StackName: "mystack"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: srcFile, SizeBytes: st.Size(), StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	composeYAML := "name: mystack\nvms:\n  vm1:\n    image: ubuntu\n    disks:\n      root:\n        size: 1M\n        storage: hot\n"
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name: "mystack", ComposeHash: "orig", ComposeYAML: composeYAML, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStack: %v", err)
	}

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm",
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}

	got, err := corrosion.GetStack(ctx, s.db, "mystack")
	if err != nil || got == nil {
		t.Fatalf("GetStack: %v", err)
	}
	if !strings.Contains(got.ComposeYAML, "storage: warm") || strings.Contains(got.ComposeYAML, "storage: hot") {
		t.Fatalf("stack compose YAML not synced to new pool:\n%s", got.ComposeYAML)
	}
	if got.ComposeHash == "orig" {
		t.Errorf("compose hash not recomputed after sync")
	}
}
