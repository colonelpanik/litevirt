package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestReplicateVolume_SameResolvedPathRejected(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	dstDir := filepath.Join(s.dataDir, "warm")
	srcPath := filepath.Join(dstDir, "vm1-root.qcow2")
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: dstDir},
	})

	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: srcPath, SizeBytes: 1 << 20,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ReplicateVolume code = %v, want FailedPrecondition; err = %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "same path") {
		t.Fatalf("ReplicateVolume error = %v, want same path rejection", err)
	}
	if len(rec.Sent) != 0 {
		t.Fatalf("same-path rejection should happen before progress is sent: %+v", rec.Sent)
	}
}

func TestReplicateVolume_BlockTargetDriverUnimplemented(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"replica": {Driver: "ceph", Source: "rbd/litevirt"},
	})

	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/var/lib/litevirt/images/vm1-root.qcow2", SizeBytes: 1 << 20,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "replica",
	}, rec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ReplicateVolume code = %v, want Unimplemented; err = %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), `target pool driver "ceph"`) {
		t.Fatalf("ReplicateVolume error = %v, want target pool driver", err)
	}
	if len(rec.Sent) != 0 {
		t.Fatalf("block-target rejection should happen before progress is sent: %+v", rec.Sent)
	}
}

func TestReplicateVolume_TargetPoolResolvedFromDB(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"

	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: "test-host",
		Name:     "replica",
		Driver:   "ceph",
		Source:   "rbd/litevirt",
		State:    "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/var/lib/litevirt/images/vm1-root.qcow2", SizeBytes: 1 << 20,
			StorageType: "local", StorageVolume: "hot",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "replica",
	}, rec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ReplicateVolume code = %v, want Unimplemented; err = %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), `target pool driver "ceph"`) {
		t.Fatalf("ReplicateVolume error = %v, want DB-resolved target pool driver", err)
	}
	if _, ok := s.lookupStoragePool("replica"); !ok {
		t.Fatal("resolvePool did not warm the in-memory storage pool cache")
	}
}

func TestReplicateVolume_BlockSourceDriverUnimplemented(t *testing.T) {
	s := testServer(t)
	s.hostName = "test-host"
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"warm": {Driver: "local", Target: t.TempDir()},
	})

	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "rbd/litevirt/vm1-root", SizeBytes: 1 << 20,
			StorageType: "ceph", StorageVolume: "rbd/litevirt",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm",
	}, rec)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ReplicateVolume code = %v, want Unimplemented; err = %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), `source pool driver "ceph"`) {
		t.Fatalf("ReplicateVolume error = %v, want source pool driver", err)
	}
	if len(rec.Sent) != 0 {
		t.Fatalf("block-source rejection should happen before progress is sent: %+v", rec.Sent)
	}
}
