package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedSnapVM inserts a running (or stopped) VM with one disk + one disk snapshot
// in both corrosion and the fake libvirt backend.
func seedSnapVM(t *testing.T, ctx context.Context, s *Server, fake interface {
	CreateSnapshot(string, string) (int64, error)
}, name, state string) {
	t.Helper()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: name, HostName: "host-a", State: state},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "host-a", Path: "/var/lib/litevirt/disks/" + name + "-root.qcow2", StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: name + "-s1", VMName: name, HostName: "host-a", Name: "s1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	if _, err := fake.CreateSnapshot(name, "s1"); err != nil {
		t.Fatalf("fake CreateSnapshot: %v", err)
	}
}

// Deleting the last snapshot of a RUNNING VM flattens the disk (block-commit),
// so the chain collapses and the VM stays migratable — not a metadata-only delete.
func TestDeleteSnapshot_RunningLastSnapshotFlattens(t *testing.T) {
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	seedSnapVM(t, ctx, s, fake, "flat-vm", "running")

	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "flat-vm", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}

	flattened, plain := false, false
	for _, e := range fake.EventLog() {
		if e.Domain != "flat-vm" {
			continue
		}
		if e.Op == "snapshot-flatten" {
			flattened = true
		}
		if e.Op == "snapshot-delete" {
			plain = true
		}
	}
	if !flattened {
		t.Error("expected a flatten (block-commit) when deleting the last snapshot of a running VM")
	}
	if plain {
		t.Error("did not expect a metadata-only delete for the running last-snapshot case")
	}
}

// Deleting a snapshot of a STOPPED VM uses the metadata-only delete (block-commit
// needs a running qemu).
func TestDeleteSnapshot_StoppedUsesMetadataDelete(t *testing.T) {
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	seedSnapVM(t, ctx, s, fake, "stopped-vm", "stopped")

	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "stopped-vm", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}

	for _, e := range fake.EventLog() {
		if e.Domain == "stopped-vm" && e.Op == "snapshot-flatten" {
			t.Error("stopped VM must not be flattened (metadata-only delete expected)")
		}
	}
}
