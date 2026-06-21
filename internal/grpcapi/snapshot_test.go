package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestCreateSnapshot_VMNotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{
		VmName: "ghost",
		Name:   "snap1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestCreateSnapshot_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{
		VmName: "remote-vm",
		Name:   "snap1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestListSnapshots_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: "vm1"})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(resp.Snapshots) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(resp.Snapshots))
	}
}

func TestListSnapshots_WithRecords(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "snap-vm", "test-host", "running")

	// Insert snapshot records directly.
	corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName:   "snap-vm",
		HostName: "test-host",
		Name:     "snap-a",
		State:    "ok",
	})
	corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName:   "snap-vm",
		HostName: "test-host",
		Name:     "snap-b",
		State:    "ok",
	})

	resp, err := s.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: "snap-vm"})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(resp.Snapshots) != 2 {
		t.Errorf("expected 2 snapshots, got %d", len(resp.Snapshots))
	}
}

func TestRestoreSnapshot_VMNotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
		VmName:       "ghost",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRestoreSnapshot_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
		VmName:       "remote-vm",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestRestoreSnapshot_TransientState(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, state := range []string{"migrating", "creating", "starting"} {
		insertTestVM(t, ctx, s.db, "vm-"+state, "test-host", state)

		_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
			VmName:       "vm-" + state,
			SnapshotName: "snap1",
		})
		if err == nil {
			t.Errorf("state=%s: expected error", state)
			continue
		}
		if c := status.Code(err); c != codes.FailedPrecondition {
			t.Errorf("state=%s: code = %v, want FailedPrecondition", state, c)
		}
	}
}

func TestDeleteSnapshot_VMNotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
		VmName:       "ghost",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteSnapshot_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
		VmName:       "remote-vm",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}
