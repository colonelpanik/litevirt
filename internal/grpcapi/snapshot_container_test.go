package grpcapi

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// snapTestServer sets up host-a with one container in the given state.
func snapTestServer(t *testing.T, state string) (*Server, *fakeCTRuntime) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs-snapshot-bytes")}
	s.SetContainerRuntime(rt)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: state, Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	return s, rt
}

// TestSnapshotContainer_CreateListRevertDelete is the full lifecycle: snapshot a
// running container (freeze), list it, revert (stop→revert→restart), delete.
func TestSnapshotContainer_CreateListRevertDelete(t *testing.T) {
	s, rt := snapTestServer(t, "running")
	ctx := context.Background()

	// Create.
	snap, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"})
	if err != nil {
		t.Fatalf("SnapshotContainer: %v", err)
	}
	if snap.Name != "s1" || snap.SizeBytes == 0 {
		t.Errorf("snapshot = %+v, want name s1 + nonzero size", snap)
	}
	if len(rt.freezeCalls) != 1 || len(rt.unfreezeCalls) != 1 {
		t.Errorf("running snapshot should freeze+unfreeze; got %v/%v", rt.freezeCalls, rt.unfreezeCalls)
	}
	row, _ := corrosion.GetContainerSnapshot(ctx, s.db, "host-a", "ct1", "s1")
	if row == nil || row.Path == "" {
		t.Fatalf("snapshot row missing or no path: %+v", row)
	}
	if _, err := os.Stat(row.Path); err != nil {
		t.Errorf("snapshot tar not written at %s: %v", row.Path, err)
	}

	// List.
	resp, err := s.ListContainerSnapshots(adminCtx(), &pb.ListContainerSnapshotsRequest{Name: "ct1", HostName: "host-a"})
	if err != nil || len(resp.Snapshots) != 1 || resp.Snapshots[0].Name != "s1" {
		t.Fatalf("list = %+v err=%v, want [s1]", resp.GetSnapshots(), err)
	}

	// Duplicate create → AlreadyExists.
	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("duplicate snapshot want AlreadyExists, got %v", err)
	}

	// Revert: running container is stopped, reverted, restarted.
	if _, err := s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("RevertContainerSnapshot: %v", err)
	}
	if len(rt.stopCalls) != 1 || len(rt.startCalls) != 1 {
		t.Errorf("revert of a running ct should stop+start; stop=%v start=%v", rt.stopCalls, rt.startCalls)
	}
	if got := string(rt.reverted["ct1"]); got != "rootfs-snapshot-bytes" {
		t.Errorf("reverted bytes = %q, want the snapshot payload", got)
	}

	// Delete: file removed + row tombstoned.
	if _, err := s.DeleteContainerSnapshot(adminCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("DeleteContainerSnapshot: %v", err)
	}
	if _, err := os.Stat(row.Path); !os.IsNotExist(err) {
		t.Errorf("snapshot tar should be removed, stat err=%v", err)
	}
	if g, _ := corrosion.GetContainerSnapshot(ctx, s.db, "host-a", "ct1", "s1"); g != nil {
		t.Errorf("snapshot row should be tombstoned, got %+v", g)
	}
}

// TestSnapshotContainer_StoppedSkipsFreeze — a stopped container needs no quiesce.
func TestSnapshotContainer_StoppedSkipsFreeze(t *testing.T) {
	s, rt := snapTestServer(t, "stopped")
	if _, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("SnapshotContainer: %v", err)
	}
	if len(rt.freezeCalls) != 0 {
		t.Errorf("stopped container should not be frozen; got %v", rt.freezeCalls)
	}
	// Revert of a stopped container: no stop/start.
	if _, err := s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "s1"}); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if len(rt.stopCalls) != 0 || len(rt.startCalls) != 0 {
		t.Errorf("revert of a stopped ct should not stop/start; stop=%v start=%v", rt.stopCalls, rt.startCalls)
	}
}

// TestRevertContainerSnapshot_NotFound errors cleanly when the snapshot is gone.
func TestRevertContainerSnapshot_NotFound(t *testing.T) {
	s, _ := snapTestServer(t, "stopped")
	_, err := s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", HostName: "host-a", Snapshot: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}
