package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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

// deleteErrVirt is a libvirtfake whose DeleteSnapshot returns a chosen error, so the
// "libvirt metadata already gone" classification can be driven directly.
type deleteErrVirt struct {
	*libvirtfake.Fake
	delErr error
}

func (v *deleteErrVirt) DeleteSnapshot(string, string) error { return v.delErr }

// deleteSnapshotServer stages a stopped local VM with one snapshot record and a
// backend whose DeleteSnapshot fails with delErr. Stopped means flatten is false at
// snapshot.go's `flatten` decision, so only DeleteSnapshot runs — one path into the
// classifier, no flatten fallback to reason about.
func deleteSnapshotServer(t *testing.T, delErr error) (*Server, context.Context) {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.virt = &deleteErrVirt{Fake: libvirtfake.New(), delErr: delErr}
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "dvm", s.hostName, "stopped")
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName: "dvm", HostName: s.hostName, Name: "snap1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	return s, ctx
}

// A snapshot that vanishes between libvirt's lookup and its delete (a revert racing a
// delete) surfaces a RAW golibvirt.Error — code ErrNoDomainSnapshot, arbitrary message.
// The old substring check called that a hard failure and returned Internal, leaking the
// corrosion record; the typed arm of lv.IsNotFound is what fixes it. "gone" contains
// neither "not found" nor "no domain snapshot", so this test fails without that arm.
func TestDeleteSnapshot_TypedNotFoundTreatedAsAlreadyGone(t *testing.T) {
	s, ctx := deleteSnapshotServer(t, golibvirt.Error{
		Code: uint32(golibvirt.ErrNoDomainSnapshot), Message: "gone",
	})

	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
		VmName: "dvm", SnapshotName: "snap1",
	}); err != nil {
		t.Fatalf("DeleteSnapshot: want success for a typed not-found libvirt error, got %v", err)
	}
	snap, _ := corrosion.GetSnapshot(ctx, s.db, "dvm", "snap1")
	if snap != nil {
		t.Errorf("corrosion record must be tombstoned, still present: %+v", snap)
	}
}

// The two message shapes the hand-rolled check covered before the helper existed:
// libvirt's own wording, and litevirt's `snapshot %q not found: %w` wrapper. These
// passed before the change too — they are the no-regression guard.
func TestDeleteSnapshot_MessageNotFoundTreatedAsAlreadyGone(t *testing.T) {
	cases := []struct {
		name   string
		delErr error
	}{
		{"libvirt wording", errors.New("no domain snapshot with matching name 'snap1'")},
		{"litevirt wrapper", fmt.Errorf("snapshot %q not found: %w", "snap1", errors.New("boom"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx := deleteSnapshotServer(t, tc.delErr)

			if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
				VmName: "dvm", SnapshotName: "snap1",
			}); err != nil {
				t.Fatalf("DeleteSnapshot: want success for %v, got %v", tc.delErr, err)
			}
			snap, _ := corrosion.GetSnapshot(ctx, s.db, "dvm", "snap1")
			if snap != nil {
				t.Errorf("corrosion record must be tombstoned, still present: %+v", snap)
			}
		})
	}
}

// A libvirt failure that is NOT an absence must still fail the RPC and LEAVE the record
// in place. Both assertions matter: the code pins that a real fault is not swallowed, and
// the surviving record pins that the handler did not run the cleanup path anyway.
func TestDeleteSnapshot_RealFailureStillPropagates(t *testing.T) {
	s, ctx := deleteSnapshotServer(t, errors.New("internal error: qemu unexpectedly closed the monitor"))

	_, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
		VmName: "dvm", SnapshotName: "snap1",
	})
	if c := status.Code(err); c != codes.Internal {
		t.Fatalf("code = %v (err=%v), want Internal", c, err)
	}
	snap, _ := corrosion.GetSnapshot(ctx, s.db, "dvm", "snap1")
	if snap == nil {
		t.Error("corrosion record must survive a real libvirt failure, it was tombstoned")
	}
}
