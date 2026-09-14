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

// ctSnapshotPath joins the caller's snapshot name straight onto dataDir, and the
// daemon runs as root. All three container-snapshot handlers checked the name
// only for emptiness, so `../` in it escapes the snapshot directory: create
// truncates whatever it lands on, and delete removes it. The VM twin validates
// its snapshot name for exactly this reason and says so (snapshot.go: "Snapshot
// names now feed a filesystem sidecar path ... to prevent a `../` escape").
//
// Asserted as InvalidArgument rather than by probing the filesystem: the name
// must be refused at the door, before any path is built from it.
func TestContainerSnapshot_RejectsATraversingSnapshotName(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: s.hostName, Name: "ct1", State: "stopped",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	const escape = "../ct2/nightly"
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"SnapshotContainer", func() error {
			_, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{Name: "ct1", Snapshot: escape})
			return err
		}},
		{"RevertContainerSnapshot", func() error {
			_, err := s.RevertContainerSnapshot(adminCtx(), &pb.RevertContainerSnapshotRequest{Name: "ct1", Snapshot: escape})
			return err
		}},
		{"DeleteContainerSnapshot", func() error {
			_, err := s.DeleteContainerSnapshot(adminCtx(), &pb.DeleteContainerSnapshotRequest{Name: "ct1", Snapshot: escape})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("%s with snapshot %q = %v (code %s), want InvalidArgument",
					tc.name, escape, err, status.Code(err))
			}
		})
	}
}

// The container name is joined into the same path and needs the same guard.
func TestContainerSnapshot_RejectsATraversingContainerName(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()

	_, err := s.SnapshotContainer(adminCtx(), &pb.SnapshotContainerRequest{
		Name: "../../etc", Snapshot: "ok",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("SnapshotContainer with a traversing container name = %v (code %s), want InvalidArgument",
			err, status.Code(err))
	}
}

// Guard rail on the helper itself: a validated pair must stay inside dataDir.
func TestCtSnapshotPath_StaysUnderDataDir(t *testing.T) {
	root := "/var/lib/litevirt"
	got := ctSnapshotPath(root, "ct1", "nightly")
	want := filepath.Join(root, containerSnapshotDir, "ct1", "nightly.tar")
	if got != want {
		t.Fatalf("ctSnapshotPath = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, root+"/") {
		t.Fatalf("ctSnapshotPath escaped %q: %q", root, got)
	}
}
