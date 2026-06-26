package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

var _ grpc.ServerStreamingServer[pb.BackupContainerProgress] = (*progressStream[pb.BackupContainerProgress])(nil)
var _ grpc.ServerStreamingServer[pb.RestoreContainerProgress] = (*progressStream[pb.RestoreContainerProgress])(nil)

// ctTestRepo initialises a fresh pbsstore repo under a temp dir.
func ctTestRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(dir); err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}
	return dir
}

// TestBackupContainer_RoundTrip backs up a running container, then restores it
// after the row is gone — proving the manifest is self-contained. It also
// asserts freeze/unfreeze bracket the push and the usage index is written.
func TestBackupContainer_RoundTrip(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)

	payload := []byte("hello-rootfs-tar-payload")
	rt := &fakeCTRuntime{exportPayload: payload}
	s.SetContainerRuntime(rt)

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running",
		Image: "alpine:3.19", CPULimit: 2, MemMiB: 256,
		RestartPolicy: `{"condition":"on-failure"}`, Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-23T10:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	last := bk.Sent[len(bk.Sent)-1]
	if last.Phase != pb.BackupContainerProgress_DONE || last.ManifestTs != "2026-06-23T10:00:00Z" {
		t.Fatalf("final frame = %+v", last)
	}
	if len(rt.freezeCalls) != 1 || len(rt.unfreezeCalls) != 1 {
		t.Errorf("freeze=%v unfreeze=%v, want one each", rt.freezeCalls, rt.unfreezeCalls)
	}
	// Usage index written for quota.
	u, _ := corrosion.SumProjectUsage(ctx, s.db, "acme")
	if u == nil {
		t.Fatal("SumProjectUsage nil")
	}

	// Drop the container row entirely — restore must rebuild from the manifest.
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-23T10:00:00Z",
	}, rs); err != nil {
		t.Fatalf("RestoreContainer: %v", err)
	}
	if got := string(rt.imported["ct1"]); got != string(payload) {
		t.Errorf("imported bytes = %q, want %q", got, payload)
	}
	row, err := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if err != nil || row == nil {
		t.Fatalf("restored row missing: %v", err)
	}
	// The restored row uses the project the permission check was made against:
	// with the live row deleted, that project is derived from the manifest's
	// embedded spec ("acme") and the (admin) caller is authorized for it, so the
	// container is restored back into its original project. A caller NOT
	// authorized for "acme" would be denied rather than silently landing it in
	// the default project.
	if row.State != "stopped" || row.CPULimit != 2 || row.MemMiB != 256 || row.Image != "alpine:3.19" {
		t.Errorf("restored row = %+v, want cpu=2 mem=256 image=alpine:3.19 stopped", row)
	}
	if row.Project != "acme" {
		t.Errorf("restored project = %q, want acme (manifest-derived, caller authorized)", row.Project)
	}
}

// TestBackupContainer_UnfreezesOnPushError is the corner case: a failure mid-
// backup must NEVER leave the container frozen (the unfreeze defer).
func TestBackupContainer_UnfreezesOnPushError(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	repo := ctTestRepo(t)

	rt := &fakeCTRuntime{exportErr: errors.New("tar: disk read error")}
	s.SetContainerRuntime(rt)
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Project: "acme",
	})

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	err := s.BackupContainer(&pb.BackupContainerRequest{Name: "ct1", HostName: "host-a", RepoPath: repo}, bk)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on export error, got %v", err)
	}
	if len(rt.freezeCalls) != 1 || len(rt.unfreezeCalls) != 1 {
		t.Errorf("freeze=%v unfreeze=%v — container must be unfrozen even on failure", rt.freezeCalls, rt.unfreezeCalls)
	}
}

// TestBackupContainer_StoppedSkipsFreeze — a stopped container needs no quiesce.
func TestBackupContainer_StoppedSkipsFreeze(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	repo := ctTestRepo(t)

	rt := &fakeCTRuntime{exportPayload: []byte("data")}
	s.SetContainerRuntime(rt)
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "stopped", Project: "acme",
	})

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "ct1", HostName: "host-a", RepoPath: repo}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	if len(rt.freezeCalls) != 0 || len(rt.unfreezeCalls) != 0 {
		t.Errorf("stopped container should not be frozen: freeze=%v unfreeze=%v", rt.freezeCalls, rt.unfreezeCalls)
	}
}

// TestBackupContainer_WrongHost mirrors the VM single-host model: a container
// owned by another host returns FailedPrecondition naming it.
func TestBackupContainer_WrongHost(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})
	_ = corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ctB", State: "running",
	})
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	err := s.BackupContainer(&pb.BackupContainerRequest{Name: "ctB", RepoPath: t.TempDir()}, bk)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

// TestRestoreContainer_NameConflict refuses to clobber a live container.
func TestRestoreContainer_NameConflict(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)

	rt := &fakeCTRuntime{exportPayload: []byte("x")}
	s.SetContainerRuntime(rt)
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Project: "acme",
	})
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-23T11:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}

	// ct1 still exists → restore must refuse.
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-23T11:00:00Z",
	}, rs)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}
}

// TestRestoreContainer_StartsWhenRequested boots the container after restore.
func TestRestoreContainer_StartsWhenRequested(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)

	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "stopped", Project: "acme",
	})
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-23T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-23T12:00:00Z", Start: true,
	}, rs); err != nil {
		t.Fatalf("RestoreContainer: %v", err)
	}
	if len(rt.startCalls) != 1 || rt.startCalls[0] != "ct1" {
		t.Errorf("start calls = %v, want [ct1]", rt.startCalls)
	}
	row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if row == nil || row.State != "running" {
		t.Errorf("restored+started row = %+v, want running", row)
	}
}
