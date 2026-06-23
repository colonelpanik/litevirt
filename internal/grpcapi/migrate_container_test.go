package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

var _ grpc.ServerStreamingServer[pb.MigrateContainerProgress] = (*progressStream[pb.MigrateContainerProgress])(nil)

// migrateTestServer sets up a source server "host-a" with a running container
// and a staging repo, returning the server, runtime and repo path.
func migrateTestServer(t *testing.T, state string) (*Server, *fakeCTRuntime, string) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	repo := ctTestRepo(t)
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs-bytes")}
	s.SetContainerRuntime(rt)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: state, Image: "alpine:3.19",
		CPULimit: 2, MemMiB: 256, Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	return s, rt, repo
}

// TestMigrateContainer_Success exercises the happy path via the restore seam:
// stop → archive → (target restores) → re-key + source cleanup, leaving exactly
// one live row owned by the target.
func TestMigrateContainer_Success(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()

	var gotTarget, gotName string
	var gotStart bool
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, start bool) error {
		gotTarget, gotName, gotStart = target, name, start
		// Mimic the target's RestoreContainer creating the new owner row.
		return corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		})
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("MigrateContainer: %v", err)
	}
	if last := st.Sent[len(st.Sent)-1]; last.Phase != pb.MigrateContainerProgress_DONE {
		t.Fatalf("final phase = %v, want DONE", last.Phase)
	}
	// Cold: it was stopped before transfer and the target was asked to start it.
	if len(rt.stopCalls) != 1 || rt.stopCalls[0].Name != "ct1" {
		t.Errorf("stop calls = %v, want one for ct1", rt.stopCalls)
	}
	if gotTarget != "host-b" || gotName != "ct1" || !gotStart {
		t.Errorf("restore seam args = (%q,%q,start=%v), want (host-b,ct1,true)", gotTarget, gotName, gotStart)
	}
	// Source copy removed (runtime + soft-deleted row); target now owns it.
	if len(rt.deleteCalls) != 1 || rt.deleteCalls[0] != "ct1" {
		t.Errorf("source runtime delete calls = %v, want [ct1]", rt.deleteCalls)
	}
	if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src != nil {
		t.Errorf("source row still live after migration: %+v", src)
	}
	dst, _ := corrosion.GetContainer(ctx, s.db, "host-b", "ct1")
	if dst == nil || dst.HostName != "host-b" {
		t.Errorf("target row = %+v, want owned by host-b", dst)
	}
	// Exactly one live row cluster-wide.
	all, _ := corrosion.ListContainers(ctx, s.db, "")
	n := 0
	for _, c := range all {
		if c.Name == "ct1" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("live ct1 rows = %d, want exactly 1", n)
	}
}

// TestMigrateContainer_RollbackOnRestoreFailure is the key corner case: if the
// target restore fails, the container must stay intact on the source — and be
// restarted if it had been running.
func TestMigrateContainer_RollbackOnRestoreFailure(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) error {
		return errors.New("target unreachable")
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
	// Restarted on the source (it was running) and NOT deleted there.
	if len(rt.startCalls) != 1 || rt.startCalls[0] != "ct1" {
		t.Errorf("rollback should restart ct1 on source; start calls = %v", rt.startCalls)
	}
	if len(rt.deleteCalls) != 0 {
		t.Errorf("source must not be deleted on rollback; delete calls = %v", rt.deleteCalls)
	}
	if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src == nil {
		t.Error("source row vanished after a failed migration")
	}
}

// TestMigrateContainer_RollbackOnArchiveFailure: a failure during the archive
// step also rolls back cleanly.
func TestMigrateContainer_RollbackOnArchiveFailure(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	rt.exportErr = errors.New("tar read error")
	restoreCalled := false
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) error {
		restoreCalled = true
		return nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st)
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
	if restoreCalled {
		t.Error("restore must not run after an archive failure")
	}
	if len(rt.startCalls) != 1 {
		t.Errorf("rollback should restart the source container; start calls = %v", rt.startCalls)
	}
}

// TestMigrateContainer_WrongSourceHost — like backup, migration runs on the
// owning host.
func TestMigrateContainer_WrongSourceHost(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})
	_ = corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ctB", State: "running",
	})
	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ctB", TargetHost: "host-c", RepoPath: t.TempDir(),
	}, st)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

// TestMigrateContainer_SameHost rejects a no-op migration.
func TestMigrateContainer_SameHost(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-a", RepoPath: repo,
	}, st)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

// TestMigrateContainer_TargetAlreadyHasIt refuses to clobber an existing
// container on the target.
func TestMigrateContainer_TargetAlreadyHasIt(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	_ = corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ct1", State: "stopped",
	})
	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}
}
