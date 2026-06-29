package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// These tests pin the fail-closed container-lifecycle contract: a cluster-row
// write that fails (or matches zero rows) must NOT be silently swallowed, and a
// create whose row write fails must not strand an untracked runtime container.
// (Same class of split-brain bug PR #57 fixed for RestoreContainer.)

// CreateContainer: if the cluster-row write fails, the just-created runtime
// container must be cleaned up and an error returned — not a false success.
func TestCreateContainer_RowWriteFailure_CleansUpRuntime(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)

	// Break the cluster-row write AFTER the runtime container is created (the hook
	// fires inside the runtime CreateContainer call, past the handler's same-name
	// preflight), so CreateContainerAtomic fails and the fail-closed cleanup runs.
	rt.createHook = func() { _ = s.db.Execute(ctx, `DROP TABLE containers`) }

	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.19",
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal when the cluster-row write fails, got %v", err)
	}
	rt.mu.Lock()
	deletes := append([]string(nil), rt.deleteCalls...)
	rt.mu.Unlock()
	if len(deletes) != 1 || deletes[0] != "web" {
		t.Fatalf("expected the just-created runtime container to be cleaned up (delete web), got %v", deletes)
	}
}

// StopContainer: if the operator-stop state write matches zero rows (the row is
// missing/soft-deleted), surface it — don't claim success, since without the
// marker the reconciler would auto-restart the container.
func TestStopContainer_MissingRow_Surfaces(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})

	_, err := s.StopContainer(ctx, &pb.StopContainerRequest{Name: "ghost", HostName: "test-host"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal stopping a container with no cluster row, got %v", err)
	}
}

// StartContainer: a missing/soft-deleted row must be caught BEFORE the runtime
// start, so we never start an untracked container.
func TestStartContainer_MissingRow_NoStart(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)

	_, err := s.StartContainer(ctx, &pb.StartContainerRequest{Name: "ghost", HostName: "test-host"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition starting a container with no cluster row, got %v", err)
	}
	rt.mu.Lock()
	starts := len(rt.startCalls)
	rt.mu.Unlock()
	if starts != 0 {
		t.Fatalf("must not start the runtime when no cluster row exists, got %d start(s)", starts)
	}
}

// DeleteContainer: a runtime "not found" is acceptable (idempotent) and must NOT
// abort before the mandatory row tombstone — otherwise a retry after
// "runtime gone but DB write failed" can never clear the ghost row.
func TestDeleteContainer_RuntimeNotFound_StillTombstones(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{deleteErr: lxc.ErrContainerNotFound})

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "web", State: "running",
	}); err != nil {
		t.Fatalf("seed container: %v", err)
	}

	if _, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "web", HostName: "test-host"}); err != nil {
		t.Fatalf("delete must tolerate a runtime not-found and still tombstone, got %v", err)
	}
	if r, _ := corrosion.GetContainer(ctx, s.db, "test-host", "web"); r != nil {
		t.Fatalf("row should be tombstoned after delete, still present: %+v", r)
	}
}

// DeleteContainer is intentionally idempotent: deleting an already-gone /
// never-present container is a success (the desired end state — absent — holds),
// so retries (e.g. from failover relocation) are safe. The zero-row tombstone is
// the documented exception to the strict "zero-row = failure" rule.
func TestDeleteContainer_AlreadyGone_Idempotent(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{deleteErr: lxc.ErrContainerNotFound})

	// No cluster row for "ghost" → the strict tombstone matches zero rows.
	if _, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "ghost", HostName: "test-host"}); err != nil {
		t.Fatalf("deleting an already-absent container must be idempotent success, got %v", err)
	}
}

// StartContainer must surface a state-READ failure as Internal (not mask it as
// FailedPrecondition: not found) — while staying fail-closed (no runtime start).
func TestStartContainer_StateReadError_Internal(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)

	if err := s.db.Execute(ctx, `DROP TABLE containers`); err != nil {
		t.Fatalf("drop containers: %v", err)
	}
	_, err := s.StartContainer(ctx, &pb.StartContainerRequest{Name: "web", HostName: "test-host"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on a state-read failure, got %v", err)
	}
	rt.mu.Lock()
	starts := len(rt.startCalls)
	rt.mu.Unlock()
	if starts != 0 {
		t.Fatalf("must not start the runtime when the state read failed, got %d start(s)", starts)
	}
}

// The strict corrosion helper must report a zero-row UPDATE as ErrNoRowsAffected
// (a soft-deleted/missing row), which a false "success" would hide.
func TestSetContainerStateDetailStrict_ZeroRows(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// No row for ("h","ghost") → strict update affects 0 rows.
	err = corrosion.SetContainerStateDetailStrict(ctx, db, "h", "ghost", "stopped", "operator-stop")
	if err != corrosion.ErrNoRowsAffected {
		t.Fatalf("expected ErrNoRowsAffected on a 0-row update, got %v", err)
	}
}
