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
	"github.com/litevirt/litevirt/internal/network"
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

// seedManagedSourceNIC gives the source ct1 a managed NIC that the source cleanly
// OWNS: the NIC is written into the container's create_spec (the set the migrate
// ownership proof is derived from — what the target rebuilds and asserts), backed
// by a real IPAM lease under (ct, host-a, ct1) and a matching interface row.
func seedManagedSourceNIC(t *testing.T, s *Server, ctx context.Context, net, ip, mac string) {
	t.Helper()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19",
		CPULimit: 2, MemMiB: 256, Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Networks: []corrosion.ContainerNetwork{{NetworkName: net, IP: ip, MAC: mac}},
		}),
	}); err != nil {
		t.Fatalf("seed source create_spec: %v", err)
	}
	if ok, err := network.ReserveContainerIP(ctx, s.db, net, ip, mac, "host-a", "ct1"); err != nil || !ok {
		t.Fatalf("seed ReserveContainerIP: ok=%v err=%v", ok, err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct1", NetworkName: net, Ordinal: 0,
		MAC: mac, IP: ip, VethDevice: "lvtest0",
	}); err != nil {
		t.Fatalf("seed interface row: %v", err)
	}
}

// TestMigrateContainer_Success exercises the happy path via the restore seam:
// stop → archive → (target restores) → re-key + source cleanup, leaving exactly
// one live row owned by the target.
func TestMigrateContainer_Success(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()

	var gotTarget, gotName string
	var gotStart bool
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, start bool) (corrosion.RestoreOutcome, error) {
		gotTarget, gotName, gotStart = target, name, start
		// Mimic the target's RestoreContainer creating the new owner row + landing.
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
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

// TestMigrateContainer_TransfersManagedLease proves the cross-host handoff of a
// managed IP: ReserveContainerIP deliberately refuses to infer ownership of a
// same-named CT on another host (steal-safety), so the mover must transfer the
// lease explicitly. After a successful migrate the IPAM lease is owned by the
// target and the source's interface rows are tombstoned — no duplicate claim,
// no stranded lease.
func TestMigrateContainer_TransfersManagedLease(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	ctx := context.Background()

	const (
		net = "br-acme"
		ip  = "10.9.0.5"
		mac = "02:11:22:33:44:55"
	)
	seedManagedSourceNIC(t, s, ctx, net, ip, mac)

	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("MigrateContainer: %v", err)
	}

	// The lease moved to the target...
	if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-b", "ct1"); a == nil || a.IP != ip {
		t.Errorf("lease not owned by host-b after migrate: %+v", a)
	}
	// ...and is no longer claimed under the source host.
	if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-a", "ct1"); a != nil {
		t.Errorf("lease still claimed by host-a after migrate: %+v", a)
	}
	// Source interface rows are tombstoned (the target wrote its own).
	if ifs, _ := corrosion.GetContainerInterfaces(ctx, s.db, "host-a", "ct1"); len(ifs) != 0 {
		t.Errorf("source interface rows still live after migrate: %+v", ifs)
	}
}

// TestMigrateContainer_RefusesWhenSourceLeaseMissing proves the per-NIC handoff
// PRECONDITION: a managed NIC whose IP has no backing source lease (a stale spec
// or a lost/stolen lease) aborts the migration BEFORE the target restore, so the
// target — which skips re-reservation on a verified migrate — can never start an
// unowned, potentially conflicting address.
func TestMigrateContainer_RefusesWhenSourceLeaseMissing(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	// A managed NIC in the create_spec (what the target rebuilds + asserts) whose IP
	// has NO ip_allocations lease behind it — the source does not own it.
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Networks: []corrosion.ContainerNetwork{{NetworkName: "br-acme", IP: "10.9.0.9", MAC: "02:00:00:00:00:09"}},
		}),
	}); err != nil {
		t.Fatalf("seed source create_spec: %v", err)
	}
	restoreCalled := false
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		restoreCalled = true
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal (refused), got %v", err)
	}
	if restoreCalled {
		t.Error("restore must not run when the source does not own a managed NIC IP")
	}
	// Nothing handed to the target; source row intact.
	if a, _ := network.GetAllocationFor(ctx, s.db, "br-acme", "ct", "host-b", "ct1"); a != nil {
		t.Errorf("no lease should be on host-b after a refused migrate: %+v", a)
	}
	if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src == nil {
		t.Error("source row vanished after a refused migration")
	}
}

// TestMigrateContainer_RollbackHandsLeasesBack proves the lease handoff is a
// reversible PRECONDITION of the restore: the leases move to the target before the
// target can run, and if the restore then fails the leases are handed back to the
// source (which gets restarted), so the source never ends up running an IP it no
// longer owns.
func TestMigrateContainer_RollbackHandsLeasesBack(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	ctx := context.Background()

	const (
		net = "br-acme"
		ip  = "10.9.0.7"
		mac = "02:aa:bb:cc:dd:ee"
	)
	seedManagedSourceNIC(t, s, ctx, net, ip, mac)

	// The restore fails BEFORE the target wrote a row (a pre-land failure) — but by
	// the time it runs the leases must already be on the target (the handoff is a
	// precondition, not a finalize step), and a pre-land failure rolls them back.
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-b", "ct1"); a == nil {
			t.Error("leases were not handed to the target before the restore ran")
		}
		return corrosion.RestoreFailedBeforeRow, errors.New("target unreachable")
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}

	// Lease handed BACK to the source; nothing stranded on the target.
	if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-a", "ct1"); a == nil || a.IP != ip {
		t.Errorf("lease not handed back to host-a after rollback: %+v", a)
	}
	if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-b", "ct1"); a != nil {
		t.Errorf("lease still on host-b after rollback: %+v", a)
	}
	// Source restarted (it was running) and its row is intact.
	if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src == nil {
		t.Error("source row vanished after a rolled-back migration")
	}
}

// TestMigrateContainer_RollbackOnRestoreFailure is the key corner case: if the
// target restore fails, the container must stay intact on the source — and be
// restarted if it had been running.
func TestMigrateContainer_RollbackOnRestoreFailure(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		return corrosion.RestoreNotAttempted, errors.New("target unreachable")
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
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		restoreCalled = true
		return corrosion.RestoreLanded, nil
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

// TestMigrateContainer_LandedThenStartFailed_Finalizes proves the core fix: once
// the target has LANDED its row, a later (start) failure does NOT roll the source
// back — that would leave two copies and yank the leases from a target that owns
// them. The migration finalizes (source removed) and the target keeps the
// container, recoverable as tracked+stopped.
func TestMigrateContainer_LandedThenStartFailed_Finalizes(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		// The target recorded its row (landed) but then its start failed: Landed +
		// a non-nil error. MigrateContainer must treat this as landed and finalize.
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "stopped", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, errors.New("started but start failed on target")
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("a landed restore whose start failed must still finalize, got %v", err)
	}
	if last := st.Sent[len(st.Sent)-1]; last.Phase != pb.MigrateContainerProgress_DONE {
		t.Fatalf("final phase = %v, want DONE", last.Phase)
	}
	// Source removed; NOT restarted (no rollback).
	if len(rt.startCalls) != 0 {
		t.Errorf("source must not be restarted after a landed restore; start calls = %v", rt.startCalls)
	}
	if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src != nil {
		t.Errorf("source row still live after a landed migration: %+v", src)
	}
}

// TestMigrateContainer_IndeterminateRestore_ParksSource: when the restore outcome
// is indeterminate (the row MAY have landed and the target MAY be running), the
// migration must NOT roll back — it parks the source stopped (operator-stop, so the
// reconciler won't auto-run it without its leases, which are on the target) and
// errors. The leases stay on the target; the source row is left live + stopped.
func TestMigrateContainer_IndeterminateRestore_ParksSource(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	const (
		net = "br-acme"
		ip  = "10.9.0.11"
		mac = "02:de:ad:be:ef:01"
	)
	seedManagedSourceNIC(t, s, ctx, net, ip, mac)
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		return corrosion.RestoreUnknown, errors.New("stream broke after the row may have landed")
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal (indeterminate), got %v", err)
	}
	// NOT restarted (parked, not rolled back).
	if len(rt.startCalls) != 0 {
		t.Errorf("source must not be restarted on an indeterminate restore; start calls = %v", rt.startCalls)
	}
	// Source parked stopped + operator-stop; row still live (not tombstoned).
	src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if src == nil {
		t.Fatal("source row must remain live on an indeterminate restore")
	}
	if src.State != "stopped" || src.StateDetail != "operator-stop" {
		t.Errorf("source not parked: state=%q detail=%q, want stopped/operator-stop", src.State, src.StateDetail)
	}
	// Leases stay on the target (NOT handed back) — the target may be live on them.
	if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-b", "ct1"); a == nil {
		t.Error("leases must stay on the target on an indeterminate restore")
	}
	if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-a", "ct1"); a != nil {
		t.Errorf("leases must NOT be handed back to the source on an indeterminate restore: %+v", a)
	}
}

// TestMigrateContainer_SourceTombstoneFailure_Errors proves the "exactly one live
// row" invariant: after the target lands, if the source row tombstone fails the
// migration does NOT report DONE — it surfaces an error (no silent ghost row).
func TestMigrateContainer_SourceTombstoneFailure_Errors(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		// Land the target, then break the containers table so the source-row tombstone
		// in finalize fails.
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		if err := s.db.Execute(ctx, `DROP TABLE containers`); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal when the source row tombstone fails, got %v", err)
	}
	if last := st.Sent[len(st.Sent)-1]; last.Phase != pb.MigrateContainerProgress_FAILED {
		t.Fatalf("final phase = %v, want FAILED (not DONE) on a tombstone failure", last.Phase)
	}
}

// TestMigrateContainer_StopIntentPersistedBeforeRestore proves the source's stop
// intent (operator-stop) is recorded right after the cold stop, before the long
// archive→transfer→restore window — so the reconciler can't see a stopped runtime
// with a running row and restart the source mid-migration.
func TestMigrateContainer_StopIntentPersistedBeforeRestore(t *testing.T) {
	s, _, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	var srcState, srcDetail string
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		// The restore drive runs after stop+archive+transfer; capture the source row.
		if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src != nil {
			srcState, srcDetail = src.State, src.StateDetail
		}
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("MigrateContainer: %v", err)
	}
	if srcState != "stopped" || srcDetail != "operator-stop" {
		t.Errorf("stop intent not persisted before restore: state=%q detail=%q, want stopped/operator-stop", srcState, srcDetail)
	}
}

// TestMigrateContainer_SourceRuntimeDeleteFailure_Errors: after the target lands,
// a source RUNTIME delete failure must NOT report success or leave an untracked
// container — it errors and the source row stays LIVE (tracked+stopped) for manual
// cleanup, because the runtime delete is ordered before the row tombstone.
func TestMigrateContainer_SourceRuntimeDeleteFailure_Errors(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	rt.deleteErr = errors.New("rmdir: directory busy")
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal when the source runtime delete fails, got %v", err)
	}
	// Row NOT tombstoned (runtime delete is ordered first), so the source stays
	// tracked + stopped + operator-stop — recoverable, not an untracked leak.
	src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if src == nil {
		t.Fatal("source row must remain live when its runtime delete fails")
	}
	if src.State != "stopped" || src.StateDetail != "operator-stop" {
		t.Errorf("source not parked stopped: state=%q detail=%q", src.State, src.StateDetail)
	}
}

// TestMigrateContainer_StoppedSourceGetsStopIntent: an ALREADY-stopped source
// (e.g. stopped out-of-band, with a restart policy) must also be marked
// operator-stop for the transfer window — otherwise the reconciler would restart
// it mid-migration and its post-archive writes would be lost when the source is
// removed after the target lands.
func TestMigrateContainer_StoppedSourceGetsStopIntent(t *testing.T) {
	s, _, repo := migrateTestServer(t, "stopped")
	ctx := context.Background()
	// A non-operator-stop detail: the reconciler WOULD act on this (restart policy).
	if err := corrosion.SetContainerStateDetail(ctx, s.db, "host-a", "ct1", "stopped", "out-of-band-stop"); err != nil {
		t.Fatal(err)
	}

	var srcDetail string
	var sawStart bool
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, start bool) (corrosion.RestoreOutcome, error) {
		sawStart = start
		if src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); src != nil {
			srcDetail = src.StateDetail
		}
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "stopped", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("MigrateContainer: %v", err)
	}
	if srcDetail != "operator-stop" {
		t.Errorf("stop intent not recorded for an already-stopped source: detail=%q, want operator-stop", srcDetail)
	}
	if sawStart {
		t.Error("an already-stopped source must not be started on the target")
	}
}

// TestMigrateContainer_StoppedSourceRollbackRestoresPriorDetail: on rollback, an
// originally-stopped source must be put back to its PRIOR state+detail — the
// migration operator-stop was only for the transfer window and must not be left
// behind (it would suppress the source's own restart policy).
func TestMigrateContainer_StoppedSourceRollbackRestoresPriorDetail(t *testing.T) {
	s, _, repo := migrateTestServer(t, "stopped")
	ctx := context.Background()
	if err := corrosion.SetContainerStateDetail(ctx, s.db, "host-a", "ct1", "stopped", "out-of-band-stop"); err != nil {
		t.Fatal(err)
	}
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		return corrosion.RestoreFailedBeforeRow, errors.New("target unreachable")
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
	src, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if src == nil || src.State != "stopped" || src.StateDetail != "out-of-band-stop" {
		t.Errorf("rollback did not restore the prior stopped state/detail: %+v", src)
	}
}

// TestMigrateContainer_SourceRowVanishedBeforeMarker_FailsClosed: if the source
// row is deleted/soft-deleted between the preflight read and the (strict)
// stop-intent write, migration fails closed — it does NOT restart the now-orphan
// runtime (which would resurrect an untracked container) and does NOT proceed to
// the restore.
func TestMigrateContainer_SourceRowVanishedBeforeMarker_FailsClosed(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	ctx := context.Background()
	// Simulate a concurrent/replicated delete landing during the cold stop — i.e.
	// after the preflight read, before the strict stop-intent write.
	rt.stopHook = func() { _ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1") }
	restoreCalled := false
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		restoreCalled = true
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition when the source row vanished, got %v", err)
	}
	if restoreCalled {
		t.Error("migration must not proceed to restore after the source row vanished")
	}
	if len(rt.startCalls) != 0 {
		t.Errorf("must NOT restart a vanished (untracked) source; start calls = %v", rt.startCalls)
	}
	// Best-effort orphan cleanup ran (the source runtime was deleted, not left).
	if len(rt.deleteCalls) != 1 || rt.deleteCalls[0] != "ct1" {
		t.Errorf("expected best-effort orphan runtime delete of ct1; delete calls = %v", rt.deleteCalls)
	}
}
