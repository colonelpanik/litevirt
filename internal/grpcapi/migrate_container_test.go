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
	if ok, err := network.ReserveContainerIP(ctx, s.db, net, ip, mac, "host-a", "ct1"); err != nil || !ok {
		t.Fatalf("seed ReserveContainerIP: ok=%v err=%v", ok, err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct1", NetworkName: net, Ordinal: 0,
		MAC: mac, IP: ip, VethDevice: "lvtest0",
	}); err != nil {
		t.Fatalf("seed interface row: %v", err)
	}

	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) error {
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
	// Managed NIC with an IP but NO ip_allocations lease behind it.
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct1", NetworkName: "br-acme", Ordinal: 0,
		MAC: "02:00:00:00:00:09", IP: "10.9.0.9", VethDevice: "lvtest0",
	}); err != nil {
		t.Fatalf("seed interface row: %v", err)
	}
	restoreCalled := false
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) error {
		restoreCalled = true
		return nil
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
	if ok, err := network.ReserveContainerIP(ctx, s.db, net, ip, mac, "host-a", "ct1"); err != nil || !ok {
		t.Fatalf("seed ReserveContainerIP: ok=%v err=%v", ok, err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct1", NetworkName: net, Ordinal: 0,
		MAC: mac, IP: ip, VethDevice: "lvtest0",
	}); err != nil {
		t.Fatalf("seed interface row: %v", err)
	}

	// The restore fails — but by the time it runs the leases must already be on the
	// target (the handoff is a precondition, not a finalize step).
	s.migrateRestoreOverride = func(_ context.Context, _, _, _, _ string, _ bool) error {
		if a, _ := network.GetAllocationFor(ctx, s.db, net, "ct", "host-b", "ct1"); a == nil {
			t.Error("leases were not handed to the target before the restore ran")
		}
		return errors.New("target unreachable")
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
