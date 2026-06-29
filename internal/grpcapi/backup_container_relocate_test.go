package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// TestBackupContainer_RoundTripPreservesCreateSpec proves the v34 create-spec
// (networks/template) survives a backup→restore so a restored container — and a
// future relocation of it — stays networking-faithful.
func TestBackupContainer_RoundTripPreservesCreateSpec(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})

	spec := corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
		Template: "download", Distro: "alpine", Release: "3.19", Arch: "amd64",
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br0", IP: "10.1.2.3"}},
	})
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19",
		Project: "acme", OnHostFailure: "image-recreate", CreateSpec: spec,
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T10:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-27T10:00:00Z",
	}, rs); err != nil {
		t.Fatalf("RestoreContainer: %v", err)
	}

	row, err := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if err != nil || row == nil {
		t.Fatalf("restored row missing: %v", err)
	}
	if row.OnHostFailure != "image-recreate" {
		t.Errorf("restored on_host_failure = %q, want image-recreate", row.OnHostFailure)
	}
	got := corrosion.DecodeCreateSpec(row.CreateSpec)
	if got.Distro != "alpine" || got.Release != "3.19" || len(got.Networks) != 1 || got.Networks[0].Bridge != "br0" {
		t.Fatalf("restored create_spec lost fidelity: %+v", got)
	}
}

// TestRestoreContainer_RowWriteFailureCleansUp proves restore atomicity: if the
// runtime import succeeds but the cluster-row write fails, RestoreContainer
// returns an error and best-effort deletes the imported container — so failover
// can't tombstone the source for an untracked, never-recorded restore.
func TestRestoreContainer_RowWriteFailureCleansUp(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T11:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	// Remove the live row so restore proceeds past the AlreadyExists guard, then
	// drop the table DURING the import (after the handler's same-name preflight) so
	// the restore's row write fails once the runtime container already exists.
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	rt.importHook = func() { _ = s.db.Execute(ctx, `DROP TABLE containers`) }

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-27T11:00:00Z",
	}, rs)
	if err == nil {
		t.Fatal("expected an error when the restore row write fails")
	}
	// The imported runtime container must have been cleaned up (no untracked leftover).
	var deleted bool
	for _, n := range rt.deleteCalls {
		if n == "ct1" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("imported container must be deleted on row-write failure; deleteCalls=%v", rt.deleteCalls)
	}
}

// TestRestoreContainer_PreservesStopIntentWhenNotStarted: an operator-stopped CT
// backed up and restored WITHOUT starting must come back stopped + operator-stop,
// so the target reconciler doesn't treat it as an out-of-band stop and restart a
// container the operator had deliberately stopped. When the restore DOES start it,
// the intent is not applied (a running container has no stop intent).
func TestRestoreContainer_PreservesStopIntentWhenNotStarted(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})

	// Operator-stopped source with a restart policy (the reconciler WOULD restart it
	// if the intent were lost).
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "stopped", StateDetail: "operator-stop",
		Image: "alpine:3.19", Project: "acme", RestartPolicy: `{"condition":"any"}`,
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-29T10:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	// Restore WITHOUT starting — the stop intent must survive.
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-29T10:00:00Z", Start: false,
	}, rs); err != nil {
		t.Fatalf("RestoreContainer(start=false): %v", err)
	}
	rec, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if rec == nil || rec.State != "stopped" || rec.StateDetail != "operator-stop" {
		t.Fatalf("restore lost the operator-stop intent: %+v", rec)
	}

	// Restoring the SAME backup WITH start does not apply the stop intent (a started
	// container ends up running, detail cleared).
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	rs2 := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-29T10:00:00Z", Start: true,
	}, rs2); err != nil {
		t.Fatalf("RestoreContainer(start=true): %v", err)
	}
	rec2, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if rec2 == nil || rec2.State != "running" || rec2.StateDetail != "" {
		t.Fatalf("started restore should be running with no stop intent: %+v", rec2)
	}
}

// TestRestoreContainer_IPUnavailable_StampsNoRestart: a Start=true restore whose
// managed IP is held by another workload is left stopped — and stamped sticky
// operator-stop so the reconciler won't auto-restart the imported config (which
// still names the conflicting IP) into that very conflict.
func TestRestoreContainer_IPUnavailable_StampsNoRestart(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)

	const (
		net = "br-acme"
		ip  = "10.9.0.5"
		mac = "52:11:22:33:44:55"
	)
	// Source with a managed static-IP NIC (in create_spec) and a restart policy.
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: s.hostName, Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme",
		RestartPolicy: `{"condition":"any"}`,
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Networks: []corrosion.ContainerNetwork{{NetworkName: net, IP: ip, MAC: mac}},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: s.hostName, RepoPath: repo, Timestamp: "2026-06-29T11:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, s.hostName, "ct1")

	// Another workload (a CT on a different host) now holds the IP, so the restore
	// can't reserve it and blanks the NIC → unreserved > 0.
	if ok, err := network.ReserveContainerIP(ctx, s.db, net, ip, mac, "host-z", "squatter"); err != nil || !ok {
		t.Fatalf("seed squatter lease: ok=%v err=%v", ok, err)
	}

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-29T11:00:00Z", Start: true,
	}, rs); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition (IP unavailable), got %v", err)
	}
	if len(rt.startCalls) != 0 {
		t.Errorf("must not start a CT whose IP is unavailable; start calls = %v", rt.startCalls)
	}
	// Stamped sticky no-restart so the container checker leaves it down.
	rec, _ := corrosion.GetContainer(ctx, s.db, s.hostName, "ct1")
	if rec == nil || rec.State != "stopped" || rec.StateDetail != "operator-stop" {
		t.Errorf("IP-unavailable restore not marked no-restart: %+v", rec)
	}
}

// TestRestoreContainerFromBackup_FindsManifestAndDrives covers the coordinator
// entry point: no manifest → (false, err); after a backup it finds the newest
// manifest, passes the registered repo NAME to the target, and reports landed
// from the drive.
func TestRestoreContainerFromBackup_FindsManifestAndDrives(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})
	s.SetBackupRepos(map[string]string{"main": repo})

	// No backup yet → no manifest → not attempted, error.
	if outcome, err := s.RestoreContainerFromBackup(ctx, "ct1", "host-b", "tok-x"); err == nil || outcome != corrosion.RestoreNotAttempted {
		t.Fatalf("want (RestoreNotAttempted, err) with no manifest, got (%v, %v)", outcome, err)
	}

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: "main", Timestamp: "2026-06-27T12:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}

	var gotRepo, gotName, gotTs string
	s.migrateRestoreOverride = func(_ context.Context, target, repoPath, name, ts string, start bool) (corrosion.RestoreOutcome, error) {
		gotRepo, gotName, gotTs = repoPath, name, ts
		return corrosion.RestoreLanded, nil
	}
	outcome, err := s.RestoreContainerFromBackup(ctx, "ct1", "host-b", "tok-x")
	if err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("want (RestoreLanded, nil), got (%v, %v)", outcome, err)
	}
	if gotName != "ct1" || gotTs != "2026-06-27T12:00:00Z" || gotRepo != "main" {
		t.Fatalf("drove restore repo=%q name=%q ts=%q; want the registered NAME 'main' + ct1 + ts", gotRepo, gotName, gotTs)
	}
}

// TestRestoreContainer_StampsRelocateTokenFromMetadata exercises the production
// metadata hop: a RestoreContainer call carrying the x-litevirt-relocate-token
// metadata stamps that token on the restored row's RelocateToken (the
// coordinator later matches it as provenance).
func TestRestoreContainer_StampsRelocateTokenFromMetadata(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	repo := ctTestRepo(t)
	s.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs")})

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running", Image: "alpine:3.19", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T13:00:00Z",
	}, bk); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	// Restore with the relocation attempt token in incoming metadata.
	rctx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(relocateTokenMDKey, "tok-xyz"))
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: rctx}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: "2026-06-27T13:00:00Z",
	}, rs); err != nil {
		t.Fatalf("RestoreContainer: %v", err)
	}

	row, err := corrosion.GetContainer(ctx, s.db, "host-a", "ct1")
	if err != nil || row == nil {
		t.Fatalf("restored row missing: %v", err)
	}
	if row.RelocateToken != "tok-xyz" {
		t.Fatalf("restored RelocateToken = %q, want tok-xyz (metadata hop not stamped)", row.RelocateToken)
	}
}

// TestClassifyRestoreError maps restore RPC error codes to outcomes: definite
// pre-row failures (incl. AlreadyExists — an unrelated same-name container, never
// "landed") vs indeterminate (Internal / transport breaks → defer, don't clobber).
func TestClassifyRestoreError(t *testing.T) {
	beforeRow := []codes.Code{
		codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument,
		codes.PermissionDenied, codes.Unimplemented, codes.AlreadyExists,
	}
	for _, code := range beforeRow {
		if got := classifyRestoreError(status.Error(code, "x")); got != corrosion.RestoreFailedBeforeRow {
			t.Errorf("classifyRestoreError(%v) = %v, want RestoreFailedBeforeRow", code, got)
		}
	}
	unknown := []codes.Code{codes.Internal, codes.Unavailable, codes.Canceled, codes.DeadlineExceeded, codes.Unknown}
	for _, code := range unknown {
		if got := classifyRestoreError(status.Error(code, "x")); got != corrosion.RestoreUnknown {
			t.Errorf("classifyRestoreError(%v) = %v, want RestoreUnknown", code, got)
		}
	}
}
