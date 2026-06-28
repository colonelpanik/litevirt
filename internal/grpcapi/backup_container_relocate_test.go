package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
	// Remove the live row (so restore proceeds past the AlreadyExists guard) AND
	// drop the table so the restore's row write fails after the import succeeds.
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	if err := s.db.Execute(ctx, `DROP TABLE containers`); err != nil {
		t.Fatalf("drop containers: %v", err)
	}

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
	s.migrateRestoreOverride = func(_ context.Context, target, repoPath, name, ts string, start bool) error {
		gotRepo, gotName, gotTs = repoPath, name, ts
		return nil
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
