package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Flow 2 (owner side): a container backup with sink_host set archives into a
// local staging repo and PushBackup-streams the manifest to the sink's CONFIGURED
// repo — the manifest lands there with no shared filesystem.
func TestBackupContainer_RemotePushToSink(t *testing.T) {
	// Sink: a configured logical repo "r1" + a host the owner's cert maps to.
	sink := newPeerAuthServer(t) // hostName "self", knows host "peer-1"
	sinkRepoDir := t.TempDir()
	if _, err := pbsstore.Init(sinkRepoDir); err != nil {
		t.Fatalf("init sink repo: %v", err)
	}
	sink.SetBackupRepos(map[string]string{"r1": sinkRepoDir})

	// Owner: holds the container + a fake runtime; pushes to the sink.
	owner := testServer(t)
	owner.hostName = "owner-host"
	owner.dataDir = t.TempDir()
	owner.SetContainerRuntime(&fakeCTRuntime{exportPayload: []byte("rootfs-bytes-rootfs-bytes")})
	if err := corrosion.UpsertContainer(context.Background(), owner.db, corrosion.ContainerRecord{
		HostName: "owner-host", Name: "ct1", State: "stopped",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	owner.peerClientOverride = func(_ context.Context, _ string) (pb.LiteVirtClient, func(), error) {
		return &fakeLVClient{srv: sink, peerCtx: mtlsCtx("peer-1")}, func() {}, nil
	}

	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := owner.BackupContainer(&pb.BackupContainerRequest{
		Name: "ct1", HostName: "owner-host", RepoPath: "r1",
		Timestamp: "2026-06-29T10:00:00Z", SinkHost: sink.hostName,
	}, bk); err != nil {
		t.Fatalf("BackupContainer(sink_host): %v", err)
	}

	// The manifest must now be in the SINK's repo.
	repo, err := pbsstore.Open(sinkRepoDir)
	if err != nil {
		t.Fatalf("open sink repo: %v", err)
	}
	if _, err := repo.GetManifest("ct1", "2026-06-29T10:00:00Z", containerBackupDisk); err != nil {
		t.Fatalf("manifest did not land in sink repo: %v", err)
	}
}

// Flow 2 (sink side): the called daemon forwards to the owner and reports success
// only after CONFIRMING the manifest landed in its own repo. An owning daemon too
// old to honor sink_host (reports DONE but pushes nothing) surfaces as an error,
// not a false success.
func TestSinkRemoteContainerBackup_AuthoritativeLandingCheck(t *testing.T) {
	mk := func(seedManifest bool) error {
		sink := newPeerAuthServer(t)
		sink.hostName = "sink-host"
		repoDir := t.TempDir()
		r, err := pbsstore.Init(repoDir)
		if err != nil {
			t.Fatalf("init repo: %v", err)
		}
		sink.SetBackupRepos(map[string]string{"r1": repoDir})
		// The container lives on a remote owner.
		if err := corrosion.UpsertContainer(context.Background(), sink.db, corrosion.ContainerRecord{
			HostName: "owner-host", Name: "ct1", State: "stopped",
		}); err != nil {
			t.Fatalf("UpsertContainer: %v", err)
		}
		if seedManifest {
			// Simulate the owner having pushed the manifest before reporting DONE.
			m, perr := pbsstore.PushDisk(context.Background(), r, bytes.NewReader([]byte("payload")), pbsstore.PushOptions{
				VMName: "ct1", DiskName: containerBackupDisk, Timestamp: "2026-06-29T10:00:00Z",
			})
			if perr != nil {
				t.Fatalf("seed PushDisk: %v", perr)
			}
			_ = m
		}
		// The forwarded BackupContainer reports DONE@ts (and, in the seeded case,
		// the manifest is already present; in the unseeded case nothing landed).
		sink.peerClientOverride = func(_ context.Context, _ string) (pb.LiteVirtClient, func(), error) {
			return &fakeLVClient{
				srv:     sink,
				peerCtx: mtlsCtx("peer-1"),
				backupContainerFn: func(_ *pb.BackupContainerRequest) ([]*pb.BackupContainerProgress, error) {
					return []*pb.BackupContainerProgress{{
						Phase: pb.BackupContainerProgress_DONE, ManifestTs: "2026-06-29T10:00:00Z",
					}}, nil
				},
			}, func() {}, nil
		}
		bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
		return sink.BackupContainer(&pb.BackupContainerRequest{Name: "ct1", RepoPath: "r1"}, bk)
	}

	if err := mk(true); err != nil {
		t.Fatalf("landed case: expected success, got %v", err)
	}
	if err := mk(false); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("not-landed case: expected FailedPrecondition, got %v", err)
	}
}

// Flows 3/4 (target side): RestoreContainer restores from a per-transfer staging
// repo a coordinator streamed into, then removes that staging repo afterward.
func TestRestoreContainer_FromStagingToken(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	ctx := context.Background()
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)

	// Produce a backup manifest the normal way, then stage it into the target's
	// internal staging repo (simulating the coordinator's PushBackup).
	repo := ctTestRepo(t)
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
	srcRepo, err := pbsstore.Open(repo)
	if err != nil {
		t.Fatalf("open src repo: %v", err)
	}
	m, err := srcRepo.GetManifest("ct1", "2026-06-27T11:00:00Z", containerBackupDisk)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	const token = "tok-restore"
	staging, err := s.openStagingRepo(token)
	if err != nil {
		t.Fatalf("openStagingRepo: %v", err)
	}
	if _, err := pbsstore.SyncManifest(ctx, srcRepo, m, pbsstore.RepoSink(staging)); err != nil {
		t.Fatalf("stage manifest: %v", err)
	}

	// Remove the live row so the restore proceeds past the AlreadyExists guard.
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")

	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", StagingToken: token, Timestamp: "2026-06-27T11:00:00Z",
	}, rs); err != nil {
		t.Fatalf("RestoreContainer(staging_token): %v", err)
	}
	// Row recreated from the staged manifest.
	if rec, _ := corrosion.GetContainer(ctx, s.db, "host-a", "ct1"); rec == nil {
		t.Fatal("container row not recreated from staging restore")
	}
	// The staging repo is a transient buffer — removed after the restore.
	if _, err := os.Stat(filepath.Join(s.dataDir, "restore-staging", token)); !os.IsNotExist(err) {
		t.Fatalf("staging repo should be cleaned up after restore, stat err = %v", err)
	}
}
