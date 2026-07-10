package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// containerBackupSpec is the slice of a container's cluster row embedded in the
// backup manifest, so a restore can recreate the row without the source cluster.
// The archived rootfs+config (the manifest's chunks) carries everything the LXC
// runtime needs; this carries what the Corrosion row needs.
type containerBackupSpec struct {
	Name          string            `json:"name"`
	Image         string            `json:"image,omitempty"`
	CPULimit      int               `json:"cpu_limit"`
	MemMiB        int               `json:"memory_mib"`
	Labels        map[string]string `json:"labels,omitempty"`
	RestartPolicy string            `json:"restart_policy,omitempty"`
	Project       string            `json:"project"`
	// v34: create-time intent (JSON ContainerCreateSpec: template/distro/release/
	// arch/networks) + the relocation policy and template flag, so a restore — or a
	// downstream host-loss relocation — rebuilds the container faithfully, incl.
	// litevirt-managed networking. Empty for backups taken before v34; readers
	// tolerate that and fall back to a bare image-recreate.
	CreateSpec    string `json:"create_spec,omitempty"`
	OnHostFailure string `json:"on_host_failure,omitempty"`
	IsTemplate    bool   `json:"is_template,omitempty"`
	// StateDetail carries the source's stop intent so a restore that does NOT start
	// the container (req.Start == false, e.g. cold-migrating an already-stopped CT)
	// preserves it. Only "operator-stop" is load-bearing — without it the target
	// reconciler treats the stopped row as an out-of-band stop and restarts it,
	// resurrecting a container the operator had deliberately stopped. (Other details
	// are transient — the reconciler overwrites them on its next sweep.)
	StateDetail string `json:"state_detail,omitempty"`
}

// containerBackupDisk is the manifest "disk" name for a container — a container
// has one logical volume, its rootfs.
const containerBackupDisk = "rootfs"

// restoreRowRecordedStatus is the progress-frame Status RestoreContainer sends
// once it has recorded the cluster row (post-import, pre-start). A remote driver
// uses it to detect a LANDED restore even if a later step (start) errors.
const restoreRowRecordedStatus = "cluster-row-recorded"

// relocateTokenMDKey is the gRPC metadata key carrying the failover coordinator's
// attempt token to a restore-relocation. The target stamps it on the restored
// row's relocate_token so the coordinator can prove the (target,name) row is ITS
// restore. Passed via metadata (not a proto field) so no contract change.
const relocateTokenMDKey = "x-litevirt-relocate-token"

// migrateFromMDKey marks a restore as the target side of a cross-host MIGRATE,
// carrying the source host. When honored, RestoreContainer keeps the imported NIC
// IPs (does NOT re-reserve/blank them) because the source has explicitly handed
// its IPAM leases to this host — a move ReserveContainerIP won't infer from a name.
const migrateFromMDKey = "x-litevirt-migrate-from-host"

// migrateFromMD reads the raw (UNVERIFIED) migrate-source claim from incoming gRPC
// metadata ("" if absent). Callers must NOT trust this directly — see
// migrateSourceFromPeer, which is the only path allowed to honor it.
func migrateFromMD(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(migrateFromMDKey); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// migrateSourceFromPeer returns the migrate source host ONLY when the marker is
// backed by peer mTLS whose certificate CN matches the claimed source (a known
// cluster host). RestoreContainer is operator-facing, so an operator/bearer caller
// — or a peer impersonating a different source — must NOT be able to set this
// header to skip IP re-reservation and import an address this host doesn't own.
// An unverified marker is IGNORED (returns ""), degrading safely to the normal
// reserve-or-blank path rather than rejecting the restore.
func (s *Server) migrateSourceFromPeer(ctx context.Context) string {
	claimed := migrateFromMD(ctx)
	if claimed == "" {
		return ""
	}
	if callerAuthMethod(ctx) != authMethodMTLS {
		slog.Warn("restore: ignoring migrate-from marker — caller is not a peer mTLS connection",
			"claimed_source", claimed)
		return ""
	}
	if cn := callerMTLSCommonName(ctx); cn != claimed {
		slog.Warn("restore: ignoring migrate-from marker — peer cert CN does not match the claimed source",
			"peer_cn", cn, "claimed_source", claimed)
		return ""
	}
	if h, _ := corrosion.GetHost(ctx, s.db, claimed); h == nil {
		slog.Warn("restore: ignoring migrate-from marker — claimed source is not a known cluster host",
			"claimed_source", claimed)
		return ""
	}
	return claimed
}

// BackupContainer freezes a container, streams its rootfs+config as a full,
// content-addressed manifest into the called daemon's repo, and indexes the size
// for quota. Call the repo-owning daemon: if the container lives elsewhere, this
// daemon (the repo sink) has the owning daemon archive locally and PushBackup-
// streams the manifest back over peer mTLS (sinkRemoteContainerBackup), then
// confirms it landed — so no shared repo is required (PR 4). sink_host drives the
// owner side of that forward and is gated to the sink peer (requireSinkPeer).
func (s *Server) BackupContainer(req *pb.BackupContainerRequest, stream grpc.ServerStreamingServer[pb.BackupContainerProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.Name == "" || req.RepoPath == "" {
		return status.Error(codes.InvalidArgument, "name and repo_path required")
	}
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// sink_host is an internal peer field — only the sink daemon may set it (to its
	// own hostname), so an operator/API client can't drive an owner→sink push that
	// skips the sink's authoritative landing + accounting. See requireSinkPeer.
	if err := s.requireSinkPeer(ctx, req.SinkHost); err != nil {
		return err
	}
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "backup.create", "operator"); err != nil {
		s.audit(ctx, "ct.backup", req.Name, "project="+project, "denied")
		return err
	}

	// Resolve the owning host.
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return err
	}
	// PR-4 flow 2 (remote CT backup, no shared repo): a remote container called
	// with no sink_host means WE are the repo SINK — have the owning daemon archive
	// locally and PushBackup the manifest back here, then confirm it landed.
	if req.SinkHost == "" && host != s.hostName {
		return s.sinkRemoteContainerBackup(ctx, host, req, stream)
	}
	if host != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"container %q lives on host %q; re-run against that daemon (set LV_HOST)",
			req.Name, host)
	}
	if s.containerRuntime == nil {
		return status.Error(codes.Unavailable, "container runtime not wired on this host")
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	// When asked to push to a remote sink (sink_host set), archive into a LOCAL
	// staging repo and stream the manifest to the sink afterward; otherwise write
	// directly into the resolved local repo (today's path).
	pushToSink := req.SinkHost != "" && req.SinkHost != s.hostName
	var repo *pbsstore.Repo
	if pushToSink {
		if filepath.IsAbs(req.RepoPath) {
			return status.Error(codes.InvalidArgument,
				"remote container backup requires a configured logical repo name on the sink (an absolute repo_path is local-only)")
		}
		var cleanup func()
		repo, cleanup, err = s.newLocalStagingRepo()
		if err != nil {
			return err
		}
		defer cleanup()
	} else {
		repoPath, rerr := s.resolveBackupRepoPath(ctx, req.RepoPath)
		if rerr != nil {
			return rerr
		}
		repo, err = pbsstore.Open(repoPath)
		if err != nil {
			return status.Errorf(codes.NotFound, "open repo %q: %v", req.RepoPath, err)
		}
	}
	timestamp := req.Timestamp
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	send := func(p *pb.BackupContainerProgress) error { return stream.Send(p) }

	// Quiesce a running container so the tar is a consistent point-in-time.
	// A freeze failure never fails the backup — log and proceed crash-consistent
	// (matches the VM fs-freeze policy). Always unfreeze, even on panic/error.
	froze := false
	if rec.State == "running" {
		if ferr := s.containerRuntime.FreezeContainer(ctx, req.Name); ferr != nil {
			_ = send(&pb.BackupContainerProgress{
				Phase:  pb.BackupContainerProgress_FREEZE,
				Status: fmt.Sprintf("freeze unavailable (%v) — proceeding crash-consistent", ferr),
			})
		} else {
			froze = true
			_ = send(&pb.BackupContainerProgress{
				Phase: pb.BackupContainerProgress_FREEZE, Status: "container frozen (consistent)",
			})
		}
	}
	if froze {
		defer func() {
			if uerr := s.containerRuntime.UnfreezeContainer(context.Background(), req.Name); uerr != nil {
				slog.Warn("container backup: unfreeze failed", "name", req.Name, "error", uerr)
			}
		}()
	}

	s.audit(ctx, "ct.backup", req.Name, "project="+project+" → "+req.RepoPath, "started")

	manifest, perr := s.archiveContainer(ctx, repo, rec, timestamp, func(p pbsstore.PushProgress) {
		_ = send(&pb.BackupContainerProgress{
			Phase:          pb.BackupContainerProgress_COPY,
			BytesProcessed: p.BytesProcessed, BytesNew: p.BytesNew,
			ChunksTotal: int32(p.ChunksTotal), ChunksDeduped: int32(p.ChunksDeduped),
		})
	})
	if perr != nil {
		s.audit(ctx, "ct.backup", req.Name, "project="+project, "error")
		return status.Errorf(codes.Internal, "backup push: %v", perr)
	}

	if pushToSink {
		// Stream the just-created manifest + its missing chunks to the sink's repo.
		// The sink records its own usage index; we don't double-count here.
		if err := s.pushManifestToPeerRepo(ctx, req.SinkHost, req.RepoPath, repo, manifest); err != nil {
			s.audit(ctx, "ct.backup", req.Name, "project="+project, "error")
			return err
		}
	} else if err := corrosion.UpsertContainerBackup(ctx, s.db, req.Name, req.RepoPath, manifest.TotalSize); err != nil {
		slog.Warn("container backup: update container_backups usage index",
			"name", req.Name, "repo", req.RepoPath, "error", err)
	}
	s.audit(ctx, "ct.backup", req.Name, fmt.Sprintf("project=%s → %s @ %s", project, req.RepoPath, manifest.Timestamp), "ok")
	return send(&pb.BackupContainerProgress{
		Phase:          pb.BackupContainerProgress_DONE,
		ManifestTs:     manifest.Timestamp,
		ChunksTotal:    int32(len(manifest.Chunks)),
		BytesProcessed: manifest.TotalSize,
		Status:         fmt.Sprintf("backup stored at %s", manifest.Timestamp),
	})
}

// sinkRemoteContainerBackup runs on the daemon the operator called (the repo
// SINK) when the container lives on another host: it asks the owning daemon to
// archive locally and PushBackup the manifest back here (sink_host = us), proxies
// progress, then CONFIRMS the manifest landed in our repo — so an owning daemon
// too old to honor sink_host surfaces as an error, not a false success.
func (s *Server) sinkRemoteContainerBackup(ctx context.Context, owner string, req *pb.BackupContainerRequest, stream grpc.ServerStreamingServer[pb.BackupContainerProgress]) error {
	if filepath.IsAbs(req.RepoPath) {
		return status.Error(codes.InvalidArgument,
			"remote container backup requires a configured logical repo name (an absolute repo_path is local-only)")
	}
	repoPath, err := s.resolveBackupRepoPath(ctx, req.RepoPath)
	if err != nil {
		return err
	}
	c, closeConn, err := s.dialPeer(ctx, owner)
	if err != nil {
		return status.Errorf(codes.Unavailable, "reach owning host %q: %v", owner, err)
	}
	defer closeConn()

	fwd := proto.Clone(req).(*pb.BackupContainerRequest)
	fwd.SinkHost = s.hostName
	stream2, err := c.BackupContainer(ctx, fwd)
	if err != nil {
		return err
	}
	var ownerTS string
	for {
		p, e := stream2.Recv()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if p.ManifestTs != "" {
			ownerTS = p.ManifestTs
		}
		if p.Phase != pb.BackupContainerProgress_DONE {
			_ = stream.Send(p)
		}
	}

	ts := ownerTS
	if ts == "" {
		ts = req.Timestamp
	}
	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		return status.Errorf(codes.Internal, "open sink repo: %v", err)
	}
	m, err := repo.GetManifest(req.Name, ts, containerBackupDisk)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"remote backup did not land in repo %q (the owning daemon %q may not support peer backup streaming): %v",
			req.RepoPath, owner, err)
	}
	if err := corrosion.UpsertContainerBackup(ctx, s.db, req.Name, req.RepoPath, m.TotalSize); err != nil {
		slog.Warn("container backup: update container_backups usage index", "name", req.Name, "repo", req.RepoPath, "error", err)
	}
	return stream.Send(&pb.BackupContainerProgress{
		Phase:          pb.BackupContainerProgress_DONE,
		ManifestTs:     m.Timestamp,
		ChunksTotal:    int32(len(m.Chunks)),
		BytesProcessed: m.TotalSize,
		Status:         fmt.Sprintf("backup stored at %s (archived on %s)", m.Timestamp, owner),
	})
}

// RestoreContainerFromBackup restores ctName's latest valid backup onto
// targetHost. It searches THIS daemon's configured repos for the newest valid
// manifest, then drives the target's RestoreContainer over peer mTLS, passing the
// registered repo NAME so the target resolves it in its OWN config (the
// shared-repo assumption the migrate path already relies on).
//
// It returns landed=true once the TARGET reports it recorded the cluster row
// (authoritative, even if a later start errors), so the failover coordinator
// needn't consult its own replication-lagged replica to tell a landed restore
// from a genuine failure. landed=false + err ⇒ fall back to image-recreate.
// Satisfies failover.ContainerRestorer.
func (s *Server) RestoreContainerFromBackup(ctx context.Context, ctName, targetHost, token string) (corrosion.RestoreOutcome, error) {
	repoName, timestamp, err := s.findLatestContainerBackup(ctName)
	if err != nil {
		return corrosion.RestoreNotAttempted, err
	}
	return s.driveRemoteRestore(ctx, targetHost, repoName, ctName, timestamp, token)
}

// relocateTokenFromMD reads the relocation attempt token from incoming gRPC
// metadata (” for a direct, non-relocation restore).
func relocateTokenFromMD(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(relocateTokenMDKey); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// relocationProofTokenBound reports whether a carried relocation proof's token is bound
// to the token being stamped on the restored row: both present and equal. The
// coordinator's recovery treats the row's relocate_token as provenance, so the validated
// proof and the stamped token must be the SAME non-empty attempt.
func relocationProofTokenBound(proofToken, mdToken string) bool {
	return proofToken != "" && mdToken != "" && proofToken == mdToken
}

// Restore proof markers — a host-local, DB-independent record of which restore PROOF
// produced the on-disk container artifact for `name`. Written after ImportContainer and
// BEFORE the DB row, so a crash between them is resumable by proof (reuse the artifact
// only when its marker proves THIS proof; a different/absent marker is refused or a clean
// untracked leftover is removed). Survives daemon restart; keyed by the validated name.

func (s *Server) restoreMarkerPath(name string) string {
	return filepath.Join(s.dataDir, "ct-restore-markers", name)
}

// readRestoreMarker returns the proof id recorded for `name`. It distinguishes ABSENT
// (no file → "", nil) from UNREADABLE/corrupt (permission, I/O, … → "", err): an empty
// marker is treated by the resume path as "untracked leftover, safe to clean + re-import",
// so a read error must NOT collapse to "" — that could destroy an artifact another restore
// owns. The caller fails closed on a non-nil error.
func (s *Server) readRestoreMarker(name string) (string, error) {
	b, err := os.ReadFile(s.restoreMarkerPath(name))
	if os.IsNotExist(err) {
		return "", nil // genuinely absent
	}
	if err != nil {
		return "", err // unreadable/corrupt → indeterminate, fail closed
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Server) writeRestoreMarker(name, proofID string) error {
	if err := os.MkdirAll(filepath.Join(s.dataDir, "ct-restore-markers"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.restoreMarkerPath(name), []byte(proofID), 0o600)
}

func (s *Server) removeRestoreMarker(name string) { _ = os.Remove(s.restoreMarkerPath(name)) }

// driveRemoteRestore opens RestoreContainer on the target over peer mTLS, drains
// its progress stream, and classifies the result. The authoritative "row
// recorded" signal is the target's restoreRowRecordedStatus frame (or a clean
// DONE/EOF); a definite pre-row status code means nothing was written; anything
// else after the RPC started is indeterminate (the row may have landed but the
// frame/stream was lost) → RestoreUnknown, which the coordinator defers rather
// than destructively falling back.
func (s *Server) driveRemoteRestore(ctx context.Context, target, repoPath, name, timestamp, token string) (corrosion.RestoreOutcome, error) {
	// Carry the attempt token to the target (on the RestoreContainer call) so it
	// stamps the restored row. The transport (PR-4 push to staging vs. shared-repo
	// fallback) is handled by drivePeerRestore.
	var md []string
	var proof *pb.RuntimeActionProof
	if token != "" {
		md = []string{relocateTokenMDKey, token}
		// Carry the FULL relocation proof (read from our just-written local row) so
		// the target validates + claims it without depending on proof-row gossip.
		if pr, ok, _ := corrosion.GetActionProofByToken(ctx, s.db, token); ok {
			proof = &pb.RuntimeActionProof{
				Id: pr.ID, Action: pr.Action, TargetKind: pr.TargetKind, TargetName: pr.TargetName,
				DestHost: pr.DestHost, Coordinator: pr.Coordinator, RelocationToken: pr.RelocationToken,
			}
		} else if s.gateActive(ctx) {
			// Under enforcement the coordinator minted a proof for this token; a miss
			// means we must NOT drive a proofless restore (the target would refuse) —
			// defer and retry rather than silently downgrade.
			return corrosion.RestoreNotAttempted, fmt.Errorf("relocation proof for token %s not found under enforcement; deferring", token)
		}
	}
	return s.drivePeerRestore(ctx, target, repoPath, name, timestamp, true, proof, md...)
}

// drainRestoreStream classifies a remote RestoreContainer progress stream. The
// authoritative "row recorded" signal is the target's restoreRowRecordedStatus
// frame (or a clean DONE/EOF) ⇒ RestoreLanded — once seen, a later error is the
// target's own recoverable post-land state (e.g. a start failure), NOT a reason to
// undo the restore. A definite pre-row status code means nothing was written;
// anything else after the row may have landed is indeterminate (RestoreUnknown).
// Shared by driveRemoteRestore (failover) and migrateRestore (cold migrate) so
// both make the same land/rollback decision.
func drainRestoreStream(rs grpc.ServerStreamingClient[pb.RestoreContainerProgress]) (corrosion.RestoreOutcome, error) {
	landed := false
	for {
		p, e := rs.Recv()
		if e == io.EOF {
			return corrosion.RestoreLanded, nil // clean DONE ⇒ full success
		}
		if e != nil {
			if landed {
				return corrosion.RestoreLanded, nil // row recorded before the break
			}
			return classifyRestoreError(e), e
		}
		if p.Error != "" {
			if landed {
				return corrosion.RestoreLanded, nil
			}
			return corrosion.RestoreUnknown, fmt.Errorf("target restore: %s", p.Error)
		}
		if p.Status == restoreRowRecordedStatus {
			landed = true
		}
	}
}

// classifyRestoreError maps a restore RPC error (received WITHOUT a prior
// row-recorded frame) to an outcome. Definite pre-row status codes — the target
// can't open the repo / find the manifest / isn't the target / unauthorized — are
// conclusive (nothing of ours was written); anything else (Internal, or a
// transport break that may have dropped the row-recorded frame after the row was
// written) is indeterminate.
//
// AlreadyExists is NOT treated as "landed": container names aren't cluster-unique
// (PK is (host_name,name)), so it means the target already holds SOME live
// container of that name — possibly UNRELATED. Without provenance we must not
// claim our restore landed there (that would tombstone the source over an
// unrelated container), so it's a pre-row failure; the coordinator's
// collision-aware fallback then declines to clobber it.
func classifyRestoreError(err error) corrosion.RestoreOutcome {
	switch status.Code(err) {
	case codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument, codes.PermissionDenied, codes.Unimplemented, codes.AlreadyExists:
		return corrosion.RestoreFailedBeforeRow
	default:
		return corrosion.RestoreUnknown
	}
}

// findLatestContainerBackup scans the daemon's configured repos for the newest
// structurally-valid rootfs manifest of ctName, returning the registered repo
// NAME (not path) + the manifest timestamp. A registered name is preferred so
// the target can resolve the same repo via its own config.
func (s *Server) findLatestContainerBackup(ctName string) (repoName, timestamp string, err error) {
	if len(s.backupRepos) == 0 {
		return "", "", fmt.Errorf("no backup repos configured")
	}
	var bestName, bestTS string
	for name, path := range s.backupRepos {
		repo, oerr := pbsstore.Open(path)
		if oerr != nil {
			continue // repo not openable from here — skip
		}
		m, ok, merr := repo.LatestManifestFor(ctName, containerBackupDisk)
		if merr != nil || !ok || m == nil {
			continue
		}
		if pbsstore.ValidateManifest(m) != nil {
			continue // structurally invalid → not restorable
		}
		// Manifest timestamps are RFC3339 (lexical == chronological).
		if m.Timestamp > bestTS {
			bestTS, bestName = m.Timestamp, name
		}
	}
	if bestName == "" {
		return "", "", fmt.Errorf("no valid backup manifest for %q in configured repos", ctName)
	}
	return bestName, bestTS, nil
}

// archiveContainer streams a container's whole on-disk directory (rootfs + LXC
// config) into repo as a full, content-addressed manifest, embedding its spec
// so a restore is self-contained. The caller holds the ct lock and has already
// quiesced the container (frozen for a live backup, or stopped for migration).
// Shared by BackupContainer and MigrateContainer — one tested data path.
func (s *Server) archiveContainer(ctx context.Context, repo *pbsstore.Repo, rec *corrosion.ContainerRecord, timestamp string, progress func(pbsstore.PushProgress)) (*pbsstore.Manifest, error) {
	specJSON, _ := json.Marshal(containerBackupSpec{
		Name: rec.Name, Image: rec.Image, CPULimit: rec.CPULimit, MemMiB: rec.MemMiB,
		Labels: rec.Labels, RestartPolicy: rec.RestartPolicy, Project: rec.Project,
		CreateSpec: rec.CreateSpec, OnHostFailure: rec.OnHostFailure, IsTemplate: rec.IsTemplate,
		StateDetail: rec.StateDetail,
	})
	// Pipe the export tar straight into the chunk store so we never buffer the
	// whole rootfs. If PushDisk returns early (error), CloseWithError unblocks
	// the export goroutine's pending Write.
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(s.containerRuntime.ExportContainer(ctx, rec.Name, pw))
	}()
	m, perr := pbsstore.PushDisk(ctx, repo, pr, pbsstore.PushOptions{
		VMName: rec.Name, DiskName: containerBackupDisk, Timestamp: timestamp,
		ContainerSpecJSON: string(specJSON), Progress: progress,
	})
	_ = pr.CloseWithError(perr)
	return m, perr
}

// RestoreContainer rebuilds a container from a manifest alone: materialise the
// archived tar, hand it to the runtime to lay down rootfs+config, then recreate
// the cluster row from the embedded spec. Self-contained — works after the
// source container (and even its image) is gone. Runs on the target host.
func (s *Server) RestoreContainer(req *pb.RestoreContainerRequest, stream grpc.ServerStreamingServer[pb.RestoreContainerProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.Name == "" || req.Timestamp == "" || (req.RepoPath == "" && req.StagingToken == "") {
		return status.Error(codes.InvalidArgument, "name, timestamp and one of repo_path / staging_token required")
	}
	// Validate the name before it composes the permission path, the staging
	// tar path (dataDir/ct-restore), or the container dir.
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}

	target := req.HostName
	if target == "" {
		target = s.hostName
	}
	if target != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"restore must run on the target host %q (set LV_HOST)", target)
	}
	if s.containerRuntime == nil {
		return status.Error(codes.Unavailable, "container runtime not wired on this host")
	}

	// Split-brain gate (Phase 1): a restore-relocation is a runtime-ownership
	// action. The target must have local quorum (ExecutionGate) AND, for a
	// token-bound coordinator restore, validate + single-use-claim the proof before
	// importing/recording. A carried proof MARKER forces the ExecutionGate even if
	// THIS host hasn't latched enforcement — an asymmetric partition can deliver a
	// valid proof to a target lacking quorum, which must not restore. Fail-open only
	// for a proofless restore before activation.
	if reason, refused := s.execGateForAction(ctx, req.Proof != nil); refused {
		s.noteGateRefused(corrosion.ActionRelocate, reason)
		return status.Errorf(codes.FailedPrecondition, "restore refused: %s", reason)
	}
	// A carried relocation proof must arrive over peer mTLS (coordinator-driven).
	if req.Proof != nil {
		if err := s.requirePeerCert(ctx); err != nil {
			return status.Error(codes.PermissionDenied, "restore relocation proof requires a peer cert")
		}
		// Bind the carried proof to the relocation token that will be stamped on the row
		// (relocateTokenFromMD). The coordinator's recovery treats the row's relocate_token
		// as PROVENANCE — completeRestore tombstones the source only when the row token
		// matches its attempt token — so the proof we validate and the token we stamp MUST
		// be the SAME non-empty attempt. Refuse (before claiming) otherwise, so a malformed
		// peer can't use a valid proof for token A while stamping token B (or none),
		// diverging proof from provenance. (The DB-driven relocate-recreate path binds them
		// by looking the proof up BY the row token; the direct RPC binds by exact equality.)
		mdToken := relocateTokenFromMD(ctx)
		if !relocationProofTokenBound(req.Proof.GetRelocationToken(), mdToken) {
			s.noteGateRefused(corrosion.ActionRelocate, health.ReasonProofConflict)
			return status.Errorf(codes.FailedPrecondition,
				"restore refused: relocation proof token %q does not match the stamped relocation token %q",
				req.Proof.GetRelocationToken(), mdToken)
		}
	}
	// Validate + single-use-claim the FULL carried proof (no dependence on proof-row
	// gossip). claimCarriedProof enforces action/target/dest==self + exact durable
	// binding; the execute-side ExecutionGate above enforces local quorum. A
	// proofless restore under enforcement is refused.
	restoreProofID, cpErr := s.claimCarriedProof(ctx, req.Proof, corrosion.ActionRelocate, "container", req.Name)
	if cpErr != nil {
		s.noteGateRefused(corrosion.ActionRelocate, health.ReasonProofConflict)
		return cpErr
	}
	if req.Proof == nil && s.gateActive(ctx) && s.requirePeerCert(ctx) == nil {
		s.noteGateRefused(corrosion.ActionRelocate, health.ReasonProofMissing)
		return status.Error(codes.FailedPrecondition, "restore refused: coordinator restore requires a proof under enforcement")
	}

	// Resolve the source of the manifest+chunks. staging_token (PR 4) is the
	// per-transfer internal repo a migrate/failover coordinator PushBackup-streamed
	// into — so the target restores WITHOUT needing the source's repo over NFS. It
	// is a transient transfer buffer, removed once we've materialised the tar.
	var (
		repo *pbsstore.Repo
		err  error
	)
	if req.StagingToken != "" {
		repo, err = s.openStagingRepo(req.StagingToken)
		if err != nil {
			return err
		}
		defer s.removeStagingRepo(req.StagingToken)
	} else {
		repoPath, rerr := s.resolveBackupRepoPath(ctx, req.RepoPath)
		if rerr != nil {
			return rerr
		}
		repo, err = pbsstore.Open(repoPath)
		if err != nil {
			return status.Errorf(codes.NotFound, "open repo: %v", err)
		}
	}
	manifest, err := repo.GetManifest(req.Name, req.Timestamp, containerBackupDisk)
	if err != nil {
		return status.Errorf(codes.NotFound, "manifest: %v", err)
	}
	// Authorize against the backup's actual project (live row, else the manifest
	// spec; admin when undeterminable) and use that project for the restored row
	// — never a _default fallback (cross-project read) nor the unauthenticated
	// manifest-claimed project.
	project, err := s.authorizeContainerRestore(ctx, req.Name, manifest)
	if err != nil {
		s.audit(ctx, "ct.restore", req.Name, "denied", "denied")
		return err
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	// Refuse to clobber a live container of the same name on this host. Fail CLOSED
	// on a read error — proceeding could land a restore over an existing container
	// (and a later cleanup keyed on (host, name) could release its NIC state).
	existing, gerr := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if gerr != nil {
		return status.Errorf(codes.Internal, "check existing container: %v", gerr)
	}
	if existing != nil {
		return status.Errorf(codes.AlreadyExists,
			"container %q already exists on host %q; delete it first or restore under a different name",
			req.Name, s.hostName)
	}

	send := func(p *pb.RestoreContainerProgress) error { return stream.Send(p) }

	// Crash-idempotent resume (proof-gated coordinator restores). A crash between
	// ImportContainer and the DB row write below leaves an UNTRACKED runtime artifact
	// (dir exists, no DB row — the row was checked above). On retry we resume by PROOF,
	// never by re-importing blindly or adopting an unmarked/foreign artifact: a host-local
	// marker (written right after import, before the row) records which proof produced it.
	skipImport := false
	if restoreProofID != "" {
		exists, xerr := s.containerRuntime.ContainerExists(ctx, req.Name)
		if xerr != nil {
			return status.Errorf(codes.Unavailable, "check existing container artifact: %v", xerr)
		}
		if exists {
			marker, merr := s.readRestoreMarker(req.Name)
			switch {
			case merr != nil:
				// Marker unreadable/corrupt — NOT proof the artifact is unowned. Fail closed
				// rather than destroy an artifact a different restore attempt may own.
				return status.Errorf(codes.Internal, "restore refused: cannot read restore marker for %q: %v", req.Name, merr)
			case marker == restoreProofID:
				skipImport = true // our own prior import (crash after import) → reuse it
			case marker != "":
				return status.Errorf(codes.FailedPrecondition,
					"restore refused: existing runtime artifact for %q belongs to a different restore attempt", req.Name)
			default:
				// Untracked, unmarked leftover (marker genuinely ABSENT — crash before the
				// marker landed, or an orphan; nothing in the DB tracks it). Clean it and
				// re-import under this proof rather than adopt an artifact we can't attribute —
				// but DeleteContainer is a force-destroy (lxc-destroy -f) that would kill a live
				// workload, so ONLY clean when the state read positively confirms it is STOPPED.
				// Fail closed on RUNNING *and* on a state-read error (can't confirm stopped →
				// don't force-destroy); let the operator stop/remove it first.
				st, serr := s.containerRuntime.StateContainer(ctx, req.Name)
				if serr != nil {
					return status.Errorf(codes.Internal,
						"restore refused: cannot determine state of untracked container %q (%v) — stop/remove it before restoring over it", req.Name, serr)
				}
				if strings.EqualFold(st, "running") {
					return status.Errorf(codes.FailedPrecondition,
						"restore refused: an untracked container %q is RUNNING here — stop/remove it before restoring over it", req.Name)
				}
				if derr := s.containerRuntime.DeleteContainer(ctx, req.Name); derr != nil {
					return status.Errorf(codes.Internal, "clean untracked leftover container %q: %v", req.Name, derr)
				}
			}
		}
	}

	if !skipImport {
		if err := send(&pb.RestoreContainerProgress{
			Phase:       pb.RestoreContainerProgress_RESTORE,
			ChunksTotal: int32(len(manifest.Chunks)),
			Status:      fmt.Sprintf("restoring %s@%s on %s", req.Name, req.Timestamp, s.hostName),
		}); err != nil {
			return err
		}

		// Materialise the archived tar to a staging file (RestoreToFile is atomic +
		// corruption-checked), then stream it into the runtime's importer.
		stageDir := filepath.Join(s.dataDir, "ct-restore")
		if err := os.MkdirAll(stageDir, 0o755); err != nil {
			return status.Errorf(codes.Internal, "staging dir: %v", err)
		}
		tarPath := filepath.Join(stageDir, fmt.Sprintf("%s-%d.tar", req.Name, time.Now().UnixNano()))
		defer os.Remove(tarPath)
		if err := pbsstore.RestoreToFile(ctx, repo, manifest, tarPath, pbsstore.RestoreOptions{
			Progress: func(p pbsstore.RestoreProgress) {
				_ = send(&pb.RestoreContainerProgress{
					Phase:        pb.RestoreContainerProgress_RESTORE,
					BytesWritten: p.BytesWritten,
					ChunksDone:   int32(p.ChunksDone), ChunksTotal: int32(p.ChunksTotal),
				})
			},
		}); err != nil {
			s.audit(ctx, "ct.restore", req.Name, "project="+project, "error")
			return status.Errorf(codes.Internal, "restore chunks: %v", err)
		}

		_ = send(&pb.RestoreContainerProgress{Phase: pb.RestoreContainerProgress_IMPORT, Status: "laying down container"})
		f, err := os.Open(tarPath)
		if err != nil {
			return status.Errorf(codes.Internal, "open staged tar: %v", err)
		}
		importErr := s.containerRuntime.ImportContainer(ctx, req.Name, f)
		_ = f.Close()
		if importErr != nil {
			s.audit(ctx, "ct.restore", req.Name, "project="+project, "error")
			return status.Errorf(codes.Internal, "import container: %v", importErr)
		}
		// Stamp the proof marker immediately after import, BEFORE the DB row — so a crash
		// in the row write resumes (marker match → skipImport) instead of re-importing. If
		// the marker can't be written, a later crash would strand an unmarked artifact, so
		// fail closed by cleaning up the just-imported container.
		if restoreProofID != "" {
			if err := s.writeRestoreMarker(req.Name, restoreProofID); err != nil {
				if delErr := s.containerRuntime.DeleteContainer(ctx, req.Name); delErr != nil {
					slog.Warn("container restore: cleanup after marker-write failure", "name", req.Name, "error", delErr)
				}
				return status.Errorf(codes.Internal, "record restore marker: %v", err)
			}
		}
	}

	// Recreate the cluster row from the embedded spec. The spec is UNTRUSTED
	// manifest data, so it supplies only descriptive fields (image/cpu/mem/
	// labels/restart) — never the project: a tampered manifest must not move the
	// restored container into a project the caller wasn't authorized for. The
	// row uses the project the permission check was made against; a cross-project
	// restore is a separate, explicitly-authorized operation.
	spec := containerBackupSpec{Name: req.Name, Project: project}
	if manifest.ContainerSpecJSON != "" {
		_ = json.Unmarshal([]byte(manifest.ContainerSpecJSON), &spec)
	}
	// Preserve the source's stop intent ONLY when we are NOT going to start the
	// container (req.Start == false — e.g. cold-migrating an already-stopped CT).
	// Otherwise the row lands as stopped with an empty detail and the reconciler
	// treats it as an out-of-band stop, restarting a CT the operator had stopped.
	// When we DO start it, leave the detail empty (a successful start clears it; a
	// failed start must not inherit a stale stop intent).
	stateDetail := ""
	if !req.Start {
		stateDetail = spec.StateDetail
	}
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: req.Name, State: "stopped", StateDetail: stateDetail,
		Image: spec.Image, CPULimit: spec.CPULimit, MemMiB: spec.MemMiB,
		Labels: spec.Labels, RestartPolicy: spec.RestartPolicy,
		Project: tenancy.NormalizeProject(project),
		// Carry forward the create-time intent + relocation policy/template flag so
		// a future host-loss relocation of THIS restored container is faithful.
		// Empty CreateSpec (pre-v34 backup) is tolerated downstream.
		CreateSpec:    spec.CreateSpec,
		OnHostFailure: spec.OnHostFailure,
		IsTemplate:    spec.IsTemplate,
		// Stamp the failover coordinator's attempt token (if this is a
		// restore-relocation) so it can prove this row is its restore.
		RelocateToken: relocateTokenFromMD(ctx),
	}
	// The cluster-state write is MANDATORY and atomic: the container row AND its
	// managed interface rows go in ONE batch, so a restore can't land a tracked
	// container with missing NIC state (failover relies on "row exists ⇒ restore
	// landed"). On failure, delete the just-imported runtime container so nothing
	// untracked is left, then error out (before signalling "landed").
	ifs := corrosion.BuildContainerInterfacesFromSpec(s.hostName, req.Name, corrosion.DecodeCreateSpec(rec.CreateSpec))
	if err := corrosion.CreateContainerAtomic(ctx, s.db, rec, ifs); err != nil {
		if delErr := s.containerRuntime.DeleteContainer(ctx, req.Name); delErr != nil {
			slog.Warn("container restore: failed to clean up imported container after cluster-state-write failure",
				"name", req.Name, "error", delErr)
		}
		s.removeRestoreMarker(req.Name) // artifact removed → drop its proof marker
		s.audit(ctx, "ct.restore", req.Name, "project="+project, "error")
		return status.Errorf(codes.Internal, "restore: record cluster state: %v", err)
	}
	// The row landed (point of no return): the DB row is now the durable record, so the
	// host-local proof marker is no longer needed (any future retry hits the "row already
	// exists" guard above, never the resume path). Drop it best-effort.
	s.removeRestoreMarker(req.Name)
	// Mark the relocation proof terminal (single-use) so a duplicate restore of the same
	// attempt can't re-import.
	if restoreProofID != "" {
		if err := corrosion.CompleteActionProof(ctx, s.db, restoreProofID, s.hostName); err != nil {
			slog.Warn("container restore: complete relocation proof", "name", req.Name, "proof", restoreProofID, "error", err)
		}
	}
	// Re-reserve the managed IPs on this host (conditional — never steals; blanks a
	// NIC whose IP a different workload now holds). Runs after the rows are written.
	// unreserved NICs gate the start below: the IMPORTED on-disk config still names
	// those IPs, so booting would cause the very conflict the blank avoids.
	//
	// EXCEPTION — a VERIFIED cross-host MIGRATE (peer-authenticated migrate-from):
	// keep the imported IPs as is; the source daemon has handed its IPAM leases to
	// this host explicitly (a move ReserveContainerIP won't infer from a name), so
	// re-reserving here would wrongly blank a still-valid address. The marker is
	// honored only over peer mTLS with a CN matching the source (migrateSourceFromPeer)
	// — an operator-supplied header falls through to the safe re-reserve path.
	unreserved := 0
	if s.migrateSourceFromPeer(ctx) == "" {
		u, rerr := network.ReserveContainerNICs(ctx, s.db, s.hostName, req.Name, ifs)
		if rerr != nil {
			slog.Warn("container restore: IP re-reservation incomplete (NIC may be re-discovered)",
				"name", req.Name, "error", rerr)
		}
		unreserved = u
	}

	// Signal that the cluster row has been recorded — the restore has LANDED. A
	// remote driver (failover RestoreContainerFromBackup) keys off this frame to
	// distinguish a landed restore whose later start failed from a genuine restore
	// failure, WITHOUT consulting its own (possibly replication-lagged) view of the
	// target row.
	_ = send(&pb.RestoreContainerProgress{Phase: pb.RestoreContainerProgress_IMPORT, Status: restoreRowRecordedStatus})

	if req.Start {
		if unreserved > 0 {
			// The imported on-disk config still names IP(s) we couldn't reserve (held
			// by another workload). Starting would create a real network conflict, so
			// leave it stopped + tracked (recoverable) and surface the reason. The row
			// was created with an EMPTY detail (we intended to start it) and keeps its
			// restart policy — which the reconciler would read as an out-of-band stop
			// and restart into that very conflict. Stamp the sticky operator-stop marker
			// so it stays down until an operator frees the IP and starts it explicitly.
			if derr := corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Name, "stopped", "operator-stop"); derr != nil {
				s.audit(ctx, "ct.restore", req.Name, "project="+project+" (ip unavailable; failed to mark no-restart)", "error")
				return status.Errorf(codes.Internal,
					"restored %q but %d NIC(s) had unavailable IPs and marking it no-restart failed: %v", req.Name, unreserved, derr)
			}
			s.audit(ctx, "ct.restore", req.Name, "project="+project+" (ip unavailable; left stopped)", "error")
			return status.Errorf(codes.FailedPrecondition,
				"restored %q but %d NIC(s) had unavailable IPs — left stopped (operator-stop) to avoid a network conflict", req.Name, unreserved)
		}
		if err := s.containerRuntime.StartContainer(ctx, req.Name); err != nil {
			// Partial success: the container is restored AND tracked (row stays
			// 'stopped'), so the reconciler / restart policy can start it later. We
			// return an error but deliberately do NOT delete the row — a tracked
			// stopped container is recoverable; an ambiguous half-state is not.
			s.audit(ctx, "ct.restore", req.Name, "project="+project+" (start failed)", "error")
			return status.Errorf(codes.Internal, "restored but start failed: %v", err)
		}
		if werr := corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Name, "running", ""); werr != nil {
			s.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
	}

	s.audit(ctx, "ct.restore", req.Name, fmt.Sprintf("project=%s from %s @ %s", project, req.RepoPath, req.Timestamp), "ok")
	return send(&pb.RestoreContainerProgress{
		Phase:        pb.RestoreContainerProgress_DONE,
		BytesWritten: manifest.TotalSize,
		ChunksDone:   int32(len(manifest.Chunks)), ChunksTotal: int32(len(manifest.Chunks)),
		Status: "restore complete",
	})
}

// resolveContainerHost finds the host that owns a container. When hostHint is
// set it's trusted (and the row fetched directly); otherwise the cluster is
// scanned by name. Returns the host plus the record.
func (s *Server) resolveContainerHost(ctx context.Context, hostHint, name string) (string, *corrosion.ContainerRecord, error) {
	if hostHint != "" {
		rec, err := corrosion.GetContainer(ctx, s.db, hostHint, name)
		if err != nil {
			return "", nil, status.Errorf(codes.Internal, "lookup container: %v", err)
		}
		if rec == nil {
			return "", nil, status.Errorf(codes.NotFound, "container %q not found on host %q", name, hostHint)
		}
		return rec.HostName, rec, nil
	}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "list containers: %v", err)
	}
	for i := range cts {
		if cts[i].Name == name {
			return cts[i].HostName, &cts[i], nil
		}
	}
	return "", nil, status.Errorf(codes.NotFound, "container %q not found in cluster", name)
}
