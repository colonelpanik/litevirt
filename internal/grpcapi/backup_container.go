package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
// content-addressed manifest into a host-local repo, and indexes the size for
// quota. Containers are host-local, so this runs on the owning host; if the
// container lives elsewhere FailedPrecondition names that host (mirrors
// BackupSnapshot — cross-host streaming is a follow-up).
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
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "backup.create", "operator"); err != nil {
		s.audit(ctx, "ct.backup", req.Name, "project="+project, "denied")
		return err
	}

	// Resolve the owning host and confirm it's us — LXC is host-local.
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return err
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

	repoPath, err := s.resolveBackupRepoPath(ctx, req.RepoPath)
	if err != nil {
		return err
	}
	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open repo %q: %v", req.RepoPath, err)
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

	if err := corrosion.UpsertContainerBackup(ctx, s.db, req.Name, req.RepoPath, manifest.TotalSize); err != nil {
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

// driveRemoteRestore opens RestoreContainer on the target over peer mTLS, drains
// its progress stream, and classifies the result. The authoritative "row
// recorded" signal is the target's restoreRowRecordedStatus frame (or a clean
// DONE/EOF); a definite pre-row status code means nothing was written; anything
// else after the RPC started is indeterminate (the row may have landed but the
// frame/stream was lost) → RestoreUnknown, which the coordinator defers rather
// than destructively falling back.
func (s *Server) driveRemoteRestore(ctx context.Context, target, repoPath, name, timestamp, token string) (corrosion.RestoreOutcome, error) {
	if s.migrateRestoreOverride != nil {
		// Test seam (shared with MigrateContainer): the override returns the
		// classified outcome directly.
		return s.migrateRestoreOverride(ctx, target, repoPath, name, timestamp, true)
	}
	// Carry the attempt token to the target so it stamps the restored row.
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, relocateTokenMDKey, token)
	}
	c, conn, derr := s.peerClient(ctx, target)
	if derr != nil {
		return corrosion.RestoreNotAttempted, fmt.Errorf("dial target: %w", derr)
	}
	defer conn.Close()
	rs, rerr := c.RestoreContainer(ctx, &pb.RestoreContainerRequest{
		RepoPath: repoPath, Name: name, Timestamp: timestamp, HostName: target, Start: true,
	})
	if rerr != nil {
		return corrosion.RestoreNotAttempted, rerr // RPC never established
	}
	return drainRestoreStream(rs)
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
	if req.RepoPath == "" || req.Name == "" || req.Timestamp == "" {
		return status.Error(codes.InvalidArgument, "repo_path, name and timestamp required")
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

	repoPath, err := s.resolveBackupRepoPath(ctx, req.RepoPath)
	if err != nil {
		return err
	}
	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open repo: %v", err)
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
		s.audit(ctx, "ct.restore", req.Name, "project="+project, "error")
		return status.Errorf(codes.Internal, "restore: record cluster state: %v", err)
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
		_ = corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Name, "running", "")
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
