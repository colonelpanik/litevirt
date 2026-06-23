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
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
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
}

// containerBackupDisk is the manifest "disk" name for a container — a container
// has one logical volume, its rootfs.
const containerBackupDisk = "rootfs"

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

	repo, err := pbsstore.Open(req.RepoPath)
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

// archiveContainer streams a container's whole on-disk directory (rootfs + LXC
// config) into repo as a full, content-addressed manifest, embedding its spec
// so a restore is self-contained. The caller holds the ct lock and has already
// quiesced the container (frozen for a live backup, or stopped for migration).
// Shared by BackupContainer and MigrateContainer — one tested data path.
func (s *Server) archiveContainer(ctx context.Context, repo *pbsstore.Repo, rec *corrosion.ContainerRecord, timestamp string, progress func(pbsstore.PushProgress)) (*pbsstore.Manifest, error) {
	specJSON, _ := json.Marshal(containerBackupSpec{
		Name: rec.Name, Image: rec.Image, CPULimit: rec.CPULimit, MemMiB: rec.MemMiB,
		Labels: rec.Labels, RestartPolicy: rec.RestartPolicy, Project: rec.Project,
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
	// Restore may target a name that no longer exists (disaster recovery); the
	// project comes from the existing row if present, else from the manifest.
	project := s.containerProject(ctx, "", req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "backup.restore", "operator"); err != nil {
		s.audit(ctx, "ct.restore", req.Name, "project="+project, "denied")
		return err
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

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	// Refuse to clobber a live container of the same name on this host.
	if existing, _ := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name); existing != nil {
		return status.Errorf(codes.AlreadyExists,
			"container %q already exists on host %q; delete it first or restore under a different name",
			req.Name, s.hostName)
	}

	repo, err := pbsstore.Open(req.RepoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open repo: %v", err)
	}
	manifest, err := repo.GetManifest(req.Name, req.Timestamp, containerBackupDisk)
	if err != nil {
		return status.Errorf(codes.NotFound, "manifest: %v", err)
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

	// Recreate the cluster row from the embedded spec.
	spec := containerBackupSpec{Name: req.Name, Project: project}
	if manifest.ContainerSpecJSON != "" {
		_ = json.Unmarshal([]byte(manifest.ContainerSpecJSON), &spec)
	}
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: req.Name, State: "stopped",
		Image: spec.Image, CPULimit: spec.CPULimit, MemMiB: spec.MemMiB,
		Labels: spec.Labels, RestartPolicy: spec.RestartPolicy,
		Project: tenancy.NormalizeProject(spec.Project),
	}
	if err := corrosion.UpsertContainer(ctx, s.db, rec); err != nil {
		slog.Warn("container restore: cluster row write failed", "name", req.Name, "error", err)
	}

	if req.Start {
		if err := s.containerRuntime.StartContainer(ctx, req.Name); err != nil {
			s.audit(ctx, "ct.restore", req.Name, "project="+project+" (start failed)", "error")
			return status.Errorf(codes.Internal, "restored but start failed: %v", err)
		}
		_ = corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Name, "running", "")
	}

	s.audit(ctx, "ct.restore", req.Name, fmt.Sprintf("project=%s from %s @ %s", spec.Project, req.RepoPath, req.Timestamp), "ok")
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
