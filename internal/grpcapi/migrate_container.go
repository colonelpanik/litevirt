package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// MigrateContainer cold-migrates a container to another host by reusing the
// backup→restore data path (one tested transport): on the SOURCE host it stops
// the container (cold), archives it into a staging repo, then drives the
// TARGET's RestoreContainer over a peer connection; on success it re-keys the
// owner (the target's restore created the new row) and removes the source copy.
// A failure anywhere before finalisation leaves the container intact on the
// source (restarted if it had been running). repo_path must be reachable from
// both hosts (e.g. an NFS-mounted repo).
//
// Runs on the source host — like BackupContainer, point it at the owning daemon
// (FailedPrecondition names it otherwise). No CRIU / live migration.
func (s *Server) MigrateContainer(req *pb.MigrateContainerRequest, stream grpc.ServerStreamingServer[pb.MigrateContainerProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.Name == "" || req.TargetHost == "" || req.RepoPath == "" {
		return status.Error(codes.InvalidArgument, "name, target_host and repo_path required")
	}
	project := s.containerProject(ctx, req.SourceHost, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "ct.migrate", "operator"); err != nil {
		s.audit(ctx, "ct.migrate", req.Name, "project="+project, "denied")
		return err
	}

	source, rec, err := s.resolveContainerHost(ctx, req.SourceHost, req.Name)
	if err != nil {
		return err
	}
	if source != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"container %q lives on host %q; run migrate against that daemon (set LV_HOST)",
			req.Name, source)
	}
	if req.TargetHost == s.hostName {
		return status.Error(codes.InvalidArgument, "source and target host are identical")
	}
	if s.containerRuntime == nil {
		return status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	// Refuse if the target already owns a container of this name.
	if existing, _ := corrosion.GetContainer(ctx, s.db, req.TargetHost, req.Name); existing != nil {
		return status.Errorf(codes.AlreadyExists,
			"container %q already exists on target host %q", req.Name, req.TargetHost)
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	repo, err := pbsstore.Open(req.RepoPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "open staging repo %q (must be reachable from both hosts): %v", req.RepoPath, err)
	}

	send := func(p *pb.MigrateContainerProgress) error { return stream.Send(p) }
	_ = send(&pb.MigrateContainerProgress{
		Phase:  pb.MigrateContainerProgress_VALIDATING,
		Status: fmt.Sprintf("migrating %s: %s → %s", req.Name, source, req.TargetHost),
	})

	s.audit(ctx, "ct.migrate", req.Name, fmt.Sprintf("project=%s %s→%s", project, source, req.TargetHost), "started")

	// Cold: stop the container before the transfer. Remember whether it was
	// running so we can both bring it up on the target and roll back on failure.
	wasRunning := rec.State == "running"
	if wasRunning {
		_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_STOPPING, Status: "stopping for cold transfer"})
		if err := s.containerRuntime.StopContainer(ctx, req.Name, 30); err != nil {
			s.audit(ctx, "ct.migrate", req.Name, "project="+project, "error")
			return status.Errorf(codes.Internal, "stop for migration: %v", err)
		}
	}
	// rollback restores the source to its pre-migration state on any failure
	// before the owner is re-keyed — the container never goes missing.
	rollback := func(reason error) error {
		if wasRunning {
			if serr := s.containerRuntime.StartContainer(ctx, req.Name); serr != nil {
				slog.Error("container migrate: rollback restart failed", "name", req.Name, "error", serr)
			} else {
				_ = corrosion.SetContainerStateDetail(ctx, s.db, source, req.Name, "running", "")
			}
		}
		s.audit(ctx, "ct.migrate", req.Name, "project="+project+" rolled back: "+reason.Error(), "error")
		_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_FAILED, Error: reason.Error()})
		return status.Errorf(codes.Internal, "migrate %s: %v (rolled back; container intact on %s)", req.Name, reason, source)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_ARCHIVING, Status: "archiving rootfs into staging repo"})
	if _, err := s.archiveContainer(ctx, repo, rec, timestamp, func(p pbsstore.PushProgress) {
		_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_ARCHIVING, BytesProcessed: p.BytesProcessed})
	}); err != nil {
		return rollback(fmt.Errorf("archive: %w", err))
	}

	_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_RESTORING, Status: "restoring on target"})
	if err := s.migrateRestore(ctx, req.TargetHost, req.RepoPath, req.Name, timestamp, wasRunning); err != nil {
		return rollback(fmt.Errorf("restore on %s: %w", req.TargetHost, err))
	}

	// Re-key: the target's RestoreContainer created the new (target,name) row.
	// Finalise by removing the source copy — runtime container + soft-deleted
	// cluster row — so exactly one live row survives the window. Past this point
	// the migration has succeeded; cleanup failures are logged, not fatal.
	_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_FINALIZING, Status: "removing source copy"})
	if err := s.containerRuntime.DeleteContainer(ctx, req.Name); err != nil {
		slog.Warn("container migrate: source runtime cleanup failed", "name", req.Name, "error", err)
	}
	if err := corrosion.DeleteContainer(ctx, s.db, source, req.Name); err != nil {
		slog.Warn("container migrate: source row soft-delete failed", "name", req.Name, "error", err)
	}
	_ = corrosion.DeleteContainerRestartState(ctx, s.db, source, req.Name)

	s.audit(ctx, "ct.migrate", req.Name, fmt.Sprintf("project=%s %s→%s", project, source, req.TargetHost), "ok")
	return send(&pb.MigrateContainerProgress{
		Phase:  pb.MigrateContainerProgress_DONE,
		Status: fmt.Sprintf("migrated to %s", req.TargetHost),
	})
}

// migrateRestore drives the target host's RestoreContainer over a peer
// connection (daemon-to-daemon mTLS authenticates as admin). The test seam
// replaces it so the success path is unit-testable without a second daemon.
func (s *Server) migrateRestore(ctx context.Context, target, repoPath, name, timestamp string, start bool) error {
	if s.migrateRestoreOverride != nil {
		return s.migrateRestoreOverride(ctx, target, repoPath, name, timestamp, start)
	}
	c, conn, err := s.peerClient(ctx, target)
	if err != nil {
		return fmt.Errorf("dial target: %w", err)
	}
	defer conn.Close()
	rs, err := c.RestoreContainer(ctx, &pb.RestoreContainerRequest{
		RepoPath: repoPath, Name: name, Timestamp: timestamp, HostName: target, Start: start,
	})
	if err != nil {
		return err
	}
	for {
		p, err := rs.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if p.Error != "" {
			return fmt.Errorf("target restore: %s", p.Error)
		}
	}
}
