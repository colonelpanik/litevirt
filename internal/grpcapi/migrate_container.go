package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
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
	// Refuse if the target already owns a container of this name. Fail CLOSED on a
	// read error — we must not migrate onto a name we couldn't prove is free.
	if existing, gerr := corrosion.GetContainer(ctx, s.db, req.TargetHost, req.Name); gerr != nil {
		return status.Errorf(codes.Internal, "check target container: %v", gerr)
	} else if existing != nil {
		return status.Errorf(codes.AlreadyExists,
			"container %q already exists on target host %q", req.Name, req.TargetHost)
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	// Resolve+authorize the repo on the source; forward the ORIGINAL req.RepoPath
	// to the target so a registered name resolves in the target's own config.
	repoPath, err := s.resolveBackupRepoPath(ctx, req.RepoPath)
	if err != nil {
		return err
	}
	repo, err := pbsstore.Open(repoPath)
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
	// srcIfaces is the source's managed NIC set (read once, before the handoff): it
	// names the IPs that must be source-owned before the transfer and target-owned
	// after — and source-owned again if we roll back.
	var srcIfaces []corrosion.ContainerInterfaceRecord
	// leasesOnTarget tracks whether the IPAM leases have been handed to the target
	// (done BEFORE the restore so the target owns its IPs before it can run). On
	// rollback the leases must be handed BACK to the source — it's the source
	// container we restart, and it must own its IPs again.
	leasesOnTarget := false
	// rollback restores the source to its pre-migration state on any failure
	// before the owner is re-keyed — the container never goes missing.
	rollback := func(reason error) error {
		if leasesOnTarget {
			// Hand the leases back and PROVE the source owns every managed IP again
			// before we dare restart it — restarting with an IP it no longer owns is
			// exactly the conflict we're guarding against. An incomplete hand-back
			// parks the source stopped + operator-stop (the reconciler's guaranteed-
			// stick marker, so it isn't auto-restarted without IPAM ownership) and
			// surfaces an explicit "manual repair" error instead of running it.
			moved, terr := network.TransferContainerLeases(ctx, s.db, req.TargetHost, source, req.Name)
			ownsAll := false
			if terr == nil {
				ownsAll, _ = network.ContainerLeasesOwnedBy(ctx, s.db, source, req.Name, srcIfaces)
			}
			if terr != nil || !ownsAll {
				slog.Error("container migrate: rollback lease hand-back INCOMPLETE — leaving source stopped",
					"name", req.Name, "moved", moved, "ownsAll", ownsAll, "error", terr)
				_ = corrosion.SetContainerStateDetail(ctx, s.db, source, req.Name, "stopped", "operator-stop")
				s.audit(ctx, "ct.migrate", req.Name, "project="+project+" rollback IPAM hand-back incomplete: "+reason.Error(), "error")
				_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_FAILED, Error: reason.Error()})
				return status.Errorf(codes.Internal,
					"migrate %s: %v (ROLLBACK INCOMPLETE — source left stopped, manual IPAM repair needed)", req.Name, reason)
			}
			leasesOnTarget = false
		}
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

	// Hand the managed IPAM leases to the target BEFORE the restore: the target
	// keeps the imported IPs (it does not re-reserve a verified migrate), so it must
	// already OWN every managed IP before it can start the container. The handoff is
	// MANDATORY and verified per-NIC, derived from the source's managed interface
	// rows (the IPs the restored container will actually assert) — NOT from a lease
	// count, which can't see a NIC whose IP lost (or never had) a backing lease.
	srcIfaces, err = corrosion.GetContainerInterfaces(ctx, s.db, source, req.Name)
	if err != nil {
		return rollback(fmt.Errorf("read source NIC rows: %w", err))
	}
	// Precondition: the source must cleanly own EVERY managed non-empty IP. If a NIC
	// names an IP no source lease backs (stale spec, lost/stolen lease), migrating
	// would hand the target an address it can't own — refuse rather than create a
	// conflict on the far side.
	if ownsAll, oerr := network.ContainerLeasesOwnedBy(ctx, s.db, source, req.Name, srcIfaces); oerr != nil {
		return rollback(fmt.Errorf("verify source NIC ownership: %w", oerr))
	} else if !ownsAll {
		return rollback(fmt.Errorf("source does not own every managed NIC IP — refusing to migrate (recreate its NICs first)"))
	}
	if _, terr := network.TransferContainerLeases(ctx, s.db, source, req.TargetHost, req.Name); terr != nil {
		return rollback(fmt.Errorf("transfer IPAM leases to target: %w", terr))
	}
	leasesOnTarget = true
	// Postcondition: EVERY managed non-empty IP is now owned by (ct, target, name).
	if ownsAll, oerr := network.ContainerLeasesOwnedBy(ctx, s.db, req.TargetHost, req.Name, srcIfaces); oerr != nil {
		return rollback(fmt.Errorf("verify target NIC ownership: %w", oerr))
	} else if !ownsAll {
		return rollback(fmt.Errorf("IPAM lease handoff incomplete — target does not own every managed NIC IP"))
	}

	_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_RESTORING, Status: "restoring on target"})
	if err := s.migrateRestore(ctx, req.TargetHost, req.RepoPath, req.Name, timestamp, wasRunning); err != nil {
		return rollback(fmt.Errorf("restore on %s: %w", req.TargetHost, err))
	}

	// Re-key: the target's RestoreContainer created the new (target,name) row and
	// already owns the IPAM leases (handed over and verified above). Finalise by
	// removing the source copy — runtime container + soft-deleted cluster row +
	// source interface rows — so exactly one live row survives the window. Past this
	// point the migration has succeeded; cleanup failures are logged, not fatal, and
	// the leases must NOT be handed back (the target owns them now).
	leasesOnTarget = false
	_ = send(&pb.MigrateContainerProgress{Phase: pb.MigrateContainerProgress_FINALIZING, Status: "removing source copy"})
	if err := s.containerRuntime.DeleteContainer(ctx, req.Name); err != nil {
		slog.Warn("container migrate: source runtime cleanup failed", "name", req.Name, "error", err)
	}
	if err := corrosion.DeleteContainer(ctx, s.db, source, req.Name); err != nil {
		slog.Warn("container migrate: source row soft-delete failed", "name", req.Name, "error", err)
	}
	if err := corrosion.DeleteContainerInterfaces(ctx, s.db, source, req.Name); err != nil {
		slog.Warn("container migrate: source interface-row cleanup failed", "name", req.Name, "error", err)
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
	// Tell the target this is a migrate FROM us, so it keeps the imported NIC IPs
	// (we transfer the IPAM leases explicitly in finalize) rather than re-reserving
	// and blanking them.
	mctx := metadata.AppendToOutgoingContext(ctx, migrateFromMDKey, s.hostName)
	rs, err := c.RestoreContainer(mctx, &pb.RestoreContainerRequest{
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
