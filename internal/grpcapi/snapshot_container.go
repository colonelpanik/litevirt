package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// containerSnapshotDir is the per-host subdir of dataDir holding container
// snapshot tars: {dataDir}/ct-snapshots/<container>/<snapshot>.tar.
const containerSnapshotDir = "ct-snapshots"

func ctSnapshotPath(dataDir, ctName, snap string) string {
	return filepath.Join(dataDir, containerSnapshotDir, ctName, snap+".tar")
}

// SnapshotContainer takes a point-in-time snapshot of a container: freeze (if
// running) → tar the on-disk dir → store host-local under dataDir, recording it
// in container_snapshots. Runs on the owning host (forwards there if the
// container lives elsewhere, mirroring VM CreateSnapshot).
func (s *Server) SnapshotContainer(ctx context.Context, req *pb.SnapshotContainerRequest) (*pb.ContainerSnapshot, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Snapshot == "" {
		return nil, status.Error(codes.InvalidArgument, "name and snapshot required")
	}
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "snapshot.create", "operator"); err != nil {
		s.audit(ctx, "ct.snapshot.create", req.Name, "project="+project, "denied")
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward snapshot: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.SnapshotContainer(ctx, req)
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	if existing, _ := corrosion.GetContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "snapshot %q already exists for container %q", req.Snapshot, req.Name)
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	path := ctSnapshotPath(s.dataDir, req.Name, req.Snapshot)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, status.Errorf(codes.Internal, "prepare snapshot dir: %v", err)
	}

	// Quiesce a running container so the tar is a consistent point-in-time;
	// always unfreeze, even on failure.
	if rec.State == "running" {
		if ferr := s.containerRuntime.FreezeContainer(ctx, req.Name); ferr == nil {
			defer func() { _ = s.containerRuntime.UnfreezeContainer(context.Background(), req.Name) }()
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create snapshot file: %v", err)
	}
	exportErr := s.containerRuntime.ExportContainer(ctx, req.Name, f)
	closeErr := f.Close()
	if exportErr != nil || closeErr != nil {
		_ = os.Remove(path)
		s.audit(ctx, "ct.snapshot.create", req.Name, "project="+project, "error")
		if exportErr != nil {
			return nil, status.Errorf(codes.Internal, "snapshot export: %v", exportErr)
		}
		return nil, status.Errorf(codes.Internal, "snapshot close: %v", closeErr)
	}
	var size int64
	if st, serr := os.Stat(path); serr == nil {
		size = st.Size()
	}

	srec := corrosion.ContainerSnapshotRecord{
		CtName: req.Name, HostName: host, Name: req.Snapshot,
		State: "ok", SizeBytes: size, Type: "tar", Path: path,
	}
	if err := corrosion.InsertContainerSnapshot(ctx, s.db, srec); err != nil {
		_ = os.Remove(path)
		return nil, status.Errorf(codes.Internal, "record snapshot: %v", err)
	}
	s.audit(ctx, "ct.snapshot.create", req.Name, fmt.Sprintf("project=%s snapshot=%s", project, req.Snapshot), "ok")
	return &pb.ContainerSnapshot{
		CtName: req.Name, HostName: host, Name: req.Snapshot,
		State: "ok", SizeBytes: size, Type: "tar",
	}, nil
}

// ListContainerSnapshots returns a container's snapshots. Forwards to the
// owning host for an immediately-consistent view.
func (s *Server) ListContainerSnapshots(ctx context.Context, req *pb.ListContainerSnapshotsRequest) (*pb.ListContainerSnapshotsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	host, _, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		if c, conn, derr := s.peerClient(ctx, host); derr == nil {
			defer conn.Close()
			req.HostName = host
			return c.ListContainerSnapshots(ctx, req)
		}
		// Fall through to the local (possibly stale) view if the peer is down.
	}
	snaps, err := corrosion.ListContainerSnapshots(ctx, s.db, host, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list snapshots: %v", err)
	}
	resp := &pb.ListContainerSnapshotsResponse{}
	for _, sn := range snaps {
		resp.Snapshots = append(resp.Snapshots, &pb.ContainerSnapshot{
			Id: sn.ID, CtName: sn.CtName, HostName: sn.HostName, Name: sn.Name,
			State: sn.State, SizeBytes: sn.SizeBytes, Type: sn.Type, CreatedAt: sn.CreatedAt,
		})
	}
	return resp, nil
}

// RevertContainerSnapshot rolls a container back to a snapshot: stop (revert
// replaces the rootfs) → restore the snapshot tar in place → restart if it had
// been running. The runtime's RevertContainer is crash-safe (sets the live dir
// aside and restores it if the extract fails).
func (s *Server) RevertContainerSnapshot(ctx context.Context, req *pb.RevertContainerSnapshotRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Snapshot == "" {
		return nil, status.Error(codes.InvalidArgument, "name and snapshot required")
	}
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "snapshot.restore", "operator"); err != nil {
		s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project, "denied")
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward revert: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.RevertContainerSnapshot(ctx, req)
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	snap, _ := corrosion.GetContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot)
	if snap == nil {
		return nil, status.Errorf(codes.NotFound, "snapshot %q not found for container %q", req.Snapshot, req.Name)
	}

	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()

	f, err := os.Open(snap.Path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open snapshot data (%s): %v", snap.Path, err)
	}
	defer f.Close()

	// Revert replaces the rootfs, so the container must be stopped. Remember
	// whether it was running to bring it back up afterward.
	wasRunning := rec.State == "running"
	if wasRunning {
		if err := s.containerRuntime.StopContainer(ctx, req.Name, 30); err != nil {
			return nil, status.Errorf(codes.Internal, "stop for revert: %v", err)
		}
		if werr := corrosion.SetContainerStateDetail(ctx, s.db, host, req.Name, "stopped", "snapshot-revert"); werr != nil {
			s.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
	}
	if err := s.containerRuntime.RevertContainer(ctx, req.Name, f); err != nil {
		s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "revert: %v", err)
	}
	if wasRunning {
		if err := s.containerRuntime.StartContainer(ctx, req.Name); err != nil {
			s.audit(ctx, "ct.snapshot.revert", req.Name, "project="+project+" (restart failed)", "error")
			return nil, status.Errorf(codes.Internal, "reverted but restart failed: %v", err)
		}
		if werr := corrosion.SetContainerStateDetail(ctx, s.db, host, req.Name, "running", ""); werr != nil {
			s.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
	}
	s.audit(ctx, "ct.snapshot.revert", req.Name, fmt.Sprintf("project=%s snapshot=%s", project, req.Snapshot), "ok")
	return &emptypb.Empty{}, nil
}

// DeleteContainerSnapshot removes a snapshot's tar and tombstones its record.
func (s *Server) DeleteContainerSnapshot(ctx context.Context, req *pb.DeleteContainerSnapshotRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Snapshot == "" {
		return nil, status.Error(codes.InvalidArgument, "name and snapshot required")
	}
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "snapshot.delete", "operator"); err != nil {
		s.audit(ctx, "ct.snapshot.delete", req.Name, "project="+project, "denied")
		return nil, err
	}
	host, _, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward delete: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.DeleteContainerSnapshot(ctx, req)
	}
	snap, _ := corrosion.GetContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot)
	if snap != nil && snap.Path != "" {
		if rmErr := os.Remove(snap.Path); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, status.Errorf(codes.Internal, "remove snapshot file: %v", rmErr)
		}
	}
	if err := corrosion.DeleteContainerSnapshot(ctx, s.db, host, req.Name, req.Snapshot); err != nil {
		return nil, status.Errorf(codes.Internal, "tombstone snapshot: %v", err)
	}
	s.audit(ctx, "ct.snapshot.delete", req.Name, fmt.Sprintf("project=%s snapshot=%s", project, req.Snapshot), "ok")
	return &emptypb.Empty{}, nil
}
