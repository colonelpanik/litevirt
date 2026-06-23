package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Containers gRPC service.
//
// Routing model:
//   - Every request carries a host_name. If empty or matches s.hostName,
//     the local containerRuntime executes.
//   - Otherwise the call forwards to the named host via peerClient
//     (existing pattern in server.go).
//   - Cluster-state side-effects (containers table) are written by
//     the host that performed the action so the row reflects truth.

// CreateContainer creates an LXC/OCI container on the named host.
// containerProject resolves a container's tenancy project for RBAC/audit,
// defaulting to "_default" when the row isn't found yet. When host is empty it
// scans by name (lifecycle RPCs usually carry the owning host).
func (s *Server) containerProject(ctx context.Context, host, name string) string {
	if host != "" {
		if ct, _ := corrosion.GetContainer(ctx, s.db, host, name); ct != nil && ct.Project != "" {
			return ct.Project
		}
		return "_default"
	}
	cts, _ := corrosion.ListContainers(ctx, s.db, "")
	for _, ct := range cts {
		if ct.Name == name && ct.Project != "" {
			return ct.Project
		}
	}
	return "_default"
}

func (s *Server) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.Container, error) {
	if err := s.RequirePerm(ctx, ctRBACPathFor(req.Project, req.Name), "ct.create", "operator"); err != nil {
		s.audit(ctx, "ct.create", req.Name, "project="+tenancy.NormalizeProject(req.Project), "denied")
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	if forwarded, err := s.forwardCreateContainer(ctx, req); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}

	// Tenancy admission — containers draw down the SAME project vCPU/Mem budget
	// as VMs (mirrors CreateVM). Runs on the owning host (post-forward) so the
	// check happens once against the cluster-wide usage view.
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, tenancy.NormalizeProject(req.Project),
			tenancy.QuotaRequest{VCPU: int(req.Cpu), MemMiB: int(req.MemoryMib)}); err != nil {
			return nil, status.Errorf(codes.ResourceExhausted, "%v", err)
		}
	}

	nics := make([]ContainerNICOpt, 0, len(req.Networks))
	for _, n := range req.Networks {
		nics = append(nics, ContainerNICOpt{Name: n.Name, Bridge: n.Bridge, IP: n.Ip, MAC: n.Mac})
	}
	info, err := s.containerRuntime.CreateContainer(ctx, CreateContainerOpts{
		Name: req.Name, Template: req.Template,
		Distro: req.Distro, Release: req.Release, Arch: req.Arch,
		CPULimit: int(req.Cpu), MemoryMiB: int(req.MemoryMib),
		Networks: nics, Labels: req.Labels,
	})
	if err != nil {
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		return nil, status.Errorf(codes.Internal, "create: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: info.Name,
		State: info.State, Image: chooseImage(req.Image, info.Image),
		CPULimit: int(req.Cpu), MemMiB: int(req.MemoryMib),
		Labels: req.Labels, RestartPolicy: encodeRestartPolicy(req.Restart),
		Project:   req.Project, // UpsertContainer normalizes "" → "_default"
		CreatedAt: now,
	}
	if err := corrosion.UpsertContainer(ctx, s.db, rec); err != nil {
		// Container exists in LXC but not in cluster state — log; the
		// next List will repopulate via ContainerRuntime.ListContainers.
		slog.Warn("container created but cluster row write failed",
			"name", info.Name, "error", err)
	}
	s.audit(ctx, "ct.create", info.Name, "project="+tenancy.NormalizeProject(req.Project)+" image="+rec.Image, "ok")
	slog.Info("container created", "name", info.Name, "host", s.hostName)
	return toPbContainer(rec), nil
}

func (s *Server) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*emptypb.Empty, error) {
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "ct.start", "operator"); err != nil {
		return nil, err
	}
	if forwarded, err := s.forwardSimpleCT(ctx, req.HostName, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.StartContainer(ctx, req)
	}); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	if err := s.containerRuntime.StartContainer(ctx, req.Name); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "start: %v", err)
	}
	// Clear any prior stop intent (e.g. 'operator-stop') so a subsequent
	// unexpected stop is correctly treated as unexpected by the reconciler.
	_ = corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Name, "running", "")
	s.audit(ctx, "ct.start", req.Name, "project="+project, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*emptypb.Empty, error) {
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "ct.stop", "operator"); err != nil {
		return nil, err
	}
	if forwarded, err := s.forwardSimpleCT(ctx, req.HostName, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.StopContainer(ctx, req)
	}); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	if err := s.containerRuntime.StopContainer(ctx, req.Name, int(req.TimeoutSec)); err != nil {
		s.audit(ctx, "ct.stop", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "stop: %v", err)
	}
	// Record operator intent so the container reconciler leaves it stopped
	// (the container analogue of StopVM writing vms.state_detail='operator-stop').
	_ = corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Name, "stopped", "operator-stop")
	s.audit(ctx, "ct.stop", req.Name, "project="+project, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) DeleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*emptypb.Empty, error) {
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "ct.delete", "operator"); err != nil {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "denied")
		return nil, err
	}
	if forwarded, err := s.forwardSimpleCT(ctx, req.HostName, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.DeleteContainer(ctx, req)
	}); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	if err := s.containerRuntime.DeleteContainer(ctx, req.Name); err != nil {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, s.hostName, req.Name)
	_ = corrosion.DeleteContainerRestartState(ctx, s.db, s.hostName, req.Name)
	s.audit(ctx, "ct.delete", req.Name, "project="+project, "ok")
	slog.Info("container deleted", "name", req.Name, "host", s.hostName)
	return &emptypb.Empty{}, nil
}

func (s *Server) ExecContainer(ctx context.Context, req *pb.ExecContainerRequest) (*pb.ExecContainerResponse, error) {
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "ct.exec", "operator"); err != nil {
		s.audit(ctx, "ct.exec", req.Name, "permission denied: "+strings.Join(req.Argv, " "), "denied")
		return nil, err
	}
	if req.HostName != "" && req.HostName != s.hostName {
		c, conn, err := s.peerClient(ctx, req.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward exec: %v", err)
		}
		defer conn.Close()
		return c.ExecContainer(ctx, req)
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	res, err := s.containerRuntime.ExecContainer(ctx, req.Name, req.Argv)
	if err != nil {
		s.audit(ctx, "ct.exec", req.Name, strings.Join(req.Argv, " "), "error")
		return nil, status.Errorf(codes.Internal, "exec: %v", err)
	}
	s.audit(ctx, "ct.exec", req.Name, strings.Join(req.Argv, " "), "ok")
	return &pb.ExecContainerResponse{
		Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: int32(res.ExitCode),
	}, nil
}

// ListContainers returns containers across the cluster (or just one
// host when host_name is set). Reads from the containers table —
// authoritative since each host upserts on every lifecycle change.
func (s *Server) ListContainers(ctx context.Context, req *pb.ListContainersRequest) (*pb.ListContainersResponse, error) {
	if err := s.RequirePerm(ctx, "/", "ct.read", "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListContainers(ctx, s.db, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	resp := &pb.ListContainersResponse{}
	for _, r := range rows {
		resp.Containers = append(resp.Containers, toPbContainer(r))
	}
	return resp, nil
}

func (s *Server) PullOCIImage(ctx context.Context, req *pb.PullOCIImageRequest) (*emptypb.Empty, error) {
	if err := s.RequirePerm(ctx, "/", "image.pull", "operator"); err != nil {
		return nil, err
	}
	// Resolve registry credentials on the ENTRY node — only here is
	// callerUsername(ctx) meaningful (a forwarded peer runs under the daemon's
	// mTLS identity). Skip if the request already carries inline creds (ad-hoc
	// `lv ct pull --username`, or a secret an entry node already resolved and
	// forwarded) or the image is a local oci: layout (RegistryHost == "").
	if req.Username == "" && req.Password == "" && s.db != nil {
		if reg := lxc.RegistryHost(req.Image); reg != "" {
			if rc, err := corrosion.ResolveRegistryCredential(ctx, s.db, callerUsername(ctx), reg); err != nil {
				slog.Warn("registry credential resolve failed; pulling anonymously",
					"registry", reg, "error", err)
			} else if rc != nil {
				req.Username, req.Password = rc.Username, rc.Secret
			}
		}
	}
	// Forward AFTER resolution so req carries the resolved secret to the host
	// that actually runs skopeo (it cannot resolve per-user creds itself).
	if forwarded, err := s.forwardSimpleCT(ctx, req.HostName, func(c pb.LiteVirtClient) (*emptypb.Empty, error) {
		return c.PullOCIImage(ctx, req)
	}); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired")
	}
	if err := s.containerRuntime.PullOCIImage(ctx, req.Image, req.Dest, req.Tag, req.Username, req.Password); err != nil {
		return nil, status.Errorf(codes.Internal, "pull oci: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// ── helpers ──

// forwardCreateContainer routes the request to the owning host when
// host_name names a remote. Returns (resp, err) — both nil means
// "execute locally".
func (s *Server) forwardCreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*pb.Container, error) {
	if req.HostName == "" || req.HostName == s.hostName {
		return nil, nil
	}
	c, conn, err := s.peerClient(ctx, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "forward create: %v", err)
	}
	defer conn.Close()
	return c.CreateContainer(ctx, req)
}

// forwardSimpleCT is the empty-result version: returns (resp, err)
// where (nil, nil) means "execute locally" so the caller proceeds.
func (s *Server) forwardSimpleCT(
	ctx context.Context, hostName string,
	dial func(pb.LiteVirtClient) (*emptypb.Empty, error),
) (*emptypb.Empty, error) {
	if hostName == "" || hostName == s.hostName {
		return nil, nil
	}
	c, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "forward: %v", err)
	}
	defer conn.Close()
	return dial(c)
}

func toPbContainer(r corrosion.ContainerRecord) *pb.Container {
	return &pb.Container{
		HostName: r.HostName, Name: r.Name, State: r.State,
		Image: r.Image, CpuLimit: int32(r.CPULimit), MemoryMib: int32(r.MemMiB),
		Restart: decodeRestartPolicy(r.RestartPolicy), StateDetail: r.StateDetail,
		Project:   r.Project,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func chooseImage(req, info string) string {
	if req != "" {
		return req
	}
	return info
}

// encodeRestartPolicy serializes a container's restart policy for the
// containers.restart_policy column. A nil or none-condition policy stores an
// empty string so the common (opt-out) case carries no JSON. Round-trips via
// decodeRestartPolicy.
func encodeRestartPolicy(rp *pb.RestartPolicy) string {
	if rp == nil || rp.Condition == "" || rp.Condition == "none" {
		return ""
	}
	b, err := json.Marshal(rp)
	if err != nil {
		return ""
	}
	return string(b)
}

// decodeRestartPolicy parses the stored restart_policy JSON; an empty string (or
// garbage) yields nil (treated as "none").
func decodeRestartPolicy(s string) *pb.RestartPolicy {
	if s == "" {
		return nil
	}
	rp := &pb.RestartPolicy{}
	if err := json.Unmarshal([]byte(s), rp); err != nil {
		return nil
	}
	return rp
}

// keep errors imported in case we add typed-error returns later
var _ = errors.New
