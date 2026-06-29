package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/safename"
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
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// Validate the name + project BEFORE the permission check (so a path-like
	// name never participates in the auth path) and before they reach the LXC
	// runtime (which builds <lxcpath>/<name>) or the stored row used for RBAC.
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.Project != "" {
		if _, err := safename.CanonicalProjectName(req.Project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(req.Project, req.Name), "ct.create", "operator"); err != nil {
		s.audit(ctx, "ct.create", req.Name, "project="+tenancy.NormalizeProject(req.Project), "denied")
		return nil, err
	}
	if forwarded, err := s.forwardCreateContainer(ctx, req); err != nil || forwarded != nil {
		return forwarded, err
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}

	// Serialize same-name creates on this host, and reject a duplicate BEFORE
	// allocating any IPAM lease. Without this, a duplicate / concurrent create that
	// later fails would run the lease-cleanup path (keyed on host+name) and tombstone
	// the EXISTING container's leases + interface rows. The lock + preflight make the
	// failure cleanup safe (this is the only live container of this name on the host).
	unlock := s.lockVM("ct/" + req.Name)
	defer unlock()
	// Fail CLOSED on a read error: if we can't prove the name is free, a later
	// cleanup keyed on (host, name) could release an existing container's managed
	// NIC state — so never proceed to allocate leases / touch the runtime on a
	// read we couldn't complete.
	existing, gerr := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if gerr != nil {
		return nil, status.Errorf(codes.Internal, "check existing container: %v", gerr)
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "container %q already exists on host %q", req.Name, s.hostName)
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

	// Resolve the requested NICs into runtime attachments + managed-interface rows
	// + create-spec intent, ALLOCATING each managed NIC's IPAM lease as it goes
	// (managed network vs legacy raw bridge). On any later failure we release this
	// container's leases (s.releaseContainerNICs) to undo partial allocation.
	plan, err := s.resolveContainerNICs(ctx, req.Name, req.Networks)
	if err != nil {
		_ = s.releaseContainerNICs(ctx, req.Name) // undo any leases taken before the error
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		return nil, err
	}
	info, err := s.containerRuntime.CreateContainer(ctx, CreateContainerOpts{
		Name: req.Name, Template: req.Template,
		Distro: req.Distro, Release: req.Release, Arch: req.Arch,
		CPULimit: int(req.Cpu), MemoryMiB: int(req.MemoryMib),
		Networks: plan.lxcNics, Labels: req.Labels,
	})
	if err != nil {
		_ = s.releaseContainerNICs(ctx, req.Name)
		s.audit(ctx, "ct.create", req.Name, "image="+req.Image, "error")
		return nil, status.Errorf(codes.Internal, "create: %v", err)
	}

	// Persist the create-time intent (incl. networking) so host-loss relocation /
	// restore can rebuild this container faithfully, not as a bare image recreate.
	createSpec := corrosion.ContainerCreateSpec{
		Template: req.Template, Distro: req.Distro, Release: req.Release, Arch: req.Arch,
		Networks: plan.specNets,
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: info.Name,
		State: info.State, Image: chooseImage(req.Image, info.Image),
		CPULimit: int(req.Cpu), MemMiB: int(req.MemoryMib),
		Labels: req.Labels, RestartPolicy: encodeRestartPolicy(req.Restart),
		Project:       req.Project, // UpsertContainer normalizes "" → "_default"
		OnHostFailure: req.OnHostFailure,
		CreateSpec:    corrosion.EncodeCreateSpec(createSpec),
		CreatedAt:     now,
	}
	// Write the container row + managed interface rows in ONE atomic batch. Fail
	// closed: the runtime container exists but the DB write failed → delete the
	// just-created container and release its leases, so no partial tracked state
	// and no leaked lease.
	if err := corrosion.CreateContainerAtomic(ctx, s.db, rec, plan.ifaces); err != nil {
		_ = s.releaseContainerNICs(ctx, info.Name)
		if delErr := s.containerRuntime.DeleteContainer(ctx, info.Name); delErr != nil {
			slog.Warn("container create: cleanup after cluster-state-write failure also failed",
				"name", info.Name, "error", delErr)
		}
		s.audit(ctx, "ct.create", info.Name, "image="+rec.Image, "error")
		return nil, status.Errorf(codes.Internal, "create: record cluster state: %v", err)
	}
	s.audit(ctx, "ct.create", info.Name, "project="+tenancy.NormalizeProject(req.Project)+" image="+rec.Image, "ok")
	slog.Info("container created", "name", info.Name, "host", s.hostName)
	return toPbContainer(rec), nil
}

func (s *Server) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
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
	// Preflight the cluster row BEFORE touching the runtime: a missing/soft-deleted
	// row means we'd start an UNTRACKED container, so refuse. (Also folds in the
	// template check — a frozen clone source can't be started.)
	rec, err := corrosion.GetContainer(ctx, s.db, s.hostName, req.Name)
	if err != nil {
		// A state-read failure is not the same as "not found" — surface it as
		// Internal rather than masking a storage problem behind FailedPrecondition.
		return nil, status.Errorf(codes.Internal, "start: read container row: %v", err)
	}
	if rec == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "container %q not found on host %q", req.Name, s.hostName)
	}
	if rec.IsTemplate {
		return nil, status.Errorf(codes.FailedPrecondition, "%q is a template and cannot be started; clone it instead", req.Name)
	}
	if err := s.containerRuntime.StartContainer(ctx, req.Name); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "start: %v", err)
	}
	// Clear any prior stop intent ('operator-stop') so a later unexpected stop is
	// judged fresh. Strict: if the row vanished mid-flight the container is now
	// untracked → stop it and error; a transient DB error leaves it running + errors.
	if err := corrosion.SetContainerStateDetailStrict(ctx, s.db, s.hostName, req.Name, "running", ""); err != nil {
		s.audit(ctx, "ct.start", req.Name, "project="+project, "error")
		if errors.Is(err, corrosion.ErrNoRowsAffected) {
			if stopErr := s.containerRuntime.StopContainer(ctx, req.Name, 0); stopErr != nil {
				slog.Warn("container start: failed to stop now-untracked container after its row vanished",
					"name", req.Name, "error", stopErr)
			}
			return nil, status.Errorf(codes.FailedPrecondition, "container %q row vanished during start; stopped to avoid an untracked container", req.Name)
		}
		return nil, status.Errorf(codes.Internal, "start: clear stop intent: %v", err)
	}
	s.audit(ctx, "ct.start", req.Name, "project="+project, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
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
	// Record operator intent so the container reconciler leaves it stopped (the
	// container analogue of StopVM's vms.state_detail='operator-stop'). Strict:
	// this marker is load-bearing — without it the reconciler auto-restarts the
	// container — so a missing-row / failed write must surface, not silently pass.
	if err := corrosion.SetContainerStateDetailStrict(ctx, s.db, s.hostName, req.Name, "stopped", "operator-stop"); err != nil {
		s.audit(ctx, "ct.stop", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "stop: record operator-stop intent: %v", err)
	}
	s.audit(ctx, "ct.stop", req.Name, "project="+project, "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) DeleteContainer(ctx context.Context, req *pb.DeleteContainerRequest) (*emptypb.Empty, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
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
	// A runtime "not found" is acceptable (idempotent) — proceed to the row
	// tombstone so a retry after "runtime gone but DB write failed" can clear the
	// ghost row. A real runtime failure still aborts.
	if err := s.containerRuntime.DeleteContainer(ctx, req.Name); err != nil && !errors.Is(err, lxc.ErrContainerNotFound) {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	// Mandatory tombstone: a ghost (stale-live) row skews quota + makes failover
	// chase a container that no longer exists. Delete is intentionally IDEMPOTENT
	// (the documented exception to the strict "zero-row = failure" rule that
	// governs start/stop): retry-safety matters for the failover/relocation paths
	// that re-issue deletes. So an already-gone row (ErrNoRowsAffected) is a
	// success — but audited distinctly (not a silent "ok") so an operator typo
	// isn't invisible; only a REAL DB error surfaces as Internal.
	derr := corrosion.DeleteContainerStrict(ctx, s.db, s.hostName, req.Name)
	if derr != nil && !errors.Is(derr, corrosion.ErrNoRowsAffected) {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: remove cluster row: %v", derr)
	}
	// Cascade the managed network state (IPAM leases + container_interfaces rows)
	// and clear restart state, on BOTH the normal and already-absent paths — a
	// prior delete may have tombstoned the container row but failed these, so a
	// retry (now zero-row) must still clean them up, else a later same-host/name
	// recreate inherits stale leases/rows.
	nicErr := s.releaseContainerNICs(ctx, req.Name)
	if err := corrosion.DeleteContainerRestartState(ctx, s.db, s.hostName, req.Name); err != nil {
		slog.Warn("container delete: failed to clear restart state (harmless, GC'able)", "name", req.Name, "error", err)
	}
	// The managed-NIC cascade is part of the CT network invariant: a stale lease or
	// interface row would be inherited by a later same-host/same-name recreate —
	// which makes the name live again and so hides the orphan from the lease GC.
	// Surface a cascade failure so the caller retries; the whole delete is
	// idempotent (runtime not-found OK, row tombstone zero-row OK, cascade re-runs).
	if nicErr != nil {
		s.audit(ctx, "ct.delete", req.Name, "project="+project, "error")
		return nil, status.Errorf(codes.Internal, "delete: release managed NICs: %v", nicErr)
	}
	if errors.Is(derr, corrosion.ErrNoRowsAffected) {
		// Idempotent: the row was already gone. Audited distinctly, not a silent "ok".
		s.audit(ctx, "ct.delete", req.Name, "project="+project+" already-absent", "ok")
		slog.Info("container delete: cluster row already absent (idempotent no-op)", "name", req.Name, "host", s.hostName)
		return &emptypb.Empty{}, nil
	}
	s.audit(ctx, "ct.delete", req.Name, "project="+project, "ok")
	slog.Info("container deleted", "name", req.Name, "host", s.hostName)
	return &emptypb.Empty{}, nil
}

func (s *Server) ExecContainer(ctx context.Context, req *pb.ExecContainerRequest) (*pb.ExecContainerResponse, error) {
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
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
	// Dest is where umoci unpacks the (untrusted) image rootfs as root, and a
	// local oci: source is read as root — both are host-path primitives. A bare
	// Dest name is contained under the daemon OCI staging dir; an absolute Dest
	// or a local oci: source requires admin (remote docker:// registry pulls
	// stay operator). The check binds the real caller on the entry node; a
	// forwarded peer call runs as admin (daemon mTLS) so it isn't re-denied.
	if lxc.RegistryHost(req.Image) == "" {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, status.Error(codes.PermissionDenied,
				"pulling from a local OCI source path requires the admin role")
		}
	}
	if filepath.IsAbs(req.Dest) {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, status.Error(codes.PermissionDenied,
				"an absolute --dest requires the admin role; use a bare name to stage under the daemon OCI directory")
		}
	} else if req.Dest != "" {
		// A bare Dest must be a single safe name (no nested path); it is resolved
		// to a staging path on the host that actually unpacks it (below, after the
		// forward), so the raw name — not the entry host's dataDir path — crosses
		// the wire.
		if err := safename.ValidateName(req.Dest); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid --dest (use a bare name): %v", err)
		}
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
	// Resolve a bare Dest name to a staging path on THIS (the unpacking) host,
	// so it lands under this host's OCI dir regardless of where the request
	// entered the cluster.
	if req.Dest != "" && !filepath.IsAbs(req.Dest) {
		resolved, err := safename.SafeJoin(filepath.Join(s.dataDir, "oci"), req.Dest)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid --dest: %v", err)
		}
		req.Dest = resolved
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
