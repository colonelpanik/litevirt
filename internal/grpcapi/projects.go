// tenancy — gRPC handlers + admission helpers.

package grpcapi

import (
	"context"
	"net"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

func (s *Server) CreateProject(ctx context.Context, req *pb.CreateProjectRequest) (*pb.Project, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// Validate the (hierarchical) name + parent reject a traversal/bad segment.
	// The name is stored as given (the project identity used by VM/ct rows and
	// quota lookups is the raw string); RBAC paths are canonicalized separately
	// by projectRBACBase, so "/acme" and "acme" resolve to the same auth path.
	if _, err := safename.CanonicalProjectName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.ParentName != "" {
		if _, err := safename.CanonicalProjectName(req.ParentName); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parent: %v", err)
		}
	}
	rec := corrosion.ProjectRecord{
		Name:       req.Name,
		Display:    req.Display,
		ParentName: req.ParentName,
	}
	if err := corrosion.InsertProject(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "create project: %v", err)
	}
	got, err := corrosion.GetProject(ctx, s.db, req.Name)
	if err != nil || got == nil {
		return nil, status.Errorf(codes.Internal, "read back project: %v", err)
	}
	s.audit(ctx, "project.create", req.Name, "", "ok")
	return projectToPB(got), nil
}

func (s *Server) ListProjects(ctx context.Context, _ *emptypb.Empty) (*pb.ListProjectsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	all, err := corrosion.ListProjects(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list projects: %v", err)
	}
	resp := &pb.ListProjectsResponse{}
	for _, p := range all {
		resp.Projects = append(resp.Projects, projectToPB(&p))
	}
	return resp, nil
}

func (s *Server) GetProject(ctx context.Context, req *pb.GetProjectRequest) (*pb.Project, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	p, err := corrosion.GetProject(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get project: %v", err)
	}
	if p == nil {
		return nil, status.Errorf(codes.NotFound, "project %q not found", req.Name)
	}
	return projectToPB(p), nil
}

func (s *Server) DeleteProject(ctx context.Context, req *pb.DeleteProjectRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteProject(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	s.audit(ctx, "project.delete", req.Name, "", "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) SetProjectQuota(ctx context.Context, req *pb.SetProjectQuotaRequest) (*pb.ProjectQuota, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Quota == nil || req.Quota.ProjectName == "" {
		return nil, status.Error(codes.InvalidArgument, "quota.project_name required")
	}
	if _, err := safename.CanonicalProjectName(req.Quota.ProjectName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	q := corrosion.ProjectQuotaRecord{
		ProjectName:    req.Quota.ProjectName,
		VCPULimit:      int(req.Quota.VcpuLimit),
		MemMiBLimit:    int(req.Quota.MemMibLimit),
		DiskGiBLimit:   int(req.Quota.DiskGibLimit),
		NICLimit:       int(req.Quota.NicLimit),
		PublicIPLimit:  int(req.Quota.PublicIpLimit),
		BackupGiBLimit: int(req.Quota.BackupGibLimit),
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, q); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert quota: %v", err)
	}
	s.audit(ctx, "project.quota.set", q.ProjectName, "", "ok")
	return quotaToPB(&q), nil
}

func (s *Server) GetProjectQuota(ctx context.Context, req *pb.GetProjectQuotaRequest) (*pb.ProjectQuota, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	q, err := corrosion.GetProjectQuota(ctx, s.db, req.ProjectName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get quota: %v", err)
	}
	if q == nil {
		// Unbounded — return zeros + the project name.
		return &pb.ProjectQuota{ProjectName: req.ProjectName}, nil
	}
	return quotaToPB(q), nil
}

func (s *Server) GetProjectUsage(ctx context.Context, req *pb.GetProjectUsageRequest) (*pb.ProjectUsage, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	u, err := corrosion.SumProjectUsage(ctx, s.db, req.ProjectName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sum usage: %v", err)
	}
	return &pb.ProjectUsage{
		ProjectName:   u.ProjectName,
		VcpuUsed:      int32(u.VCPUUsed),
		MemMibUsed:    int32(u.MemMiBUsed),
		DiskGibUsed:   int32(u.DiskGiBUsed),
		NicUsed:       int32(u.NICUsed),
		VmCount:       int32(u.VMCount),
		PublicIpsUsed: int32(u.PublicIPsUsed),
		BackupGibUsed: int32(u.BackupGiBUsed),
	}, nil
}

func projectToPB(p *corrosion.ProjectRecord) *pb.Project {
	return &pb.Project{
		Name:       p.Name,
		Display:    p.Display,
		ParentName: p.ParentName,
		CreatedAt:  p.CreatedAt,
		UpdatedAt:  p.UpdatedAt,
	}
}

func quotaToPB(q *corrosion.ProjectQuotaRecord) *pb.ProjectQuota {
	return &pb.ProjectQuota{
		ProjectName:    q.ProjectName,
		VcpuLimit:      int32(q.VCPULimit),
		MemMibLimit:    int32(q.MemMiBLimit),
		DiskGibLimit:   int32(q.DiskGiBLimit),
		NicLimit:       int32(q.NICLimit),
		PublicIpLimit:  int32(q.PublicIPLimit),
		BackupGibLimit: int32(q.BackupGiBLimit),
	}
}

// sumDiskGiB totals all disks in the VMSpec in GiB. Used by the
// CreateVM admission path. The DiskSpec carries `size` as a string
// ("30G", "1T", "512M"); we parse the SI suffix and round up so the
// quota is conservative.
//
// Unparseable sizes count as 1 GiB — the operator gets a too-small
// admission bias rather than a free-for-all bypass.
func sumDiskGiB(disks []*pb.DiskSpec) int {
	total := 0
	for _, d := range disks {
		if d == nil {
			continue
		}
		gib := parseDiskGiB(d.Size)
		if gib <= 0 {
			gib = 1
		}
		total += gib
	}
	return total
}

// parseDiskGiB extracts a GiB count from strings like "30G", "1T",
// "512M". Bare integers are interpreted as GiB. Returns 0 on parse
// failure so the caller can apply a conservative default.
func parseDiskGiB(s string) int {
	s = trim(s)
	if s == "" {
		return 0
	}
	mult := 1
	switch s[len(s)-1] {
	case 'T', 't':
		mult = 1024
		s = s[:len(s)-1]
	case 'G', 'g':
		mult = 1
		s = s[:len(s)-1]
	case 'M', 'm':
		// Round small disks up to 1 GiB so 512M doesn't subtract zero.
		return 1
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n * mult
}

// countPublicIPs counts NICs whose declared IP is a non-RFC1918,
// non-link-local IPv4 (or a globally-routable IPv6). The tenancy
// admission engine uses this for the public_ip quota — operators
// who run a hosted network charge per public IP, and we don't want
// a tenant to bypass the cap by claiming a routable address in
// compose without going through the quota.
func countPublicIPs(nics []*pb.NetworkAttachment) int {
	n := 0
	for _, nic := range nics {
		if nic == nil {
			continue
		}
		if isPublicIP(nic.Ip) || isPublicIP(nic.Ipv6) {
			n++
		}
	}
	return n
}

func isPublicIP(addr string) bool {
	if addr == "" {
		return false
	}
	// Drop CIDR suffix if present.
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsUnspecified() {
		return false
	}
	return true
}

func trim(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
