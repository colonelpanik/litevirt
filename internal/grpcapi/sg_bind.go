package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// BindSecurityGroups replaces the SG name list on one VM NIC. The
// firewall reconciler on every host re-renders its ruleset on the
// next 30s tick (or immediately via ReloadFirewall). RBAC: requires
// the network.update verb on the VM's path.
//
// this is the runtime entry point that lets operators
// adjust SG bindings without redeploying a stack — useful for
// incident response (drop a compromised VM into an isolation SG).
func (s *Server) BindSecurityGroups(ctx context.Context, req *pb.BindSecurityGroupsRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" || req.NetworkName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name and network_name required")
	}
	rbacPath := vmRBACPathFor("", req.VmName)
	if vm, gerr := corrosion.GetVM(ctx, s.db, req.VmName); gerr == nil && vm != nil {
		rbacPath = vmRBACPath(vm)
	}
	if err := s.RequirePerm(ctx, rbacPath, "network.update", "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.SetInterfaceSecurityGroups(ctx, s.db,
		req.VmName, req.NetworkName, req.SecurityGroups); err != nil {
		return nil, status.Errorf(codes.Internal, "update binding: %v", err)
	}
	slog.Info("vm-nic security groups updated",
		"vm", req.VmName, "network", req.NetworkName,
		"sgs", req.SecurityGroups, "by", callerUsername(ctx))
	return &emptypb.Empty{}, nil
}
