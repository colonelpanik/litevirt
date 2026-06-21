package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReloadFirewall forces the local firewall reconciler to re-read
// security_groups + sg_rules + vm_interfaces and re-render the host's
// nftables ruleset NOW. Returns a snapshot of the post-reconcile
// state so operators can confirm the reload actually fired.
//
// The reconciler still polls every 30s; this RPC is the
// "I just changed a rule and want it live immediately" override.
func (s *Server) ReloadFirewall(ctx context.Context, _ *emptypb.Empty) (*pb.FirewallStatus, error) {
	if err := s.RequirePerm(ctx, "/", "network.update", "operator"); err != nil {
		return nil, err
	}
	if s.fwReconciler == nil {
		return nil, status.Error(codes.Unavailable, "firewall reconciler not wired (test server?)")
	}
	if err := s.fwReconciler.Reconcile(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "reconcile: %v", err)
	}

	// Build the operator-facing summary. Counts come from cluster
	// state directly so we don't depend on the reconciler's internals.
	statusOut := &pb.FirewallStatus{HostName: s.hostName}
	if e := s.fwReconciler.LastError(); e != nil {
		statusOut.LastError = e.Error()
	}
	if t := s.fwReconciler.LastTick(); !t.IsZero() {
		statusOut.LastAppliedAt = t.UTC().Format(time.RFC3339)
	}
	sgs, err := corrosion.ListSecurityGroups(ctx, s.db, "")
	if err == nil {
		statusOut.SecurityGroups = int32(len(sgs))
		for _, sg := range sgs {
			rules, _ := corrosion.ListSGRules(ctx, s.db, sg.ID)
			statusOut.RulesTotal += int32(len(rules))
		}
	}
	ifaces, err := corrosion.ListVMInterfacesByHost(ctx, s.db, s.hostName)
	if err == nil {
		for _, ifc := range ifaces {
			if len(ifc.SecurityGroups) > 0 {
				statusOut.NicsBound++
			}
		}
	}
	return statusOut, nil
}
