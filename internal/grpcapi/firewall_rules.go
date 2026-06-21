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

// Distributed-firewall management RPCs for the cluster/host tiers, ip sets, and
// the default-deny policy (v21). The per-NIC tier is managed via the security
// group RPCs + BindSecurityGroups. After a mutation the connected host
// re-reconciles immediately so `lv firewall …` changes are visible at once;
// every other host picks them up on its own 30s reconcile tick.

func toPbFirewallRule(r corrosion.FirewallRule) *pb.FirewallRule {
	return &pb.FirewallRule{
		Id: r.ID, HostName: r.HostName, Direction: r.Direction, Proto: r.Proto,
		Port: r.PortRange, Cidr: r.CIDR, Action: r.Action, Priority: int32(r.Priority),
		Comment: r.Comment, StackName: r.StackName,
	}
}

func toPbIpSet(s corrosion.IPSet) *pb.IpSet {
	return &pb.IpSet{Id: s.ID, Name: s.Name, Cidrs: s.CIDRs, StackName: s.StackName}
}

// reconcileLocal triggers an immediate best-effort re-render on the connected
// host so an operator's change is live without waiting for the poll tick.
func (s *Server) reconcileLocal(ctx context.Context) {
	if s.fwReconciler == nil {
		return
	}
	if err := s.fwReconciler.Reconcile(ctx); err != nil {
		slog.Warn("firewall: immediate reconcile after change failed", "error", err)
	}
}

// ── Cluster-tier rules ──

func (s *Server) CreateClusterFirewallRule(ctx context.Context, req *pb.CreateClusterFirewallRuleRequest) (*pb.FirewallRule, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	r := req.GetRule()
	if r == nil || r.Direction == "" {
		return nil, status.Error(codes.InvalidArgument, "rule with direction required")
	}
	row := corrosion.FirewallRule{
		ID: newID(), Direction: r.Direction, Proto: r.Proto, PortRange: r.Port,
		CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority), Comment: r.Comment,
	}
	if err := corrosion.InsertClusterFirewallRule(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "create cluster rule: %v", err)
	}
	s.audit(ctx, "firewall.cluster-rule.add", row.ID, r.Direction+" "+r.Action, "ok")
	s.reconcileLocal(ctx)
	return toPbFirewallRule(row), nil
}

func (s *Server) ListClusterFirewallRules(ctx context.Context, _ *pb.ListClusterFirewallRulesRequest) (*pb.ListClusterFirewallRulesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rules, err := corrosion.ListClusterFirewallRules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list cluster rules: %v", err)
	}
	resp := &pb.ListClusterFirewallRulesResponse{}
	for _, r := range rules {
		resp.Rules = append(resp.Rules, toPbFirewallRule(r))
	}
	return resp, nil
}

func (s *Server) DeleteClusterFirewallRule(ctx context.Context, req *pb.DeleteClusterFirewallRuleRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteClusterFirewallRule(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete cluster rule: %v", err)
	}
	s.audit(ctx, "firewall.cluster-rule.rm", req.Id, "", "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ── Host-tier rules ──

func (s *Server) CreateHostFirewallRule(ctx context.Context, req *pb.CreateHostFirewallRuleRequest) (*pb.FirewallRule, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	r := req.GetRule()
	if r == nil || r.Direction == "" || r.HostName == "" {
		return nil, status.Error(codes.InvalidArgument, "rule with host_name and direction required")
	}
	row := corrosion.FirewallRule{
		ID: newID(), HostName: r.HostName, Direction: r.Direction, Proto: r.Proto,
		PortRange: r.Port, CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority), Comment: r.Comment,
	}
	if err := corrosion.InsertHostFirewallRule(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "create host rule: %v", err)
	}
	s.audit(ctx, "firewall.host-rule.add", row.ID, r.HostName, "ok")
	s.reconcileLocal(ctx)
	return toPbFirewallRule(row), nil
}

func (s *Server) ListHostFirewallRules(ctx context.Context, req *pb.ListHostFirewallRulesRequest) (*pb.ListHostFirewallRulesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rules, err := corrosion.ListHostFirewallRules(ctx, s.db, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list host rules: %v", err)
	}
	resp := &pb.ListHostFirewallRulesResponse{}
	for _, r := range rules {
		resp.Rules = append(resp.Rules, toPbFirewallRule(r))
	}
	return resp, nil
}

func (s *Server) DeleteHostFirewallRule(ctx context.Context, req *pb.DeleteHostFirewallRuleRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteHostFirewallRule(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete host rule: %v", err)
	}
	s.audit(ctx, "firewall.host-rule.rm", req.Id, "", "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ── IP sets ──

func (s *Server) CreateIpSet(ctx context.Context, req *pb.CreateIpSetRequest) (*pb.IpSet, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	row := corrosion.IPSet{ID: newID(), Name: req.Name, CIDRs: req.Cidrs}
	if err := corrosion.InsertIPSet(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.Internal, "create ipset: %v", err)
	}
	s.audit(ctx, "firewall.ipset.add", row.Name, "", "ok")
	s.reconcileLocal(ctx)
	return toPbIpSet(row), nil
}

func (s *Server) ListIpSets(ctx context.Context, _ *pb.ListIpSetsRequest) (*pb.ListIpSetsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	sets, err := corrosion.ListIPSets(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list ipsets: %v", err)
	}
	resp := &pb.ListIpSetsResponse{}
	for _, st := range sets {
		resp.Ipsets = append(resp.Ipsets, toPbIpSet(st))
	}
	return resp, nil
}

func (s *Server) DeleteIpSet(ctx context.Context, req *pb.DeleteIpSetRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteIPSet(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete ipset: %v", err)
	}
	s.audit(ctx, "firewall.ipset.rm", req.Id, "", "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// ── Default-deny policy ──

func (s *Server) SetFirewallDefault(ctx context.Context, req *pb.SetFirewallDefaultRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	scope := req.Scope
	if scope == "" {
		scope = "cluster"
	}
	if err := corrosion.SetFirewallDefault(ctx, s.db, scope, req.DefaultDeny, ""); err != nil {
		return nil, status.Errorf(codes.Internal, "set default policy: %v", err)
	}
	verdict := "accept"
	if req.DefaultDeny {
		verdict = "deny"
	}
	s.audit(ctx, "firewall.default-deny", scope, verdict, "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

func (s *Server) ListFirewallDefaults(ctx context.Context, _ *pb.ListFirewallDefaultsRequest) (*pb.ListFirewallDefaultsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	defaults, err := corrosion.ListFirewallDefaults(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list defaults: %v", err)
	}
	resp := &pb.ListFirewallDefaultsResponse{}
	for _, d := range defaults {
		resp.Defaults = append(resp.Defaults, &pb.FirewallDefault{Scope: d.Scope, DefaultDeny: d.DefaultDeny, StackName: d.StackName})
	}
	return resp, nil
}
