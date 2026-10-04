package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// Security-group CRUD, the per-NIC firewall tier (colonelpanik/litevirt#182).
//
// The web UI's security-group pages call these with the session's bearer, so
// the daemon's own interceptor decides who the caller is and RequirePerm
// decides what they may do, exactly as for any other RPC. The pages used to
// write in-process behind an in-process authorizer that resolved the caller
// from incoming gRPC metadata the UI never has, so it authorized every session
// as the bearerless admin. Each RPC checks sg.write at the cluster root
// (security groups are cluster-global, bound to NICs by name) and records who,
// what, and the group or rule before and after. Only the daemon can write that
// row, because only it holds the host's audit sub-chain tail and signing key.
//
// `lv sg create/rm/rule-add/rule-rm` still write the host's Corrosion database
// from the CLI process on this branch; moving them onto these RPCs is separate
// work.
//
// sg.write is held by Admin (`*`) and NetworkAdmin (`sg.*`); Operator holds
// sg.read only. A cluster with no role bindings falls back to the legacy
// operator role.

const sgWriteVerb = "sg.write"

func (s *Server) requireSGWrite(ctx context.Context) error {
	return s.RequirePerm(ctx, "/", sgWriteVerb, "operator")
}

func toPbSecurityGroup(g corrosion.SecurityGroup) *pb.SecurityGroup {
	return &pb.SecurityGroup{Id: g.ID, Name: g.Name, StackName: g.StackName, CreatedAt: g.CreatedAt}
}

func toPbSGRule(r corrosion.SGRule) *pb.SecurityGroupRule {
	return &pb.SecurityGroupRule{
		Id: r.ID, SgId: r.SGID, Direction: r.Direction, Proto: r.Proto,
		Port: r.PortRange, Cidr: r.CIDR, Action: r.Action, Priority: int32(r.Priority),
	}
}

// CreateSecurityGroup creates an empty security group.
func (s *Server) CreateSecurityGroup(ctx context.Context, req *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	row := corrosion.SecurityGroup{ID: randid.New(), Name: req.Name, StackName: req.StackName}
	if err := corrosion.InsertSecurityGroup(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.Internal, "create security group: %v", err)
	}
	// The same after-state the UI records for a new group: it has no rules yet.
	s.audit(ctx, "sg.add", row.Name, corrosion.AuditChange(corrosion.AuditStateNone, row.AuditText(nil)), "ok")
	s.reconcileLocal(ctx)
	if stored, err := corrosion.GetSecurityGroup(ctx, s.db, row.ID); err == nil && stored != nil {
		row = *stored
	}
	return toPbSecurityGroup(row), nil
}

// DeleteSecurityGroup tombstones a security group and every rule in it.
func (s *Server) DeleteSecurityGroup(ctx context.Context, req *pb.DeleteSecurityGroupRequest) (*emptypb.Empty, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	// Read what is about to go, rules included: after this the audit row is
	// the only record of which traffic they allowed or refused.
	before := corrosion.SecurityGroupAuditState(ctx, s.db, req.Id)
	if err := corrosion.DeleteSGRules(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete security group rules: %v", err)
	}
	if err := corrosion.DeleteSecurityGroup(ctx, s.db, req.Id); err != nil {
		// The rules are already gone, so the change is recorded even though
		// the group row itself was not tombstoned.
		s.audit(ctx, "sg.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditUnknown(err)), "error")
		s.reconcileLocal(ctx)
		return nil, status.Errorf(codes.Internal, "delete security group: %v", err)
	}
	s.audit(ctx, "sg.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}

// AddSecurityGroupRule appends a rule to a security group.
func (s *Server) AddSecurityGroupRule(ctx context.Context, req *pb.AddSecurityGroupRuleRequest) (*pb.SecurityGroupRule, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	r := req.GetRule()
	if r == nil || r.SgId == "" || r.Direction == "" {
		return nil, status.Error(codes.InvalidArgument, "rule with sg_id and direction required")
	}
	row := corrosion.SGRule{
		ID: randid.New(), SGID: r.SgId, Direction: r.Direction, Proto: r.Proto,
		PortRange: r.Port, CIDR: r.Cidr, Action: r.Action, Priority: int(r.Priority),
	}
	if err := corrosion.InsertSGRule(ctx, s.db, row); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "add security group rule: %v", err)
	}
	// Read back, so the "after" (and the reply) is the rule as stored: the
	// insert fills in defaults for an empty proto, action and priority.
	stored, gerr := corrosion.GetSGRule(ctx, s.db, row.ID)
	s.audit(ctx, "sg.rule.add", row.SGID,
		corrosion.AuditChange(corrosion.AuditStateNone, corrosion.SGRuleAuditState(stored, gerr)), "ok")
	s.reconcileLocal(ctx)
	if gerr == nil && stored != nil {
		row = *stored
	}
	return toPbSGRule(row), nil
}

// RemoveSecurityGroupRule tombstones one rule, by the RULE id.
func (s *Server) RemoveSecurityGroupRule(ctx context.Context, req *pb.RemoveSecurityGroupRuleRequest) (*emptypb.Empty, error) {
	if err := s.requireSGWrite(ctx); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	before := corrosion.SGRuleAuditState(corrosion.GetSGRule(ctx, s.db, req.Id))
	if err := corrosion.DeleteSGRule(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "remove security group rule: %v", err)
	}
	s.audit(ctx, "sg.rule.rm", req.Id, corrosion.AuditChange(before, corrosion.AuditStateNone), "ok")
	s.reconcileLocal(ctx)
	return &emptypb.Empty{}, nil
}
