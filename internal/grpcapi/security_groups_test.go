package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv sg create/rm/rule-add/rule-rm` used to write the host's database straight
// from the CLI process, so they skipped the daemon's authorization and left no
// audit row (colonelpanik/litevirt#182). They now reach these RPCs, which must
// record the same rows the web UI's security-group pages record: who, what, and
// the group or rule before and after. A removal matters most, because the group
// and its rules are tombstoned and the row is then the only record of what
// traffic they governed.
func TestSecurityGroupRPCs_AuditWhoWhatBeforeAfter(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	rec := &fakeReconciler{}
	s.SetFirewallReconciler(rec)

	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "isolate"})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	if sg.Id == "" || sg.Name != "isolate" {
		t.Fatalf("CreateSecurityGroup returned %+v, want a new id and name isolate", sg)
	}
	wantAudit(t, s, "sg.add", "alice", "isolate", "before=none after={name=isolate rules=[]}")
	if got, err := corrosion.GetSecurityGroup(context.Background(), s.db, sg.Id); err != nil || got == nil {
		t.Fatalf("group %s not stored (err %v)", sg.Id, err)
	}

	// Proto, action and priority are left empty: the "after" must be the rule
	// as stored and enforced, defaults included.
	added, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
		SgId: sg.Id, Direction: "ingress", Port: "22", Cidr: "10.0.0.0/8",
	}})
	if err != nil {
		t.Fatalf("AddSecurityGroupRule: %v", err)
	}
	if added.Id == "" || added.Proto != "all" || added.Action != "accept" || added.Priority != 100 {
		t.Errorf("AddSecurityGroupRule returned %+v, want a new id and the stored defaults", added)
	}
	rule := "{sg=" + sg.Id + " ingress all port=22 cidr=10.0.0.0/8 accept priority=100}"
	wantAudit(t, s, "sg.rule.add", "alice", sg.Id, "before=none after="+rule)

	if _, err := s.RemoveSecurityGroupRule(ctx, &pb.RemoveSecurityGroupRuleRequest{Id: added.Id}); err != nil {
		t.Fatalf("RemoveSecurityGroupRule: %v", err)
	}
	wantAudit(t, s, "sg.rule.rm", "alice", added.Id, "before="+rule+" after=none")

	// A second rule, so the group's removal has something of its own to record.
	if _, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
		SgId: sg.Id, Direction: "egress", Proto: "udp", Port: "53", Action: "drop", Priority: 5,
	}}); err != nil {
		t.Fatalf("AddSecurityGroupRule(egress): %v", err)
	}
	if _, err := s.DeleteSecurityGroup(ctx, &pb.DeleteSecurityGroupRequest{Id: sg.Id}); err != nil {
		t.Fatalf("DeleteSecurityGroup: %v", err)
	}
	wantAudit(t, s, "sg.rm", "alice", sg.Id,
		"before={name=isolate rules=[{sg="+sg.Id+" egress udp port=53 cidr=any drop priority=5}]} after=none")
	if rules, err := corrosion.ListSGRules(context.Background(), s.db, sg.Id); err != nil || len(rules) != 0 {
		t.Errorf("rules left after the group was removed: %v (err %v)", rules, err)
	}
	// Every mutation re-renders the connected host at once, as the other
	// firewall tiers do.
	if rec.calls != 5 {
		t.Errorf("reconciler ran %d times, want 5 (one per mutation)", rec.calls)
	}
}

// A viewer must not be able to change the firewall. Before these RPCs the CLI
// had no authorization at all: anything that could read the host's data
// directory could rewrite the cluster's security groups.
func TestSecurityGroupRPCs_ViewerRefused(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server) context.Context{
		// No role bindings at all: the legacy role fallback decides.
		"legacy viewer": func(t *testing.T, s *Server) context.Context { return viewerCtx() },
		// Bound to the built-in Viewer role: the RBAC engine decides.
		"bound Viewer": func(t *testing.T, s *Server) context.Context {
			bg := context.Background()
			if err := auth.SeedBuiltinRoles(bg, s.db); err != nil {
				t.Fatalf("SeedBuiltinRoles: %v", err)
			}
			if err := corrosion.InsertRoleBinding(bg, s.db, corrosion.RoleBindingRecord{
				ID: "bob-root", Path: "/", Role: "Viewer", Principal: "user:bob@local", Propagate: true,
			}); err != nil {
				t.Fatalf("InsertRoleBinding: %v", err)
			}
			engine := auth.NewEngine(s.db)
			if err := engine.Reload(bg); err != nil {
				t.Fatalf("Reload: %v", err)
			}
			s.SetAuthEngine(engine)
			// bob's legacy role says operator; the binding must win.
			return userCtx("bob", "operator")
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			ctx := mk(t, s)
			bg := context.Background()
			existing := corrosion.SecurityGroup{ID: "sg-1", Name: "web"}
			if err := corrosion.InsertSecurityGroup(bg, s.db, existing); err != nil {
				t.Fatalf("InsertSecurityGroup: %v", err)
			}
			if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "r-1", SGID: "sg-1", Direction: "ingress"}); err != nil {
				t.Fatalf("InsertSGRule: %v", err)
			}

			calls := map[string]func() error{
				"CreateSecurityGroup": func() error {
					_, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "evil"})
					return err
				},
				"DeleteSecurityGroup": func() error {
					_, err := s.DeleteSecurityGroup(ctx, &pb.DeleteSecurityGroupRequest{Id: "sg-1"})
					return err
				},
				"AddSecurityGroupRule": func() error {
					_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
						SgId: "sg-1", Direction: "ingress", Port: "22",
					}})
					return err
				},
				"RemoveSecurityGroupRule": func() error {
					_, err := s.RemoveSecurityGroupRule(ctx, &pb.RemoveSecurityGroupRuleRequest{Id: "r-1"})
					return err
				},
			}
			for rpc, call := range calls {
				if err := call(); status.Code(err) != codes.PermissionDenied {
					t.Errorf("%s as viewer: err = %v, want PermissionDenied", rpc, err)
				}
			}

			sgs, _ := corrosion.ListSecurityGroups(bg, s.db, "")
			if len(sgs) != 1 || sgs[0].ID != "sg-1" {
				t.Errorf("groups after refused calls = %+v, want only sg-1", sgs)
			}
			rules, _ := corrosion.ListSGRules(bg, s.db, "sg-1")
			if len(rules) != 1 || rules[0].ID != "r-1" {
				t.Errorf("rules after refused calls = %+v, want only r-1", rules)
			}
		})
	}
}

// A NetworkAdmin binding carries sg.*, which is what these RPCs check.
func TestSecurityGroupRPCs_NetworkAdminAllowed(t *testing.T) {
	s := testServer(t)
	bg := context.Background()
	if err := auth.SeedBuiltinRoles(bg, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(bg, s.db, corrosion.RoleBindingRecord{
		ID: "net-root", Path: "/", Role: "NetworkAdmin", Principal: "user:nina@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(bg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	// A legacy role of viewer: only the binding can admit her.
	ctx := userCtx("nina", "viewer")
	if _, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"}); err != nil {
		t.Fatalf("CreateSecurityGroup as NetworkAdmin: %v", err)
	}
	wantAudit(t, s, "sg.add", "nina", "web", "before=none after={name=web rules=[]}")
}

func TestSecurityGroupRPCs_RejectBadRequests(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	for name, err := range map[string]error{
		"create without a name": func() error {
			_, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{})
			return err
		}(),
		"rule without a group": func() error {
			_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{Direction: "ingress"}})
			return err
		}(),
		"rule with an IPv6 cidr": func() error {
			_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
				SgId: "sg-1", Direction: "ingress", Cidr: "2001:db8::/32",
			}})
			return err
		}(),
		"delete without an id": func() error {
			_, err := s.DeleteSecurityGroup(ctx, &pb.DeleteSecurityGroupRequest{})
			return err
		}(),
		"remove rule without an id": func() error {
			_, err := s.RemoveSecurityGroupRule(ctx, &pb.RemoveSecurityGroupRuleRequest{})
			return err
		}(),
	} {
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
}
