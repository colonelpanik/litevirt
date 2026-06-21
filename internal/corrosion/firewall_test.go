package corrosion

import (
	"context"
	"testing"
)

func TestClusterFirewallRuleCRUD(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if err := InsertClusterFirewallRule(ctx, c, FirewallRule{
		ID: "cr-1", Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	rules, err := ListClusterFirewallRules(ctx, c)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 || rules[0].PortRange != "80" {
		t.Fatalf("list = %+v, want one rule on port 80", rules)
	}
	if err := DeleteClusterFirewallRule(ctx, c, "cr-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rules, _ = ListClusterFirewallRules(ctx, c)
	if len(rules) != 0 {
		t.Fatalf("after delete, list = %+v, want empty", rules)
	}
}

func TestHostFirewallRuleScoping(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if err := InsertHostFirewallRule(ctx, c, FirewallRule{ID: "a", HostName: "h1", Direction: "ingress", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertHostFirewallRule(ctx, c, FirewallRule{ID: "b", HostName: "h2", Direction: "ingress", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	h1, _ := ListHostFirewallRules(ctx, c, "h1")
	if len(h1) != 1 || h1[0].HostName != "h1" {
		t.Fatalf("h1 rules = %+v, want one for h1", h1)
	}
	all, _ := ListHostFirewallRules(ctx, c, "")
	if len(all) != 2 {
		t.Fatalf("all rules = %d, want 2", len(all))
	}
}

func TestHostFirewallRuleRequiresHost(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertHostFirewallRule(ctx, c, FirewallRule{ID: "x", Direction: "ingress"}); err == nil {
		t.Fatal("expected error inserting host rule with empty host name")
	}
}

func TestFirewallRuleRejectsIPv6(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	err := InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "v6", Direction: "ingress", CIDR: "2001:db8::/32", Action: "accept"})
	if err == nil {
		t.Fatal("expected IPv6 CIDR to be rejected (renderer is IPv4-only)")
	}
}

func TestIPSetCRUD(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := InsertIPSet(ctx, c, IPSet{ID: "s1", Name: "trusted", CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	sets, err := ListIPSets(ctx, c)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sets) != 1 || len(sets[0].CIDRs) != 2 {
		t.Fatalf("list = %+v, want one set with 2 CIDRs", sets)
	}
	if err := DeleteIPSet(ctx, c, "s1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	sets, _ = ListIPSets(ctx, c)
	if len(sets) != 0 {
		t.Fatalf("after delete = %+v, want empty", sets)
	}
}

func TestFirewallDefaultsResolution(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// Unset → accept.
	if deny, _ := ResolveDefaultDeny(ctx, c, "h1"); deny {
		t.Error("unset default should resolve to accept")
	}
	// Cluster deny applies to all hosts without an override.
	if err := SetFirewallDefault(ctx, c, "cluster", true, ""); err != nil {
		t.Fatal(err)
	}
	if deny, _ := ResolveDefaultDeny(ctx, c, "h1"); !deny {
		t.Error("h1 should inherit cluster deny")
	}
	// Upsert is idempotent (one live row per scope).
	if err := SetFirewallDefault(ctx, c, "cluster", true, ""); err != nil {
		t.Fatal(err)
	}
	defs, _ := ListFirewallDefaults(ctx, c)
	if len(defs) != 1 {
		t.Fatalf("defaults = %d, want 1 (upsert must not duplicate)", len(defs))
	}
}

func TestDeleteStackFirewall(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	const stack = "web-stack"

	// Seed a full stack firewall config.
	if err := InsertSecurityGroup(ctx, c, SecurityGroup{ID: "sg1", Name: "web", StackName: stack}); err != nil {
		t.Fatal(err)
	}
	if err := InsertSGRule(ctx, c, SGRule{ID: "r1", SGID: "sg1", Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertIPSet(ctx, c, IPSet{ID: "ip1", Name: "set", CIDRs: []string{"10.0.0.0/8"}, StackName: stack}); err != nil {
		t.Fatal(err)
	}
	if err := InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "cr1", Direction: "ingress", Action: "accept", StackName: stack}); err != nil {
		t.Fatal(err)
	}
	if err := SetFirewallDefault(ctx, c, "cluster", true, stack); err != nil {
		t.Fatal(err)
	}

	// Tear it down.
	if err := DeleteStackFirewall(ctx, c, stack); err != nil {
		t.Fatalf("DeleteStackFirewall: %v", err)
	}

	if sgs, _ := ListSecurityGroups(ctx, c, stack); len(sgs) != 0 {
		t.Errorf("security groups not removed: %+v", sgs)
	}
	if rules, _ := ListSGRules(ctx, c, "sg1"); len(rules) != 0 {
		t.Errorf("sg rules not removed: %+v", rules)
	}
	if sets, _ := ListIPSets(ctx, c); len(sets) != 0 {
		t.Errorf("ipsets not removed: %+v", sets)
	}
	if cr, _ := ListClusterFirewallRules(ctx, c); len(cr) != 0 {
		t.Errorf("cluster rules not removed: %+v", cr)
	}
	if defs, _ := ListFirewallDefaults(ctx, c); len(defs) != 0 {
		t.Errorf("stack default-deny not removed: %+v", defs)
	}
}
