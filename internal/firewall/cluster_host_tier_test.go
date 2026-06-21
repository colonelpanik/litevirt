package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCorrosionPlanLoader_LoadsAllTiers is the v21 regression: the loader must
// now populate the cluster + host rule tiers, the default-deny policy, and ip
// sets — all of which were dead (never read) before the firewall wire-up.
func TestCorrosionPlanLoader_LoadsAllTiers(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Cluster rule: allow ssh from a trusted ipset, on every NIC.
	if err := corrosion.InsertIPSet(ctx, db, corrosion.IPSet{
		ID: "ips-1", Name: "admins", CIDRs: []string{"10.0.0.0/24"},
	}); err != nil {
		t.Fatalf("InsertIPSet: %v", err)
	}
	if err := corrosion.InsertClusterFirewallRule(ctx, db, corrosion.FirewallRule{
		ID: "cr-1", Direction: "ingress", Proto: "tcp", PortRange: "22",
		CIDR: "@admins", Action: "accept", Comment: "admin ssh",
	}); err != nil {
		t.Fatalf("InsertClusterFirewallRule: %v", err)
	}
	// Host rule: drop egress to RFC1918 on host-a only.
	if err := corrosion.InsertHostFirewallRule(ctx, db, corrosion.FirewallRule{
		ID: "hr-1", HostName: "host-a", Direction: "egress", Proto: "all",
		CIDR: "192.168.0.0/16", Action: "drop",
	}); err != nil {
		t.Fatalf("InsertHostFirewallRule: %v", err)
	}
	// A host rule for a DIFFERENT host must NOT appear in host-a's plan.
	if err := corrosion.InsertHostFirewallRule(ctx, db, corrosion.FirewallRule{
		ID: "hr-2", HostName: "host-b", Direction: "ingress", Proto: "tcp", PortRange: "443", Action: "accept",
	}); err != nil {
		t.Fatalf("InsertHostFirewallRule(host-b): %v", err)
	}
	// Cluster-wide default-deny.
	if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, ""); err != nil {
		t.Fatalf("SetFirewallDefault: %v", err)
	}

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{})(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}

	if !plan.DefaultDeny {
		t.Error("DefaultDeny = false, want true (cluster policy)")
	}
	if len(plan.ClusterRules) != 1 {
		t.Fatalf("ClusterRules = %d, want 1", len(plan.ClusterRules))
	}
	if plan.ClusterRules[0].Comment != "admin ssh" {
		t.Errorf("cluster rule comment = %q, want 'admin ssh'", plan.ClusterRules[0].Comment)
	}
	if len(plan.HostRules) != 1 {
		t.Fatalf("HostRules for host-a = %d, want 1 (host-b's rule must be excluded)", len(plan.HostRules))
	}
	if plan.HostRules[0].Action != Drop {
		t.Errorf("host rule action = %q, want drop", plan.HostRules[0].Action)
	}
	if len(plan.IPSets) != 1 || plan.IPSets[0].Name != "admins" {
		t.Fatalf("IPSets = %+v, want one named admins", plan.IPSets)
	}

	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"policy drop;",                          // default-deny rendered
		"set admins {",                          // ipset object
		"jump cluster_default",                  // cluster tier hooked
		"jump host_overrides",                   // host tier hooked
		"tcp dport 22 ip saddr @admins accept",  // cluster rule, ingress→saddr
		"ip daddr 192.168.0.0/16 drop",          // host rule, egress→daddr
	)
}

// TestCorrosionPlanLoader_DefaultAcceptWhenUnset confirms the unchanged
// pre-v21 behaviour: no firewall_defaults row ⇒ policy accept.
func TestCorrosionPlanLoader_DefaultAcceptWhenUnset(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{})(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if plan.DefaultDeny {
		t.Error("DefaultDeny = true with no policy set, want false (accept)")
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "policy accept;") {
		t.Errorf("expected default policy accept, got:\n%s", out)
	}
}

// TestHostDefaultOverridesCluster checks ResolveDefaultDeny prefers the
// host-scoped policy over the cluster default.
func TestHostDefaultOverridesCluster(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Cluster deny, but host-a overrides to accept.
	if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetFirewallDefault(ctx, db, "host-a", false, ""); err != nil {
		t.Fatal(err)
	}
	planA, _ := CorrosionPlanLoader(db, "host-a", Plan{})(ctx)
	if planA.DefaultDeny {
		t.Error("host-a should inherit its own accept override, got deny")
	}
	planB, _ := CorrosionPlanLoader(db, "host-b", Plan{})(ctx)
	if !planB.DefaultDeny {
		t.Error("host-b has no override, should inherit cluster deny")
	}
}
