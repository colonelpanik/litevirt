package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func newFWTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{db: db, hostName: "host-a"}
}

// TestPersistStackFirewall is the v21 regression for the compose→firewall gap:
// a compose file's security-groups / ipsets / firewall block must persist to
// Corrosion on deploy, and be torn down on delete.
func TestPersistStackFirewall(t *testing.T) {
	ctx := context.Background()
	s := newFWTestServer(t)

	yaml := `
name: webstack
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
      - {direction: ingress, proto: tcp, port: "443", action: accept}
ipsets:
  admins:
    cidrs: ["10.0.0.0/24"]
firewall:
  default-deny: true
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "@admins", action: accept, comment: "ssh"}
`
	f, err := compose.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := s.persistStackFirewall(ctx, f); err != nil {
		t.Fatalf("persistStackFirewall: %v", err)
	}

	sgs, _ := corrosion.ListSecurityGroups(ctx, s.db, "webstack")
	if len(sgs) != 1 || sgs[0].Name != "web" {
		t.Fatalf("security groups = %+v, want one named web", sgs)
	}
	rules, _ := corrosion.ListSGRules(ctx, s.db, sgs[0].ID)
	if len(rules) != 2 {
		t.Fatalf("sg rules = %d, want 2", len(rules))
	}
	// Rules must render in YAML order (priority 10, 20) so accept-before-drop
	// sequences are deterministic.
	if rules[0].PortRange != "80" || rules[1].PortRange != "443" {
		t.Fatalf("sg rules out of YAML order: [%s, %s], want [80, 443]", rules[0].PortRange, rules[1].PortRange)
	}
	if rules[0].Priority >= rules[1].Priority {
		t.Fatalf("rule priorities not ascending by YAML order: %d, %d", rules[0].Priority, rules[1].Priority)
	}
	sets, _ := corrosion.ListIPSets(ctx, s.db)
	if len(sets) != 1 || sets[0].Name != "admins" {
		t.Fatalf("ipsets = %+v, want one named admins", sets)
	}
	cr, _ := corrosion.ListClusterFirewallRules(ctx, s.db)
	if len(cr) != 1 || cr[0].CIDR != "@admins" {
		t.Fatalf("cluster rules = %+v, want one referencing @admins", cr)
	}
	if deny, _ := corrosion.ResolveDefaultDeny(ctx, s.db, "host-a"); !deny {
		t.Error("default-deny not applied from compose")
	}

	// Re-deploy is idempotent: persisting again must not duplicate.
	if err := s.persistStackFirewall(ctx, f); err != nil {
		t.Fatalf("re-persist: %v", err)
	}
	sgs2, _ := corrosion.ListSecurityGroups(ctx, s.db, "webstack")
	if len(sgs2) != 1 {
		t.Fatalf("after re-deploy, security groups = %d, want 1 (no dupes)", len(sgs2))
	}

	// Teardown removes everything.
	if err := corrosion.DeleteStackFirewall(ctx, s.db, "webstack"); err != nil {
		t.Fatalf("DeleteStackFirewall: %v", err)
	}
	if sgs3, _ := corrosion.ListSecurityGroups(ctx, s.db, "webstack"); len(sgs3) != 0 {
		t.Errorf("security groups survived teardown: %+v", sgs3)
	}
	if cr3, _ := corrosion.ListClusterFirewallRules(ctx, s.db); len(cr3) != 0 {
		t.Errorf("cluster rules survived teardown: %+v", cr3)
	}
}

// TestPersistStackFirewall_RejectsIPv6 confirms a bad firewall block surfaces
// as an error (so DeployStack aborts) rather than silently not enforcing.
func TestPersistStackFirewall_RejectsIPv6(t *testing.T) {
	ctx := context.Background()
	s := newFWTestServer(t)
	yaml := `
name: v6stack
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, cidr: "2001:db8::/32", action: accept}
`
	f, err := compose.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := s.persistStackFirewall(ctx, f); err == nil {
		t.Fatal("expected IPv6 cluster rule to be rejected")
	}
}

// TestBackupRunner_ResolvesComposeRepo confirms the scheduler runner resolves a
// repo registered via a compose `backup-repos:` block (corrosion fallback),
// not just daemon-config repos.
func TestBackupRunner_ResolvesComposeRepo(t *testing.T) {
	ctx := context.Background()
	s := newFWTestServer(t)
	// No daemon-config repos; only a corrosion-registered one.
	r := &backupRunner{server: s, repos: map[string]string{}}

	if got := r.resolveRepoPath(ctx, "main"); got != "" {
		t.Fatalf("unknown repo resolved to %q, want empty", got)
	}
	if err := corrosion.UpsertBackupRepo(ctx, s.db, corrosion.BackupRepo{Name: "main", Path: "/srv/backup/main", StackName: "st"}); err != nil {
		t.Fatal(err)
	}
	if got := r.resolveRepoPath(ctx, "main"); got != "/srv/backup/main" {
		t.Fatalf("resolved %q, want /srv/backup/main", got)
	}
	// Daemon config wins over corrosion.
	r.repos["main"] = "/config/path"
	if got := r.resolveRepoPath(ctx, "main"); got != "/config/path" {
		t.Fatalf("config repo should win: got %q", got)
	}
}
