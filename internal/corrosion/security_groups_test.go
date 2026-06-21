package corrosion

import (
	"context"
	"testing"
)

func TestSecurityGroupCRUD(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	sg := SecurityGroup{
		ID:        "sg-001",
		Name:      "web-tier",
		StackName: "mystack",
	}

	if err := InsertSecurityGroup(ctx, db, sg); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}

	got, err := GetSecurityGroup(ctx, db, "sg-001")
	if err != nil {
		t.Fatalf("GetSecurityGroup: %v", err)
	}
	if got == nil {
		t.Fatal("expected SG, got nil")
	}
	if got.Name != "web-tier" {
		t.Errorf("expected web-tier, got %s", got.Name)
	}
	if got.StackName != "mystack" {
		t.Errorf("expected mystack, got %s", got.StackName)
	}
}

func TestListSecurityGroups(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	for _, sg := range []SecurityGroup{
		{ID: "sg-a", Name: "alpha", StackName: "stack1"},
		{ID: "sg-b", Name: "beta", StackName: "stack1"},
		{ID: "sg-c", Name: "gamma", StackName: "stack2"},
	} {
		if err := InsertSecurityGroup(ctx, db, sg); err != nil {
			t.Fatalf("InsertSecurityGroup %s: %v", sg.ID, err)
		}
	}

	// Filter by stack
	sgs, err := ListSecurityGroups(ctx, db, "stack1")
	if err != nil {
		t.Fatalf("ListSecurityGroups: %v", err)
	}
	if len(sgs) != 2 {
		t.Errorf("expected 2 SGs in stack1, got %d", len(sgs))
	}

	// All
	all, err := ListSecurityGroups(ctx, db, "")
	if err != nil {
		t.Fatalf("ListSecurityGroups all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 total SGs, got %d", len(all))
	}
}

func TestDeleteSecurityGroup(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	sg := SecurityGroup{ID: "sg-del", Name: "to-delete"}
	if err := InsertSecurityGroup(ctx, db, sg); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}

	if err := DeleteSecurityGroup(ctx, db, "sg-del"); err != nil {
		t.Fatalf("DeleteSecurityGroup: %v", err)
	}

	got, err := GetSecurityGroup(ctx, db, "sg-del")
	if err != nil {
		t.Fatalf("GetSecurityGroup after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil after deletion")
	}
}

// TestInsertSGRule_RejectsIPv6 is the F10 regression: IPv6 CIDRs must be
// rejected at creation (the renderer only emits IPv4, so accepting them would
// silently fail to filter IPv6). IPv4 and empty (any) CIDRs are accepted.
func TestInsertSGRule_RejectsIPv6(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-v6", Name: "v6"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}

	for _, cidr := range []string{"2001:db8::/32", "fe80::1", "::/0"} {
		err := InsertSGRule(ctx, db, SGRule{ID: "r-" + cidr, SGID: "sg-v6", Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: "accept"})
		if err == nil {
			t.Errorf("IPv6 CIDR %q should be rejected", cidr)
		}
	}
	// IPv4 + empty (any-source) must still be accepted.
	for _, cidr := range []string{"10.0.0.0/8", "192.168.1.5", ""} {
		if err := InsertSGRule(ctx, db, SGRule{ID: "ok-" + cidr, SGID: "sg-v6", Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: "accept"}); err != nil {
			t.Errorf("IPv4/empty CIDR %q should be accepted, got %v", cidr, err)
		}
	}
}

func TestIsIPv6CIDR(t *testing.T) {
	v6 := []string{"2001:db8::/32", "::1", "fe80::1", "::/0"}
	notV6 := []string{"", "10.0.0.0/8", "192.168.1.1", "not-an-ip", "0.0.0.0/0"}
	for _, s := range v6 {
		if !isIPv6CIDR(s) {
			t.Errorf("isIPv6CIDR(%q) = false, want true", s)
		}
	}
	for _, s := range notV6 {
		if isIPv6CIDR(s) {
			t.Errorf("isIPv6CIDR(%q) = true, want false", s)
		}
	}
}

func TestSGRulesCRUD(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Insert SG first
	if err := InsertSecurityGroup(ctx, db, SecurityGroup{ID: "sg-rules", Name: "test"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}

	rules := []SGRule{
		{ID: "rule-1", SGID: "sg-rules", Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"},
		{ID: "rule-2", SGID: "sg-rules", Direction: "ingress", Proto: "tcp", PortRange: "443", Action: "accept"},
	}
	for _, r := range rules {
		if err := InsertSGRule(ctx, db, r); err != nil {
			t.Fatalf("InsertSGRule %s: %v", r.ID, err)
		}
	}

	listed, err := ListSGRules(ctx, db, "sg-rules")
	if err != nil {
		t.Fatalf("ListSGRules: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(listed))
	}

	if err := DeleteSGRules(ctx, db, "sg-rules"); err != nil {
		t.Fatalf("DeleteSGRules: %v", err)
	}

	after, err := ListSGRules(ctx, db, "sg-rules")
	if err != nil {
		t.Fatalf("ListSGRules after delete: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(after))
	}
}

func TestGetSecurityGroup_NotFound(t *testing.T) {
	db, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	sg, err := GetSecurityGroup(ctx, db, "nonexistent")
	if err != nil {
		t.Fatalf("GetSecurityGroup: %v", err)
	}
	if sg != nil {
		t.Errorf("expected nil for nonexistent SG, got %+v", sg)
	}
}
