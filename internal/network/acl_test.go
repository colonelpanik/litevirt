package network

import (
	"strings"
	"testing"
)

func TestChainName(t *testing.T) {
	tests := []struct {
		tapDev    string
		direction string
		want      string
	}{
		{"tap0", "in", "tap-tap0-in"},
		{"tap0", "out", "tap-tap0-out"},
		{"vnet1", "in", "tap-vnet1-in"},
	}
	for _, tt := range tests {
		got := chainName(tt.tapDev, tt.direction)
		if got != tt.want {
			t.Errorf("chainName(%q, %q) = %q, want %q", tt.tapDev, tt.direction, got, tt.want)
		}
	}
}

func TestNftRuleArgs_TCP(t *testing.T) {
	rule := ACLRule{
		Direction: "ingress",
		Proto:     "tcp",
		PortRange: "80",
		Action:    "accept",
	}
	args := nftRuleArgs("tap0", rule)

	// Check key elements
	checkContains(t, args, "iifname")
	checkContains(t, args, "tap0")
	checkContains(t, args, "tcp")
	checkContains(t, args, "dport")
	checkContains(t, args, "80")
	checkContains(t, args, "accept")
}

func TestNftRuleArgs_ICMP(t *testing.T) {
	rule := ACLRule{
		Direction: "ingress",
		Proto:     "icmp",
		Action:    "accept",
	}
	args := nftRuleArgs("tap1", rule)

	checkContains(t, args, "iifname")
	checkContains(t, args, "ip")
	checkContains(t, args, "protocol")
	checkContains(t, args, "icmp")
	checkContains(t, args, "accept")

	// Should not have dport
	for _, a := range args {
		if a == "dport" || a == "sport" {
			t.Errorf("ICMP rule should not have port match, got: %v", args)
			break
		}
	}
}

func TestNftRuleArgs_AllProto(t *testing.T) {
	rule := ACLRule{
		Direction: "ingress",
		Proto:     "all",
		Action:    "accept",
	}
	args := nftRuleArgs("tap2", rule)

	checkContains(t, args, "iifname")
	checkContains(t, args, "accept")

	// Should not have proto-specific terms
	for _, a := range args {
		if a == "tcp" || a == "udp" || a == "protocol" {
			t.Errorf("'all' proto rule should not have protocol match: %v", args)
		}
	}
}

func TestNftRuleArgs_Egress(t *testing.T) {
	rule := ACLRule{
		Direction: "egress",
		Proto:     "tcp",
		PortRange: "443",
		Action:    "accept",
	}
	args := nftRuleArgs("tap3", rule)

	checkContains(t, args, "oifname")
	checkContains(t, args, "tcp")
	checkContains(t, args, "sport")
	checkContains(t, args, "accept")

	// Should NOT have iifname
	for _, a := range args {
		if a == "iifname" {
			t.Errorf("egress rule should use oifname, got iifname: %v", args)
		}
	}
}

func TestNftRuleArgs_WithCIDR(t *testing.T) {
	rule := ACLRule{
		Direction: "ingress",
		Proto:     "tcp",
		PortRange: "22",
		CIDR:      "10.0.0.0/8",
		Action:    "accept",
	}
	args := nftRuleArgs("tap4", rule)

	checkContains(t, args, "ip")
	checkContains(t, args, "saddr")
	checkContains(t, args, "10.0.0.0/8")
}

func TestEnsureChain_Empty(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := EnsureChain("tap0", nil)
	if err != nil {
		t.Fatalf("EnsureChain empty rules: %v", err)
	}

	// Should create table + chains, verify "accept" policy.
	// The policy is embedded in a single arg like "{ type filter... policy accept; }"
	found := false
	for _, call := range calls {
		for _, a := range call {
			if strings.Contains(a, "accept") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("empty rules should use accept policy, calls: %v", calls)
	}
}

func TestEnsureChain_WithRules(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	rules := []ACLRule{
		{Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"},
	}
	err := EnsureChain("tap5", rules)
	if err != nil {
		t.Fatalf("EnsureChain with rules: %v", err)
	}

	// Should have add table + add chains + flush + rule calls
	if len(calls) < 4 {
		t.Errorf("expected at least 4 calls, got %d: %v", len(calls), calls)
	}

	// Verify drop policy in chain creation
	foundDrop := false
	for _, call := range calls {
		for _, a := range call {
			if a == "{ type filter hook forward priority 0; policy drop; }" {
				foundDrop = true
			}
		}
	}
	if !foundDrop {
		t.Errorf("rules-present chain should use drop policy; calls: %v", calls)
	}
}

func TestDeleteChain(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := DeleteChain("tap6")
	if err != nil {
		t.Fatalf("DeleteChain: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %v", len(calls), calls)
	}
	for _, call := range calls {
		if call[0] != "nft" || call[1] != "delete" || call[2] != "chain" {
			t.Errorf("expected nft delete chain, got %v", call)
		}
	}
	// Verify chain names
	foundIn := false
	foundOut := false
	for _, call := range calls {
		for _, a := range call {
			if a == "tap-tap6-in" {
				foundIn = true
			}
			if a == "tap-tap6-out" {
				foundOut = true
			}
		}
	}
	if !foundIn {
		t.Errorf("missing tap-tap6-in in calls: %v", calls)
	}
	if !foundOut {
		t.Errorf("missing tap-tap6-out in calls: %v", calls)
	}
}

// checkContains is a helper to verify a value is present in a slice.
func checkContains(t *testing.T, args []string, want string) {
	t.Helper()
	for _, a := range args {
		if a == want {
			return
		}
	}
	t.Errorf("expected %q in args %v", want, args)
}
