package firewall

import (
	"strings"
	"testing"
)

// TestRender_EmptyPlan_BareTable produces a parseable table with the
// stateful-conntrack preamble and accept policy by default.
func TestRender_EmptyPlan_BareTable(t *testing.T) {
	out, err := Render(Plan{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"table inet litevirt-fw {",
		"chain forward {",
		"policy accept;",
		"ct state established,related accept",
		"ct state invalid drop",
		"jump cluster_default",
		"jump host_overrides",
		"jump nic_dispatch",
	)
}

// TestRender_DefaultDeny flips policy to drop and keeps conntrack so
// reply traffic still flows.
func TestRender_DefaultDeny(t *testing.T) {
	out, err := Render(Plan{DefaultDeny: true})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "policy drop;") {
		t.Errorf("expected drop policy, got:\n%s", out)
	}
	// Conntrack accept must still come BEFORE any drop logic, otherwise
	// reply traffic dies under the default-deny policy.
	idxConntrack := strings.Index(out, "ct state established,related accept")
	idxJump := strings.Index(out, "jump nic_dispatch")
	if idxConntrack < 0 || idxJump < 0 || idxConntrack > idxJump {
		t.Errorf("conntrack accept must precede chain jumps")
	}
}

// TestRender_SecurityGroup_Expansion verifies SG rules land inside the
// per-NIC chain and reference the correct interface.
func TestRender_SecurityGroup_Expansion(t *testing.T) {
	plan := Plan{
		SecurityGroups: []SecurityGroup{{
			Name: "web",
			Rules: []Rule{
				{Direction: Ingress, Proto: "tcp", PortRange: "80", Action: Accept, Comment: "http"},
				{Direction: Ingress, Proto: "tcp", PortRange: "443", Action: Accept, Comment: "https"},
			},
		}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "web-1", SecurityGroups: []string{"web"}}},
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Cloud-vendor convention: ingress = arriving at the VM, so the
	// packet is leaving the bridge OUT through the tap → oifname.
	mustContainAll(t, out,
		"chain nic_tap0 {",
		`# security group "web"`,
		"oifname tap0 tcp dport 80 accept",
		"oifname tap0 tcp dport 443 accept",
		`comment "http"`,
		"iifname tap0 jump nic_tap0",
		"oifname tap0 jump nic_tap0",
	)
}

// TestRender_RejectsIPv6 (F10): the renderer is IPv4-only, so an IPv6 CIDR or
// ipset element must be rejected at validation — emitting `ip saddr <v6>` would
// poison the whole atomic ruleset at apply time. Set references ("@name") and
// IPv4 CIDRs must NOT be falsely rejected.
func TestRender_RejectsIPv6(t *testing.T) {
	if _, err := Render(Plan{
		SecurityGroups: []SecurityGroup{{
			Name:  "web",
			Rules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "443", CIDR: "2001:db8::/32", Action: Accept}},
		}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "web-1", SecurityGroups: []string{"web"}}},
	}); err == nil {
		t.Error("IPv6 CIDR in an SG rule should be rejected, got nil")
	}

	if _, err := Render(Plan{
		IPSets: []IPSet{{Name: "blocked", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}}},
	}); err == nil {
		t.Error("IPv6 ipset element should be rejected, got nil")
	}

	// IPv4 CIDR + a set reference must pass cleanly.
	if _, err := Render(Plan{
		IPSets: []IPSet{{Name: "allow", CIDRs: []string{"10.0.0.0/8"}}},
		SecurityGroups: []SecurityGroup{{
			Name: "web",
			Rules: []Rule{
				{Direction: Ingress, Proto: "tcp", PortRange: "443", CIDR: "192.168.0.0/16", Action: Accept},
				{Direction: Ingress, Proto: "tcp", PortRange: "80", CIDR: "@allow", Action: Accept},
			},
		}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "web-1", SecurityGroups: []string{"web"}}},
	}); err != nil {
		t.Errorf("IPv4 CIDR + set-reference should pass, got %v", err)
	}
}

// TestRender_EgressMatchesViaIifname_DPort ensures egress rules match
// traffic FROM the VM (iifname=tap0) and use dport (the destination
// port at the remote endpoint, which is what users mean).
func TestRender_EgressMatchesViaIifname_DPort(t *testing.T) {
	plan := Plan{NICs: []NICBinding{{
		NICDev: "tap0",
		ExtraRules: []Rule{{
			Direction: Egress, Proto: "tcp", PortRange: "53",
			CIDR: "10.0.0.10/32", Action: Accept, Comment: "dns",
		}},
	}}}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "iifname tap0 tcp dport 53 ip daddr 10.0.0.10/32 accept") {
		t.Errorf("egress rule should match iifname/dport/daddr, got:\n%s", out)
	}
}

// TestRender_IPSet renders set blocks and rules referencing them by
// the @name syntax.
func TestRender_IPSet(t *testing.T) {
	plan := Plan{
		IPSets: []IPSet{{Name: "trusted_admins", CIDRs: []string{"10.0.0.5/32", "10.0.0.6/32"}}},
		NICs: []NICBinding{{
			NICDev: "tap0",
			ExtraRules: []Rule{{
				Direction: Ingress, Proto: "tcp", PortRange: "22",
				CIDR: "@trusted_admins", Action: Accept,
			}},
		}},
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"set trusted_admins {",
		"type ipv4_addr",
		"flags interval",
		"elements = { 10.0.0.5/32, 10.0.0.6/32 }",
		// Ingress rule against an IPset → match saddr=@set
		"oifname tap0 tcp dport 22 ip saddr @trusted_admins accept",
	)
}

// TestRender_UnknownSGRejected protects against typos in compose.
func TestRender_UnknownSGRejected(t *testing.T) {
	_, err := Render(Plan{
		NICs: []NICBinding{{NICDev: "tap0", SecurityGroups: []string{"ghost"}}},
	})
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected error mentioning unknown SG, got %v", err)
	}
}

// TestRender_DeterministicOutput two equivalent Plans produce identical
// bytes — required for the applier's "no change → skip" fast path.
func TestRender_DeterministicOutput(t *testing.T) {
	plan := Plan{
		SecurityGroups: []SecurityGroup{
			{Name: "a", Rules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "80", Action: Accept}}},
			{Name: "b", Rules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "443", Action: Accept}}},
		},
		IPSets: []IPSet{
			{Name: "first", CIDRs: []string{"10.0.0.0/24"}},
			{Name: "second", CIDRs: []string{"10.0.1.0/24"}},
		},
		NICs: []NICBinding{
			{NICDev: "tapZ", SecurityGroups: []string{"a"}},
			{NICDev: "tapA", SecurityGroups: []string{"b"}},
		},
	}
	a, _ := Render(plan)
	// Build the same plan with reversed NIC + IPset order.
	plan2 := plan
	plan2.NICs = []NICBinding{plan.NICs[1], plan.NICs[0]}
	plan2.IPSets = []IPSet{plan.IPSets[1], plan.IPSets[0]}
	b, _ := Render(plan2)
	if a != b {
		t.Errorf("output not deterministic across input ordering:\nA=\n%s\nB=\n%s", a, b)
	}
}

// TestRender_ChainNameSanitisation veth names contain dashes which are
// illegal in nftables identifiers — they must be turned into underscores.
func TestRender_ChainNameSanitisation(t *testing.T) {
	plan := Plan{NICs: []NICBinding{{NICDev: "veth-vm1-eth0"}}}
	out, _ := Render(plan)
	mustContainAll(t, out,
		"chain nic_veth_vm1_eth0 {",
		"iifname veth-vm1-eth0 jump nic_veth_vm1_eth0",
	)
}

// TestValidate_BadDirection ensures typo'd directions don't silently
// become rules that match nothing.
func TestValidate_BadDirection(t *testing.T) {
	_, err := Render(Plan{HostRules: []Rule{{Direction: "in", Action: Accept}}})
	if err == nil || !strings.Contains(err.Error(), "direction") {
		t.Fatalf("expected direction error, got %v", err)
	}
}

// TestValidate_BadAction rejects action strings outside accept/drop/reject.
func TestValidate_BadAction(t *testing.T) {
	_, err := Render(Plan{HostRules: []Rule{{Direction: Ingress, Action: "log"}}})
	if err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("expected action error, got %v", err)
	}
}

// TestFromCorrosionRule_DefaultsCollapseSafely covers the conversion
// from the on-disk-permissive defaults into the strict typed Rule.
func TestFromCorrosionRule_DefaultsCollapseSafely(t *testing.T) {
	r := FromCorrosionRule("", "", "", "", "")
	if r.Direction != Ingress {
		t.Errorf("default direction = %q, want ingress", r.Direction)
	}
	if r.Proto != "all" {
		t.Errorf("default proto = %q, want all", r.Proto)
	}
	if r.Action != Accept {
		t.Errorf("default action = %q, want accept", r.Action)
	}
}

func mustContainAll(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected %q in:\n%s", n, haystack)
		}
	}
}
