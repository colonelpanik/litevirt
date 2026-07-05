package firewall

import (
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// Golden-file coverage for the deterministic firewall renderer. Each
// case below pins one rendering surface (cluster tier, host tier, NIC
// dispatch, IPset expansion, default-deny). Update with `go test
// ./internal/firewall/ -run TestRenderGolden -update`.
func TestRenderGolden(t *testing.T) {
	cases := []struct {
		name string
		path string
		plan Plan
	}{
		{
			name: "empty",
			path: "testdata/render_empty.golden",
			plan: Plan{},
		},
		{
			name: "default_deny_no_rules",
			path: "testdata/render_default_deny.golden",
			plan: Plan{DefaultDeny: true},
		},
		{
			name: "cluster_and_host_tier",
			path: "testdata/render_cluster_host.golden",
			plan: Plan{
				DefaultDeny: true,
				ClusterRules: []Rule{
					{Direction: Egress, Proto: "all", CIDR: "10.0.0.0/8", Action: Drop, Comment: "no rfc1918 egress"},
				},
				HostRules: []Rule{
					{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "192.0.2.0/24", Action: Accept, Comment: "ssh from jump"},
				},
			},
		},
		{
			name: "ipsets_and_nic_binding",
			path: "testdata/render_ipsets_nic.golden",
			plan: Plan{
				DefaultDeny: true,
				IPSets: []IPSet{
					{Name: "trusted", CIDRs: []string{"10.0.0.0/24", "10.0.1.0/24"}},
				},
				SecurityGroups: []SecurityGroup{
					{Name: "web", Rules: []Rule{
						{Direction: Ingress, Proto: "tcp", PortRange: "80", CIDR: "@trusted", Action: Accept},
						{Direction: Ingress, Proto: "tcp", PortRange: "443", CIDR: "@trusted", Action: Accept},
					}},
				},
				NICs: []NICBinding{
					{NICDev: "tap-vm1-0", VMName: "vm1", SecurityGroups: []string{"web"}},
				},
			},
		},
		{
			name: "nat_and_isolation",
			path: "testdata/render_nat_isolation.golden",
			plan: Plan{
				NAT: []NATRule{
					// out of order to prove deterministic sort + SNAT-before-masquerade.
					{Subnet: "10.0.2.0/24", Bridge: "br-mgd-b"},
					{Subnet: "10.0.1.0/24", Bridge: "br-mgd-a"},
					{Subnet: "10.100.0.0/24", OutIface: "eth0", SNATTo: "203.0.113.5"},
				},
				HostIsolation: []IsolationChain{
					{Bridge: "br-iso-z"},
					{Bridge: "br-iso-a", Exceptions: []IsolationException{
						{VIP: "10.100.0.50", Ports: []int{80, 443}},
					}},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render(tc.plan)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			golden.Assert(t, tc.path, got)
		})
	}
}
