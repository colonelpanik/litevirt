package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// staticIfaceGatewayAddress derives the cloud-init CIDR address + gateway for a
// NIC's static IP. The guard under test: a prefix the caller already supplied
// must be preserved (never doubled to 10.0.1.50/24/24); a bare address takes
// the network's prefix, or a family default when the network has no subnet.
func TestStaticIfaceGatewayAddress(t *testing.T) {
	net24 := &compose.NetworkDef{Subnet: "10.0.1.0/24"}
	// SubnetRange returns the gateway with a prefix ("10.0.1.1/24"); the
	// network-config gateway must be a bare host address, so a derived gateway
	// is stripped to "10.0.1.1" (netplan/ENI reject a gateway carrying a prefix).
	const derivedGw = "10.0.1.1"
	cases := []struct {
		name             string
		ip, gateway      string
		netDef           *compose.NetworkDef
		wantAddr, wantGw string
	}{
		{"bare_ip_derives_prefix", "10.0.1.50", "", net24, "10.0.1.50/24", derivedGw},
		{"supplied_prefix_preserved", "10.0.1.50/24", "", net24, "10.0.1.50/24", derivedGw},
		{"supplied_host_prefix_preserved", "10.0.1.50/32", "", net24, "10.0.1.50/32", derivedGw},
		{"explicit_gateway_wins", "10.0.1.50", "10.0.1.254", net24, "10.0.1.50/24", "10.0.1.254"},
		{"no_subnet_v4_default", "192.168.9.5", "", nil, "192.168.9.5/24", ""},
		{"no_subnet_v6_default", "2001:db8::5", "", nil, "2001:db8::5/64", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, gw := staticIfaceGatewayAddress(tc.ip, tc.gateway, tc.netDef)
			if addr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tc.wantAddr)
			}
			if gw != tc.wantGw {
				t.Errorf("gw = %q, want %q", gw, tc.wantGw)
			}
		})
	}
}
