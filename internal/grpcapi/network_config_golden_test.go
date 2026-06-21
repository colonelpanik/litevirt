package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// Golden-file coverage for buildIsolatedNetworkConfig — the cloud-init
// network-config v1 emitter that drives every isolated-network NIC.
// vm_ipv6_test.go already covers the substring asserts (static / static6
// blocks, ordering); this pins the *full* rendered output so reordering,
// indentation, or key-name regressions don't slip through. Update with
// `go test./internal/grpcapi/ -run TestBuildIsolatedNetworkConfigGolden -update`.
func TestBuildIsolatedNetworkConfigGolden(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		ifaces []isolatedIface
	}{
		{
			name: "single_v4",
			path: "testdata/netconfig_v4.golden",
			ifaces: []isolatedIface{{
				MAC:     "aa:bb:cc:dd:ee:01",
				Address: "10.0.0.10/24",
				Gateway: "10.0.0.1",
				DNS:     []string{"1.1.1.1", "9.9.9.9"},
			}},
		},
		{
			name: "single_v6",
			path: "testdata/netconfig_v6.golden",
			ifaces: []isolatedIface{{
				MAC:      "aa:bb:cc:dd:ee:02",
				Address6: "2001:db8::10/64",
				Gateway6: "2001:db8::1",
			}},
		},
		{
			name: "dual_stack",
			path: "testdata/netconfig_dual_stack.golden",
			ifaces: []isolatedIface{{
				MAC:      "aa:bb:cc:dd:ee:03",
				Address:  "10.0.0.10/24",
				Gateway:  "10.0.0.1",
				DNS:      []string{"1.1.1.1"},
				Address6: "2001:db8::10/64",
				Gateway6: "2001:db8::1",
			}},
		},
		{
			name: "v6_slaac_no_gateway",
			path: "testdata/netconfig_v6_slaac.golden",
			ifaces: []isolatedIface{{
				MAC:      "aa:bb:cc:dd:ee:04",
				Address6: "2001:db8::20/64",
			}},
		},
		{
			name: "two_ifaces_dual_stack",
			path: "testdata/netconfig_two_ifaces.golden",
			ifaces: []isolatedIface{
				{
					MAC:     "aa:bb:cc:dd:ee:05",
					Address: "10.0.0.10/24",
					Gateway: "10.0.0.1",
					DNS:     []string{"1.1.1.1"},
				},
				{
					MAC:      "aa:bb:cc:dd:ee:06",
					Address6: "2001:db8::30/64",
					Gateway6: "2001:db8::1",
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildIsolatedNetworkConfig(tc.ifaces)
			golden.Assert(t, tc.path, got)
		})
	}
}
