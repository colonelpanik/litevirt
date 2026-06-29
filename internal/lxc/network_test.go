package lxc

import (
	"strings"
	"testing"
)

// TestNetworkConfig_HappyPath checks the bridge + flags + IP rendering
// for a representative two-NIC container.
func TestNetworkConfig_HappyPath(t *testing.T) {
	got, err := NetworkConfig([]NetworkAttach{
		{Name: "eth0", Bridge: "br0", IP: "10.0.0.5/24", MAC: "aa:bb:cc:dd:ee:ff", Veth: "lvc0abc1234"},
		{Name: "eth1", Bridge: "vxlan-prod"},
	})
	if err != nil {
		t.Fatalf("NetworkConfig: %v", err)
	}
	mustContainAll(t, got,
		"lxc.net.0.type = veth",
		"lxc.net.0.link = br0",
		"lxc.net.0.flags = up",
		"lxc.net.0.name = eth0",
		"lxc.net.0.hwaddr = aa:bb:cc:dd:ee:ff",
		"lxc.net.0.veth.pair = lvc0abc1234",
		"lxc.net.0.ipv4.address = 10.0.0.5/24",
		"lxc.net.1.type = veth",
		"lxc.net.1.link = vxlan-prod",
		"lxc.net.1.name = eth1",
	)
	// eth1 has no MAC/IP, so those lines must NOT appear.
	if strings.Contains(got, "lxc.net.1.hwaddr") {
		t.Error("eth1 has no MAC; hwaddr line must not be emitted")
	}
}

// TestNetworkConfig_PreservesOrdinalOrder pins the contract that lxc.net.N
// follows the CALLER's order (not sorted by name): N must equal the NIC's
// ordinal, since the cluster interface rows + deterministic veth/MAC are keyed
// on ordinal. Same input → same output (deterministic); a NIC out of name order
// keeps its index.
func TestNetworkConfig_PreservesOrdinalOrder(t *testing.T) {
	got, err := NetworkConfig([]NetworkAttach{
		{Name: "ethX", Bridge: "br0"}, // index 0 despite not being name-first
		{Name: "ethA", Bridge: "br1"},
	})
	if err != nil {
		t.Fatalf("NetworkConfig: %v", err)
	}
	mustContainAll(t, got,
		"lxc.net.0.link = br0",
		"lxc.net.0.name = ethX",
		"lxc.net.1.link = br1",
		"lxc.net.1.name = ethA",
	)
}

// TestNetworkConfig_RejectsConfigInjection ensures a NIC field containing a
// newline can't forge extra lxc.* directives.
func TestNetworkConfig_RejectsConfigInjection(t *testing.T) {
	if _, err := NetworkConfig([]NetworkAttach{
		{Name: "eth0", Bridge: "br0\nlxc.net.0.script.up = /evil"},
	}); err == nil {
		t.Fatal("expected an error for a NIC field with an embedded newline")
	}
}

// TestResourceConfig_EmitsBothCgroupVersions is intentional cross-distro
// portability: writing only v1 or only v2 keys would silently break on
// the other family.
func TestResourceConfig_EmitsBothCgroupVersions(t *testing.T) {
	got := ResourceConfig(2, 512)
	mustContainAll(t, got,
		"cgroup2.cpu.max",
		"cgroup.cpu.shares",
		"cgroup2.memory.max",
		"cgroup.memory.limit_in_bytes",
		"512M",
	)
}

// TestResourceConfig_SkipsUnsetLimits guards against accidentally
// pinning containers to 0 CPU / 0 memory.
func TestResourceConfig_SkipsUnsetLimits(t *testing.T) {
	if got := ResourceConfig(0, 0); got != "" {
		t.Errorf("zero limits should emit nothing, got %q", got)
	}
	got := ResourceConfig(0, 1024)
	if strings.Contains(got, "cpu.max") {
		t.Error("CPU 0 should not emit cpu.max")
	}
	if !strings.Contains(got, "memory.max") {
		t.Error("memory>0 should still emit memory.max")
	}
}

// TestParseOCITag covers the registry-with-port edge cases that catch
// naive ":" splitting.
func TestParseOCITag(t *testing.T) {
	cases := map[string]string{
		"alpine":                            "latest",
		"alpine:3.19":                       "3.19",
		"docker.io/library/alpine:3.19":     "3.19",
		"registry.local:5000/team/img:v1":   "v1",
		"registry.local:5000/team/img":      "latest",
		"docker://registry.local:5000/x:v9": "v9",
	}
	for in, want := range cases {
		if got := parseOCITag(in); got != want {
			t.Errorf("parseOCITag(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustContainAll(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected to find %q in:\n%s", n, haystack)
		}
	}
}
