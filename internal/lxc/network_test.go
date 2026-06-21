package lxc

import (
	"strings"
	"testing"
)

// TestNetworkConfig_HappyPath checks the bridge + flags + IP rendering
// for a representative two-NIC container.
func TestNetworkConfig_HappyPath(t *testing.T) {
	got := NetworkConfig([]NetworkAttach{
		{Name: "eth0", Bridge: "br0", IP: "10.0.0.5/24", MAC: "aa:bb:cc:dd:ee:ff"},
		{Name: "eth1", Bridge: "vxlan-prod"},
	})
	mustContainAll(t, got,
		"lxc.net.0.type = veth",
		"lxc.net.0.link = br0",
		"lxc.net.0.flags = up",
		"lxc.net.0.name = eth0",
		"lxc.net.0.hwaddr = aa:bb:cc:dd:ee:ff",
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

// TestNetworkConfig_StableOrdering ensures two equivalent inputs render
// identically — important for diff-friendly config files.
func TestNetworkConfig_StableOrdering(t *testing.T) {
	a := NetworkConfig([]NetworkAttach{
		{Name: "eth1", Bridge: "br1"},
		{Name: "eth0", Bridge: "br0"},
	})
	b := NetworkConfig([]NetworkAttach{
		{Name: "eth0", Bridge: "br0"},
		{Name: "eth1", Bridge: "br1"},
	})
	if a != b {
		t.Errorf("non-deterministic ordering:\nA=%s\nB=%s", a, b)
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
