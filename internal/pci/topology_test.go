package pci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPCIAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0000:41:00.0", true},
		{"0000:00:01.0", true},
		{"abcd:ef:01.2", true},
		{"pci0000:00", false},
		{"", false},
		{"short", false},
		{"0000:41:00", false},   // missing dot/function
		{"0000:41.00.0", false}, // wrong format
	}
	for _, tt := range tests {
		if got := isPCIAddress(tt.input); got != tt.want {
			t.Errorf("isPCIAddress(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDiscoverPCIeBridge(t *testing.T) {
	// Create a fake sysfs hierarchy:
	// tmp/pci0000:00/0000:00:01.0/0000:01:00.0
	tmp := t.TempDir()
	rootPort := filepath.Join(tmp, "pci0000:00", "0000:00:01.0")
	device := filepath.Join(rootPort, "0000:01:00.0")
	os.MkdirAll(device, 0755)

	// Create a symlink that resolves to the device path.
	link := filepath.Join(tmp, "devlink")
	os.Symlink(device, link)

	got := discoverPCIeBridge(link)
	if got != "0000:00:01.0" {
		t.Errorf("discoverPCIeBridge = %q, want 0000:00:01.0", got)
	}
}

func TestDiscoverPCIeBridge_NoBridge(t *testing.T) {
	// Device directly under PCI domain — no bridge.
	tmp := t.TempDir()
	device := filepath.Join(tmp, "pci0000:00", "0000:00:00.0")
	os.MkdirAll(device, 0755)

	link := filepath.Join(tmp, "devlink")
	os.Symlink(device, link)

	got := discoverPCIeBridge(link)
	if got != "" {
		t.Errorf("discoverPCIeBridge = %q, want empty (parent is pci domain)", got)
	}
}

func TestDiscoverPCIeRoot(t *testing.T) {
	// Hierarchy: tmp/pci0000:00/0000:00:01.0/0000:01:00.0/0000:02:00.0
	tmp := t.TempDir()
	rootPort := filepath.Join(tmp, "pci0000:00", "0000:00:01.0")
	bridge := filepath.Join(rootPort, "0000:01:00.0")
	device := filepath.Join(bridge, "0000:02:00.0")
	os.MkdirAll(device, 0755)

	link := filepath.Join(tmp, "devlink")
	os.Symlink(device, link)

	got := discoverPCIeRoot(link)
	if got != "0000:00:01.0" {
		t.Errorf("discoverPCIeRoot = %q, want 0000:00:01.0", got)
	}
}

func TestDiscoverPCIeRoot_DirectUnderDomain(t *testing.T) {
	// Device directly under PCI domain — it IS the root.
	tmp := t.TempDir()
	device := filepath.Join(tmp, "pci0000:00", "0000:00:00.0")
	os.MkdirAll(device, 0755)

	link := filepath.Join(tmp, "devlink")
	os.Symlink(device, link)

	got := discoverPCIeRoot(link)
	if got != "0000:00:00.0" {
		t.Errorf("discoverPCIeRoot = %q, want 0000:00:00.0", got)
	}
}

func TestDiscoverLinkPeers_NVLink(t *testing.T) {
	tmp := t.TempDir()
	devPath := filepath.Join(tmp, "0000:41:00.0")
	nvDir := filepath.Join(devPath, "nvidia")
	os.MkdirAll(nvDir, 0755)
	os.WriteFile(filepath.Join(nvDir, "gpu_link_peers"), []byte("0000:42:00.0 0000:43:00.0\n"), 0644)

	clique, peers := discoverLinkPeers(devPath)
	if clique != "0000:41:00.0" { // self is lexicographically smallest
		t.Errorf("clique = %q, want 0000:41:00.0", clique)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %v, want 2 entries", peers)
	}
}

func TestDiscoverLinkPeers_AMD_xGMI(t *testing.T) {
	tmp := t.TempDir()
	devPath := filepath.Join(tmp, "0000:41:00.0")
	os.MkdirAll(devPath, 0755)
	os.WriteFile(filepath.Join(devPath, "xgmi_hive_id"), []byte("0x1234abcd\n"), 0644)

	clique, peers := discoverLinkPeers(devPath)
	if clique != "0x1234abcd" {
		t.Errorf("clique = %q, want 0x1234abcd", clique)
	}
	// AMD xGMI doesn't list individual peers from this file.
	if len(peers) != 0 {
		t.Errorf("peers = %v, want empty", peers)
	}
}

func TestDiscoverLinkPeers_None(t *testing.T) {
	tmp := t.TempDir()
	devPath := filepath.Join(tmp, "0000:41:00.0")
	os.MkdirAll(devPath, 0755)

	clique, peers := discoverLinkPeers(devPath)
	if clique != "" {
		t.Errorf("clique = %q, want empty", clique)
	}
	if peers != nil {
		t.Errorf("peers = %v, want nil", peers)
	}
}

func TestDiscoverLinkPeers_xGMI_ZeroHive(t *testing.T) {
	tmp := t.TempDir()
	devPath := filepath.Join(tmp, "0000:41:00.0")
	os.MkdirAll(devPath, 0755)
	// hive_id of 0 means xGMI is not active.
	os.WriteFile(filepath.Join(devPath, "xgmi_hive_id"), []byte("0\n"), 0644)

	clique, _ := discoverLinkPeers(devPath)
	if clique != "" {
		t.Errorf("clique = %q, want empty for hive_id 0", clique)
	}
}

func TestEnrichTopology_PropagatesClique(t *testing.T) {
	// Create fake sysfs structure for two GPUs with NVLink peers.
	tmp := t.TempDir()

	// GPU A: 0000:41:00.0 — lists GPU B as NVLink peer
	gpuA := filepath.Join(tmp, "pci0000:00", "0000:00:01.0", "0000:41:00.0")
	os.MkdirAll(filepath.Join(gpuA, "nvidia"), 0755)
	os.WriteFile(filepath.Join(gpuA, "nvidia", "gpu_link_peers"), []byte("0000:42:00.0\n"), 0644)

	// GPU B: 0000:42:00.0 — no nvidia dir (might not expose peers file)
	gpuB := filepath.Join(tmp, "pci0000:00", "0000:00:02.0", "0000:42:00.0")
	os.MkdirAll(gpuB, 0755)

	// Create symlinks as sysDevices would have them.
	sysDir := filepath.Join(tmp, "sys_devices")
	os.MkdirAll(sysDir, 0755)
	os.Symlink(gpuA, filepath.Join(sysDir, "0000:41:00.0"))
	os.Symlink(gpuB, filepath.Join(sysDir, "0000:42:00.0"))

	// Temporarily override sysDevices for the test.
	origSysDevices := sysDevices
	sysDevices = sysDir
	defer func() { sysDevices = origSysDevices }()

	devices := []Device{
		{Address: "0000:41:00.0", Type: "gpu"},
		{Address: "0000:42:00.0", Type: "gpu"},
	}

	EnrichTopology(devices)

	// GPU A should have clique and peers.
	if devices[0].LinkClique == "" {
		t.Error("GPU A should have a clique ID")
	}
	// GPU B should have the same clique propagated from GPU A.
	if devices[1].LinkClique != devices[0].LinkClique {
		t.Errorf("GPU B clique %q != GPU A clique %q", devices[1].LinkClique, devices[0].LinkClique)
	}
}

func TestEnrichTopology_NonGPU_NoLinkPeers(t *testing.T) {
	tmp := t.TempDir()

	nic := filepath.Join(tmp, "pci0000:00", "0000:00:03.0", "0000:03:00.0")
	os.MkdirAll(nic, 0755)

	sysDir := filepath.Join(tmp, "sys_devices")
	os.MkdirAll(sysDir, 0755)
	os.Symlink(nic, filepath.Join(sysDir, "0000:03:00.0"))

	origSysDevices := sysDevices
	sysDevices = sysDir
	defer func() { sysDevices = origSysDevices }()

	devices := []Device{
		{Address: "0000:03:00.0", Type: "network"},
	}

	EnrichTopology(devices)

	if devices[0].LinkClique != "" {
		t.Errorf("NIC should not have a clique, got %q", devices[0].LinkClique)
	}
	if devices[0].LinkPeers != nil {
		t.Errorf("NIC should not have link peers, got %v", devices[0].LinkPeers)
	}
}
