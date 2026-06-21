package pci

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EnrichTopology fills PCIe topology fields (PCIeRootPort, PCIeBridge,
// LinkClique, LinkPeers) on each device by inspecting sysfs.
func EnrichTopology(devices []Device) {
	for i := range devices {
		devPath := filepath.Join(sysDevices, devices[i].Address)
		devices[i].PCIeBridge = discoverPCIeBridge(devPath)
		devices[i].PCIeRootPort = discoverPCIeRoot(devPath)
	}

	// Build address→index for fast lookups.
	addrIdx := make(map[string]int, len(devices))
	for i, d := range devices {
		addrIdx[d.Address] = i
	}

	// Discover NVLink/xGMI peers for GPU devices.
	for i := range devices {
		if devices[i].Type != "gpu" {
			continue
		}
		devPath := filepath.Join(sysDevices, devices[i].Address)
		clique, peers := discoverLinkPeers(devPath)
		devices[i].LinkClique = clique
		devices[i].LinkPeers = peers
	}

	// Propagate clique IDs: if a device lists peers but one peer discovered
	// its clique first, ensure they all share the same ID.
	for i := range devices {
		if devices[i].LinkClique == "" {
			continue
		}
		for _, peer := range devices[i].LinkPeers {
			if j, ok := addrIdx[peer]; ok && devices[j].LinkClique == "" {
				devices[j].LinkClique = devices[i].LinkClique
			}
		}
	}
}

// discoverPCIeBridge returns the PCI address of the immediate parent bridge.
// It resolves the sysfs device symlink and extracts the parent directory name.
// For example, if the real path is.../0000:00:01.0/0000:01:00.0, the parent
// bridge is "0000:00:01.0".
func discoverPCIeBridge(devPath string) string {
	real, err := filepath.EvalSymlinks(devPath)
	if err != nil {
		return ""
	}
	parent := filepath.Base(filepath.Dir(real))
	// Validate it looks like a PCI address (DDDD:BB:SS.F).
	if isPCIAddress(parent) {
		return parent
	}
	return ""
}

// discoverPCIeRoot walks the sysfs path upward from a device to find the
// root port — the topmost PCI bridge whose parent is a PCI domain host bridge
// (e.g. pci0000:00). Returns the PCI address of the root port, or "" if
// the hierarchy cannot be determined.
func discoverPCIeRoot(devPath string) string {
	real, err := filepath.EvalSymlinks(devPath)
	if err != nil {
		return ""
	}

	// Walk upward, collecting PCI bridge addresses until we hit a
	// non-PCI-address directory (the domain host bridge like "pci0000:00").
	var lastBridge string
	cur := real
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			break // reached filesystem root
		}
		name := filepath.Base(cur)
		parentName := filepath.Base(parent)

		if isPCIAddress(name) && !isPCIAddress(parentName) {
			// 'name' is the root port — its parent is the PCI domain.
			return name
		}
		if isPCIAddress(name) {
			lastBridge = name
		}
		cur = parent
	}
	return lastBridge
}

// discoverLinkPeers detects NVLink (NVIDIA) or xGMI (AMD) peer groups.
//
// NVIDIA: reads /sys/bus/pci/devices/<addr>/nvidia/gpu_link_peers
//
//	which contains space-separated PCI addresses of peer GPUs.
//
// AMD:    reads /sys/class/drm/cardN/device/xgmi_hive_id (same hive = same clique).
//
//	Since resolving cardN from a PCI address requires scanning drm/,
//	we check for an xgmi_hive_id under the device path itself.
//
// Returns (clique ID, peer addresses). Clique ID is the lexicographically
// smallest address in the peer group (including self) for NVIDIA, or the
// hive_id hex string for AMD.
func discoverLinkPeers(devPath string) (clique string, peers []string) {
	// Try NVIDIA NVLink.
	nvlinkPath := filepath.Join(devPath, "nvidia", "gpu_link_peers")
	if data, err := os.ReadFile(nvlinkPath); err == nil {
		raw := strings.TrimSpace(string(data))
		if raw != "" {
			peers = strings.Fields(raw)
			// Build clique ID from sorted set including self.
			self := filepath.Base(devPath)
			all := append([]string{self}, peers...)
			sort.Strings(all)
			return all[0], peers
		}
	}

	// Try AMD xGMI. The hive_id file may be directly under the device or
	// under the drm/cardN/device/ path.
	for _, rel := range []string{"xgmi_hive_id", "amdgpu/xgmi_hive_id"} {
		hivePath := filepath.Join(devPath, rel)
		if data, err := os.ReadFile(hivePath); err == nil {
			hiveID := strings.TrimSpace(string(data))
			if hiveID != "" && hiveID != "0" && hiveID != "0x0" {
				return hiveID, nil // peers discovered via shared hive ID
			}
		}
	}

	return "", nil
}

// isPCIAddress returns true if s looks like a PCI BDF address (DDDD:BB:SS.F).
func isPCIAddress(s string) bool {
	// Quick structural check: expect format like "0000:41:00.0" (12 or 13 chars).
	if len(s) < 10 {
		return false
	}
	// Must contain exactly two colons and one dot.
	colons := 0
	dots := 0
	for _, c := range s {
		switch c {
		case ':':
			colons++
		case '.':
			dots++
		default:
			if !isHexDigit(byte(c)) {
				return false
			}
		}
	}
	return colons == 2 && dots == 1
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
