// Package pci discovers and classifies PCI devices on the host.
// It reads from /sys/bus/pci/devices/ and /sys/kernel/iommu_groups/.
package pci

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Device represents a discovered PCI device.
type Device struct {
	Address    string // "0000:41:00.0"
	VendorID   string // "10de"
	DeviceID   string // "2236"
	VendorName string // resolved from pci.ids or /sys
	DeviceName string // resolved from pci.ids or /sys
	Type       string // gpu | network | nvme | infiniband | other
	IOMMUGroup int    // -1 if not available
	Driver     string // current bound driver (e.g. "nvidia", "vfio-pci")
	NUMANode   int

	// PCIe topology
	PCIeRootPort string   // root port ancestor address (e.g. "0000:00:01.0")
	PCIeBridge   string   // immediate parent bridge address
	LinkClique   string   // NVLink/xGMI peer group ID (empty if none)
	LinkPeers    []string // PCI addresses of peer GPUs in the same clique

	// SR-IOV
	SRIOVCapable  bool
	SRIOVVFsTotal int
	SRIOVVFsFree  int
}

var sysDevices = "/sys/bus/pci/devices"

// Scan enumerates all PCI devices on the host.
func Scan() ([]Device, error) {
	entries, err := os.ReadDir(sysDevices)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", sysDevices, err)
	}

	var devices []Device
	for _, e := range entries {
		addr := e.Name()
		devPath := filepath.Join(sysDevices, addr)
		d := Device{Address: addr}

		d.VendorID = readSysTrimmed(filepath.Join(devPath, "vendor"))
		d.DeviceID = readSysTrimmed(filepath.Join(devPath, "device"))
		d.Driver = readDriverName(devPath)
		d.NUMANode = readSysInt(filepath.Join(devPath, "numa_node"))
		d.IOMMUGroup = readIOMMUGroup(devPath)
		d.Type = classifyDevice(devPath, d.VendorID)

		// Resolve human-readable names from /sys (kernel exposes in some cases).
		d.VendorName = readVendorName(devPath, d.VendorID)
		d.DeviceName = readDeviceName(devPath, d.DeviceID)

		// SR-IOV detection.
		if _, err := os.Stat(filepath.Join(devPath, "sriov_totalvfs")); err == nil {
			d.SRIOVCapable = true
			d.SRIOVVFsTotal = readSysInt(filepath.Join(devPath, "sriov_totalvfs"))
			d.SRIOVVFsFree = d.SRIOVVFsTotal - readSysInt(filepath.Join(devPath, "sriov_numvfs"))
			if d.SRIOVVFsFree < 0 {
				d.SRIOVVFsFree = 0
			}
		}

		devices = append(devices, d)
	}

	// Enrich devices with PCIe topology information.
	EnrichTopology(devices)

	slog.Info("PCI scan complete", "devices", len(devices))
	return devices, nil
}

// FilterInteresting returns only devices likely relevant for passthrough
// (GPUs, network, NVMe, InfiniBand) — excludes bridges, ISA, etc.
func FilterInteresting(devices []Device) []Device {
	var result []Device
	for _, d := range devices {
		if d.Type != "other" {
			result = append(result, d)
		}
	}
	return result
}

// IOMMUGroupMembers returns all PCI addresses sharing the same IOMMU group.
func IOMMUGroupMembers(group int) ([]string, error) {
	if group < 0 {
		return nil, nil
	}
	groupPath := fmt.Sprintf("/sys/kernel/iommu_groups/%d/devices", group)
	entries, err := os.ReadDir(groupPath)
	if err != nil {
		return nil, fmt.Errorf("read IOMMU group %d: %w", group, err)
	}
	addrs := make([]string, len(entries))
	for i, e := range entries {
		addrs[i] = e.Name()
	}
	return addrs, nil
}

// classifyDevice determines the device type from its PCI class code.
func classifyDevice(devPath, vendorID string) string {
	classStr := readSysTrimmed(filepath.Join(devPath, "class"))
	if classStr == "" {
		return "other"
	}
	// PCI class code: 0xCCSSPP (class, subclass, prog-if)
	classCode, err := strconv.ParseUint(strings.TrimPrefix(classStr, "0x"), 16, 32)
	if err != nil {
		return "other"
	}
	classTop := (classCode >> 16) & 0xFF
	subClass := (classCode >> 8) & 0xFF

	switch classTop {
	case 0x03: // Display controller
		return "gpu"
	case 0x02: // Network controller
		return "network"
	case 0x01: // Mass storage
		if subClass == 0x08 { // NVM Express
			return "nvme"
		}
		return "other"
	case 0x0C: // Serial bus
		if subClass == 0x06 { // InfiniBand
			return "infiniband"
		}
		return "other"
	default:
		// Some InfiniBand HCAs show up as network devices with Mellanox vendor.
		if classTop == 0x02 && (vendorID == "0x15b3" || vendorID == "15b3") {
			return "network" // Mellanox — could be IB or Ethernet, classify as network
		}
		return "other"
	}
}

func readSysTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(string(data), "0x"))
}

func readSysInt(path string) int {
	s := readSysTrimmed(path)
	n, _ := strconv.Atoi(s)
	return n
}

func readDriverName(devPath string) string {
	link, err := os.Readlink(filepath.Join(devPath, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

func readIOMMUGroup(devPath string) int {
	link, err := os.Readlink(filepath.Join(devPath, "iommu_group"))
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(filepath.Base(link))
	if err != nil {
		return -1
	}
	return n
}

func readVendorName(devPath, vendorID string) string {
	// Try the kernel-exposed label file if available (some drivers provide it).
	if name := readSysTrimmed(filepath.Join(devPath, "label")); name != "" {
		return name
	}
	// Fallback: use vendor ID as name. Real resolution from pci.ids would
	// require shipping or parsing the database — keep it simple.
	return vendorID
}

func readDeviceName(devPath, deviceID string) string {
	return deviceID
}
