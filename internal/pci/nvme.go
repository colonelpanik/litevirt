package pci

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NVMeNamespace represents an NVMe namespace discovered via sysfs.
type NVMeNamespace struct {
	Controller string // e.g. "nvme0"
	NSID       int    // namespace ID
	PCIAddress string // PCI address of the NVMe controller
	SizeBytes  int64  // namespace size
	State      string // "live" or "dead"
}

// nvmeClassPath is the sysfs path for NVMe controllers. Variable for testing.
var nvmeClassPath = "/sys/class/nvme"

// ScanNVMeNamespaces discovers all NVMe namespaces on the host.
func ScanNVMeNamespaces() ([]NVMeNamespace, error) {
	controllers, err := os.ReadDir(nvmeClassPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read nvme class: %w", err)
	}

	var namespaces []NVMeNamespace
	for _, ctrl := range controllers {
		if !strings.HasPrefix(ctrl.Name(), "nvme") {
			continue
		}
		ctrlName := ctrl.Name()
		pciAddr := nvmeControllerPCIAddress(ctrlName)

		// Enumerate namespaces: /sys/class/nvme/nvmeN/nvmeNnM
		ctrlPath := filepath.Join(nvmeClassPath, ctrlName)
		entries, err := os.ReadDir(ctrlPath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// Namespace directories match pattern: nvmeNnM
			if !strings.HasPrefix(e.Name(), ctrlName+"n") {
				continue
			}
			nsidStr := strings.TrimPrefix(e.Name(), ctrlName+"n")
			nsid, err := strconv.Atoi(nsidStr)
			if err != nil {
				continue
			}

			nsPath := filepath.Join(ctrlPath, e.Name())
			ns := NVMeNamespace{
				Controller: ctrlName,
				NSID:       nsid,
				PCIAddress: pciAddr,
				SizeBytes:  readNVMeSize(nsPath),
				State:      readNVMeState(nsPath),
			}
			namespaces = append(namespaces, ns)
		}
	}
	return namespaces, nil
}

// nvmeControllerPCIAddress resolves the PCI address for an NVMe controller
// by reading the device symlink.
func nvmeControllerPCIAddress(ctrlName string) string {
	deviceLink := filepath.Join(nvmeClassPath, ctrlName, "device")
	resolved, err := filepath.EvalSymlinks(deviceLink)
	if err != nil {
		return ""
	}
	// The resolved path ends with the PCI address, e.g..../0000:03:00.0
	base := filepath.Base(resolved)
	if isPCIAddress(base) {
		return base
	}
	return ""
}

// readNVMeSize reads the namespace size from the size file (in 512-byte blocks).
func readNVMeSize(nsPath string) int64 {
	data, err := os.ReadFile(filepath.Join(nsPath, "size"))
	if err != nil {
		return 0
	}
	blocks, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return blocks * 512
}

// readNVMeState reads the namespace state (e.g. "live", "dead").
func readNVMeState(nsPath string) string {
	data, err := os.ReadFile(filepath.Join(nsPath, "state"))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
