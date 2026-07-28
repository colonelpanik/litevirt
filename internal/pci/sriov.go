package pci

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CreateVFs creates a VF pool of `count` VFs on an EMPTY PF and returns the PCI
// addresses of the created VFs. litevirt only ever creates a pool on an empty PF — it
// never grows an existing pool — so a non-empty PF is refused. A short create (the
// kernel produced fewer VFs than requested) is a FAILURE: it returns the partial pool
// alongside a structured error and does NOT auto-zero (the caller rescans + marks the
// host degraded rather than silently succeeding on a truncated pool).
func CreateVFs(pfAddress string, count int) ([]string, error) {
	devPath := filepath.Join(sysDevices, pfAddress)

	// Check SR-IOV capability.
	totalPath := filepath.Join(devPath, "sriov_totalvfs")
	if _, err := os.Stat(totalPath); err != nil {
		return nil, fmt.Errorf("device %s is not SR-IOV capable", pfAddress)
	}

	totalVFs := readSysInt(totalPath)
	currentVFs := readSysInt(filepath.Join(devPath, "sriov_numvfs"))
	if currentVFs != 0 {
		return nil, fmt.Errorf("PF %s: refusing to create VFs on a non-empty pool (sriov_numvfs=%d); litevirt only creates a pool on an empty PF and never resizes one",
			pfAddress, currentVFs)
	}
	if count > totalVFs {
		return nil, fmt.Errorf("PF %s: requested %d VFs but hardware maximum is %d", pfAddress, count, totalVFs)
	}

	// Write the VF count (pool creation on an empty PF).
	numvfsPath := filepath.Join(devPath, "sriov_numvfs")
	if err := os.WriteFile(numvfsPath, []byte(strconv.Itoa(count)), 0200); err != nil {
		return nil, fmt.Errorf("write sriov_numvfs for %s: %w", pfAddress, err)
	}

	// Wait briefly for the kernel to create the new VF devices.
	time.Sleep(500 * time.Millisecond)

	newVFs := listVFAddresses(devPath)
	if len(newVFs) < count {
		// Retain the partial pool (no auto-zero) and fail with structured detail.
		slog.Error("SR-IOV short VF creation", "pf", pfAddress, "requested", count, "got", len(newVFs))
		return newVFs, fmt.Errorf("PF %s: short VF creation — requested %d, got %d", pfAddress, count, len(newVFs))
	}

	slog.Info("SR-IOV VF pool created", "pf", pfAddress, "vfs", len(newVFs))
	return newVFs, nil
}

// DestroyVFs sets sriov_numvfs to 0, removing all VFs from a PF.
func DestroyVFs(pfAddress string) error {
	numvfsPath := filepath.Join(sysDevices, pfAddress, "sriov_numvfs")
	if err := os.WriteFile(numvfsPath, []byte("0"), 0200); err != nil {
		return fmt.Errorf("reset sriov_numvfs for %s: %w", pfAddress, err)
	}
	slog.Info("SR-IOV VFs destroyed", "pf", pfAddress)
	return nil
}

// ListVFs returns the PCI addresses of all VFs for a given PF address.
func ListVFs(pfAddress string) ([]string, error) {
	devPath := filepath.Join(sysDevices, pfAddress)
	addrs := listVFAddresses(devPath)
	return addrs, nil
}

// listVFAddresses reads the virtfnN symlinks under a PF's sysfs directory
// and returns the PCI addresses of all current VFs.
func listVFAddresses(pfDevPath string) []string {
	entries, err := os.ReadDir(pfDevPath)
	if err != nil {
		return nil
	}
	var addrs []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "virtfn") {
			continue
		}
		link, err := os.Readlink(filepath.Join(pfDevPath, e.Name()))
		if err != nil {
			continue
		}
		// link is relative like "../0000:41:00.1"
		addrs = append(addrs, filepath.Base(link))
	}
	return addrs
}

// ScanDevice reads sysfs for a single PCI device and returns its info.
func ScanDevice(address string) (Device, error) {
	devPath := filepath.Join(sysDevices, address)
	if _, err := os.Stat(devPath); err != nil {
		return Device{}, fmt.Errorf("device %s not found in sysfs", address)
	}

	d := Device{Address: address}
	d.VendorID = readSysTrimmed(filepath.Join(devPath, "vendor"))
	d.DeviceID = readSysTrimmed(filepath.Join(devPath, "device"))
	d.Driver = readDriverName(devPath)
	d.NUMANode = readSysInt(filepath.Join(devPath, "numa_node"))
	d.IOMMUGroup = readIOMMUGroup(devPath)
	d.Type = classifyDevice(devPath, d.VendorID)
	d.VendorName = readVendorName(devPath, d.VendorID)
	d.DeviceName = readDeviceName(devPath, d.DeviceID)

	if _, err := os.Stat(filepath.Join(devPath, "sriov_totalvfs")); err == nil {
		d.SRIOVCapable = true
		d.SRIOVVFsTotal = readSysInt(filepath.Join(devPath, "sriov_totalvfs"))
		d.SRIOVVFsFree = d.SRIOVVFsTotal - readSysInt(filepath.Join(devPath, "sriov_numvfs"))
		if d.SRIOVVFsFree < 0 {
			d.SRIOVVFsFree = 0
		}
	}

	return d, nil
}
