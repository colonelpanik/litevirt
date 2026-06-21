// Package vfio manages binding and unbinding PCI devices to/from the vfio-pci driver.
package vfio

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const (
	sysDevices     = "/sys/bus/pci/devices"
	vfioDriverPath = "/sys/bus/pci/drivers/vfio-pci"
)

// SysFS abstracts sysfs filesystem operations for testability.
type SysFS interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	Readlink(path string) (string, error)
	ReadDir(path string) ([]os.DirEntry, error)
}

type realFS struct{}

func (realFS) ReadFile(path string) ([]byte, error)                      { return os.ReadFile(path) }
func (realFS) WriteFile(path string, d []byte, p os.FileMode) error      { return os.WriteFile(path, d, p) }
func (realFS) Readlink(path string) (string, error)                      { return os.Readlink(path) }
func (realFS) ReadDir(path string) ([]os.DirEntry, error)                { return os.ReadDir(path) }

var sysfs SysFS = realFS{}

// SetFS replaces the filesystem implementation (for testing). Returns a restore function.
func SetFS(f SysFS) func() {
	old := sysfs
	sysfs = f
	return func() { sysfs = old }
}

// Bind unbinds a PCI device from its current driver and binds it to vfio-pci.
// Returns the name of the previous driver so it can be restored later.
func Bind(address string) (previousDriver string, err error) {
	devPath := filepath.Join(sysDevices, address)

	// Read current driver.
	driverLink, err := sysfs.Readlink(filepath.Join(devPath, "driver"))
	if err == nil {
		previousDriver = filepath.Base(driverLink)
		if previousDriver == "vfio-pci" {
			slog.Debug("device already bound to vfio-pci", "address", address)
			return previousDriver, nil
		}

		// Unbind from current driver.
		unbindPath := filepath.Join(devPath, "driver", "unbind")
		if err := sysfs.WriteFile(unbindPath, []byte(address), 0200); err != nil {
			return "", fmt.Errorf("unbind %s from %s: %w", address, previousDriver, err)
		}
		slog.Info("unbound device from driver", "address", address, "driver", previousDriver)
	}

	// Read vendor:device ID for driver_override.
	vendorID := readTrimmed(filepath.Join(devPath, "vendor"))
	deviceID := readTrimmed(filepath.Join(devPath, "device"))
	if vendorID == "" || deviceID == "" {
		return "", fmt.Errorf("cannot read vendor/device for %s", address)
	}

	// Write driver_override to ensure vfio-pci claims this device.
	overridePath := filepath.Join(devPath, "driver_override")
	if err := sysfs.WriteFile(overridePath, []byte("vfio-pci"), 0200); err != nil {
		return "", fmt.Errorf("set driver_override for %s: %w", address, err)
	}

	// Trigger vfio-pci bind via new_id or probe.
	newIDPath := filepath.Join(vfioDriverPath, "new_id")
	idStr := fmt.Sprintf("%s %s", vendorID, deviceID)
	// Writing new_id may fail if already known — that's fine.
	sysfs.WriteFile(newIDPath, []byte(idStr), 0200)

	// Probe the device.
	probePath := filepath.Join(vfioDriverPath, "bind")
	if err := sysfs.WriteFile(probePath, []byte(address), 0200); err != nil {
		// Try the general reprobe path.
		driversProbePath := "/sys/bus/pci/drivers_probe"
		if err2 := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err2 != nil {
			return "", fmt.Errorf("bind %s to vfio-pci: %w (probe also failed: %v)", address, err, err2)
		}
	}

	// Verify binding took effect.
	verifyLink, verifyErr := sysfs.Readlink(filepath.Join(devPath, "driver"))
	if verifyErr != nil || filepath.Base(verifyLink) != "vfio-pci" {
		actual := filepath.Base(verifyLink)
		if verifyErr != nil {
			actual = "none"
		}
		return "", fmt.Errorf("bind %s: verification failed — driver is %q, expected vfio-pci", address, actual)
	}

	slog.Info("device bound to vfio-pci", "address", address, "previous", previousDriver)
	return previousDriver, nil
}

// Unbind removes a device from vfio-pci and optionally restores the original driver.
func Unbind(address, restoreDriver string) error {
	devPath := filepath.Join(sysDevices, address)

	// Check current driver.
	driverLink, err := sysfs.Readlink(filepath.Join(devPath, "driver"))
	if err == nil {
		currentDriver := filepath.Base(driverLink)
		if currentDriver == "vfio-pci" {
			unbindPath := filepath.Join(devPath, "driver", "unbind")
			if err := sysfs.WriteFile(unbindPath, []byte(address), 0200); err != nil {
				return fmt.Errorf("unbind %s from vfio-pci: %w", address, err)
			}
		}
	}

	// Clear driver_override.
	overridePath := filepath.Join(devPath, "driver_override")
	if err := sysfs.WriteFile(overridePath, []byte(""), 0200); err != nil {
		return fmt.Errorf("clear driver_override for %s: %w", address, err)
	}

	// Restore original driver if specified.
	if restoreDriver != "" && restoreDriver != "vfio-pci" {
		bindPath := filepath.Join("/sys/bus/pci/drivers", restoreDriver, "bind")
		if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err != nil {
			// Fallback to generic probe.
			if err2 := sysfs.WriteFile("/sys/bus/pci/drivers_probe", []byte(address), 0200); err2 != nil {
				return fmt.Errorf("restore %s to driver %s: bind failed: %v, probe also failed: %w",
					address, restoreDriver, err, err2)
			}
		}
		slog.Info("device restored to original driver", "address", address, "driver", restoreDriver)
	} else {
		// Just reprobe to let the kernel find the right driver.
		if err := sysfs.WriteFile("/sys/bus/pci/drivers_probe", []byte(address), 0200); err != nil {
			return fmt.Errorf("reprobe %s: %w", address, err)
		}
	}

	// Verify device is no longer bound to vfio-pci.
	if verifyLink, err := sysfs.Readlink(filepath.Join(devPath, "driver")); err == nil {
		if filepath.Base(verifyLink) == "vfio-pci" {
			return fmt.Errorf("unbind %s: verification failed — still bound to vfio-pci", address)
		}
	}

	return nil
}

// IsVF returns true if the PCI device at the given address is an SR-IOV Virtual Function.
// VFs have a "physfn" symlink pointing to their parent Physical Function.
func IsVF(address string) bool {
	_, err := sysfs.Readlink(filepath.Join(sysDevices, address, "physfn"))
	return err == nil
}

// IsIOMMUEnabled checks if IOMMU is available on the host.
func IsIOMMUEnabled() bool {
	entries, err := sysfs.ReadDir("/sys/kernel/iommu_groups")
	if err != nil {
		return false
	}
	return len(entries) > 0
}

func readTrimmed(path string) string {
	data, err := sysfs.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
