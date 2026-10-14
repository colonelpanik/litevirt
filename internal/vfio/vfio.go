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

	// driversProbePath asks the PCI core to probe an unbound device against every
	// driver; a set driver_override restricts that probe to the named driver.
	driversProbePath = "/sys/bus/pci/drivers_probe"

	// clearOverride is the value that clears a device's driver_override: a lone
	// newline, which is what `echo > driver_override` writes. A ZERO-LENGTH write
	// does not clear it: sysfs_kf_write returns before the attribute's store runs
	// when count is 0, so the override stays set and the next probe hands the
	// device straight back to vfio-pci.
	clearOverride = "\n"
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
//
// It claims the device through driver_override alone. It never writes vfio-pci's
// new_id: that adds a dynamic vendor:device match to the driver, so every OTHER
// device with the same ID (the sibling VFs of an SR-IOV NIC) becomes claimable by
// vfio-pci on its next probe, and Unbind has no remove_id it could safely write
// (the same dynamic ID can come from the operator's vfio-pci.ids=). With the
// override set, vfio-pci's bind matches the device without any ID table entry.
//
// If the bind cannot be verified, Bind puts the device back: the override is
// cleared and the previous driver rebound (or the device reprobed), so a failed
// bind does not leave a driverless device that the next probe hands to vfio-pci.
func Bind(address string) (previousDriver string, err error) {
	devPath := filepath.Join(sysDevices, address)

	// Read current driver.
	previousDriver, err = currentDriver(devPath)
	if err != nil {
		return "", fmt.Errorf("read the driver of %s: %w", address, err)
	}
	if previousDriver == "vfio-pci" {
		slog.Debug("device already bound to vfio-pci", "address", address)
		return previousDriver, nil
	}

	// The device must exist before anything is changed.
	vendorID := readTrimmed(filepath.Join(devPath, "vendor"))
	deviceID := readTrimmed(filepath.Join(devPath, "device"))
	if vendorID == "" || deviceID == "" {
		return "", fmt.Errorf("cannot read vendor/device for %s", address)
	}

	if previousDriver != "" {
		unbindPath := filepath.Join(devPath, "driver", "unbind")
		if err := sysfs.WriteFile(unbindPath, []byte(address), 0200); err != nil {
			return "", fmt.Errorf("unbind %s from %s: %w", address, previousDriver, err)
		}
		slog.Info("unbound device from driver", "address", address, "driver", previousDriver)
	}

	// From here on the device has left its previous driver; a failure restores it.
	fail := func(err error) (string, error) {
		if rerr := restoreAfterFailedBind(devPath, address, previousDriver); rerr != nil {
			return "", fmt.Errorf("%w (returning %s to its previous driver also failed: %v)", err, address, rerr)
		}
		return "", err
	}

	// driver_override makes vfio-pci, and only vfio-pci, able to claim the device.
	overridePath := filepath.Join(devPath, "driver_override")
	if err := sysfs.WriteFile(overridePath, []byte("vfio-pci"), 0200); err != nil {
		return fail(fmt.Errorf("set driver_override for %s: %w", address, err))
	}

	// Bind to vfio-pci, or reprobe (the override steers the probe to vfio-pci).
	bindPath := filepath.Join(vfioDriverPath, "bind")
	if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err != nil {
		if err2 := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err2 != nil {
			return fail(fmt.Errorf("bind %s to vfio-pci: %w (probe also failed: %v)", address, err, err2))
		}
	}

	// Verify binding took effect.
	final, verifyErr := currentDriver(devPath)
	if verifyErr != nil || final != "vfio-pci" {
		if verifyErr != nil || final == "" {
			final = "none"
		}
		return fail(fmt.Errorf("bind %s: verification failed — driver is %q, expected vfio-pci", address, final))
	}

	slog.Info("device bound to vfio-pci", "address", address, "previous", previousDriver)
	return previousDriver, nil
}

// restoreAfterFailedBind undoes a Bind that did not reach vfio-pci: it clears the
// override and returns a driverless device to previousDriver, or reprobes it when
// it had none or that bind fails.
func restoreAfterFailedBind(devPath, address, previousDriver string) error {
	if err := clearDriverOverride(devPath, address); err != nil {
		return err
	}
	cur, err := currentDriver(devPath)
	if err != nil {
		return err
	}
	if cur != "" {
		return nil // something bound it already
	}
	if previousDriver != "" {
		bindPath := filepath.Join("/sys/bus/pci/drivers", previousDriver, "bind")
		if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err == nil {
			return nil
		}
	}
	return sysfs.WriteFile(driversProbePath, []byte(address), 0200)
}

// Unbind removes a device from vfio-pci and returns it to a host driver.
//
// Each step is checked against what the kernel reports back:
//
//  1. Clear driver_override (with "\n", see clearOverride) and read it back. If it
//     is still set, stop with the device still on vfio-pci: unbinding now would
//     only have the next probe re-claim it for vfio-pci.
//  2. Unbind from vfio-pci.
//  3. Bind restoreDriver explicitly, falling back to drivers_probe. With no usable
//     restoreDriver ("", or "vfio-pci", which is what the inventory records once a
//     rescan has seen the device bound) reprobe and let the kernel pick.
//  4. Read the driver back. Still vfio-pci is an error. NO driver is an error when
//     a host driver was named: the device was released but not returned to it.
//     With none named, a driverless device is accepted, because a host with no
//     driver for it (a passthrough-only GPU, its driver blacklisted) never had one.
func Unbind(address, restoreDriver string) error {
	devPath := filepath.Join(sysDevices, address)

	current, err := currentDriver(devPath)
	if err != nil {
		return fmt.Errorf("read the driver of %s: %w", address, err)
	}

	// 1. Clear the override and prove it cleared, before the binding changes.
	if err := clearDriverOverride(devPath, address); err != nil {
		return err
	}
	if current != "" && current != "vfio-pci" {
		return nil // on a host driver already; with the override gone, nothing to release
	}

	// 2. Unbind from vfio-pci.
	if current == "vfio-pci" {
		unbindPath := filepath.Join(devPath, "driver", "unbind")
		if err := sysfs.WriteFile(unbindPath, []byte(address), 0200); err != nil {
			return fmt.Errorf("unbind %s from vfio-pci: %w", address, err)
		}
	}

	// 3. Return the device to a host driver.
	want := restoreDriver
	if want == "vfio-pci" {
		want = ""
	}
	if want != "" {
		bindPath := filepath.Join("/sys/bus/pci/drivers", want, "bind")
		if err := sysfs.WriteFile(bindPath, []byte(address), 0200); err != nil {
			// Fallback to generic probe.
			if err2 := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err2 != nil {
				return fmt.Errorf("restore %s to driver %s: bind failed: %v, probe also failed: %w",
					address, want, err, err2)
			}
		}
	} else if err := sysfs.WriteFile(driversProbePath, []byte(address), 0200); err != nil {
		return fmt.Errorf("reprobe %s: %w", address, err)
	}

	// 4. Verify where the device ended up.
	final, err := currentDriver(devPath)
	if err != nil {
		return fmt.Errorf("unbind %s: cannot read the driver back: %w", address, err)
	}
	switch {
	case final == "vfio-pci":
		return fmt.Errorf("unbind %s: verification failed — still bound to vfio-pci", address)
	case final == "" && want != "":
		return fmt.Errorf("unbind %s: verification failed — released from vfio-pci but left with no driver (%s did not bind and a reprobe found none)", address, want)
	case final == "":
		slog.Warn("device released from vfio-pci; no host driver claimed it", "address", address)
	case want != "" && final != want:
		slog.Warn("device released from vfio-pci to a different host driver", "address", address, "driver", final, "wanted", want)
	default:
		slog.Info("device restored to host driver", "address", address, "driver", final)
	}
	return nil
}

// clearDriverOverride clears devPath's driver_override and reads it back, failing
// while the kernel still reports an override. The kernel shows a cleared one as
// "(null)".
func clearDriverOverride(devPath, address string) error {
	overridePath := filepath.Join(devPath, "driver_override")
	if err := sysfs.WriteFile(overridePath, []byte(clearOverride), 0200); err != nil {
		return fmt.Errorf("clear driver_override for %s: %w", address, err)
	}
	data, err := sysfs.ReadFile(overridePath)
	if err != nil {
		return fmt.Errorf("clear driver_override for %s: cannot read it back: %w", address, err)
	}
	if v := strings.TrimSpace(string(data)); v != "" && v != "(null)" {
		return fmt.Errorf("clear driver_override for %s: still %q after the clear; not unbinding, the next probe would bind %s again", address, v, v)
	}
	return nil
}

// currentDriver returns the name of the driver bound to the device at devPath, or
// "" when none is. Only a not-exist error means "no driver"; any other error is
// returned, so a caller fails closed rather than assume the device is unbound.
func currentDriver(devPath string) (string, error) {
	link, err := sysfs.Readlink(filepath.Join(devPath, "driver"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(link), nil
}

// IsBoundToVFIO reports whether the PCI device at address is CURRENTLY bound to the
// vfio-pci driver, read from the device's driver symlink. This is the GROUND-TRUTH
// "is this device claimed by vfio right now" signal — as opposed to inferring
// boundness from bookkeeping such as vm_pci_realizations rows, which can lie after a
// crash or a rollback that tombstoned the rows while retaining the binding. It mirrors
// the readlink pattern Bind/Unbind use: bound iff the driver link's basename is
// "vfio-pci". A device with NO driver bound (the link is absent → a not-exist error)
// is reported false, nil; an UNEXPECTED filesystem error (anything other than
// not-exist) is returned so a caller can fail closed rather than assume "unbound".
func IsBoundToVFIO(address string) (bool, error) {
	link, err := sysfs.Readlink(filepath.Join(sysDevices, address, "driver"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return filepath.Base(link) == "vfio-pci", nil
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
