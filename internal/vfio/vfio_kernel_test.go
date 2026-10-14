package vfio

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// kernelFS models how the PCI core answers the sysfs writes Bind and Unbind make,
// for one device. memFS only records a write; kernelFS applies it the way the
// kernel does, which is what the lab caught Unbind getting wrong (V1, igb VF on
// kernel 6.8):
//
//   - driver_override: a ZERO-LENGTH write is a no-op (sysfs_kf_write returns
//     before the store runs when count is 0). Otherwise the value up to the first
//     newline is the override, and an empty one clears it. A cleared override
//     reads back as "(null)".
//   - <dev>/driver/unbind detaches the bound driver.
//   - drivers/<drv>/bind: EBUSY when bound, ENODEV when the device does not match
//     the driver. With an override set only that driver matches; with none, only
//     the native driver does (no dynamic IDs are modelled; see the new_id check).
//   - drivers_probe binds an unbound device to the override's driver, or to the
//     native driver when there is no override, if that driver is loaded.
type kernelFS struct {
	*memFS
	addr     string
	native   string          // the driver the kernel's own match picks ("" = none)
	loaded   map[string]bool // drivers present under /sys/bus/pci/drivers
	override string          // "" = (null)
	// stickyOverride makes every override write a no-op, to model a kernel that
	// does not honour the clear at all.
	stickyOverride bool
}

func newKernelFS(addr, native, bound, override string, loaded ...string) *kernelFS {
	m := newMemFS()
	m.addDevice(addr, "0x8086", "0x10ca", bound)
	k := &kernelFS{memFS: m, addr: addr, native: native, loaded: map[string]bool{}, override: override}
	for _, d := range loaded {
		k.loaded[d] = true
	}
	return k
}

func (k *kernelFS) devPath() string { return filepath.Join(sysDevices, k.addr) }

func (k *kernelFS) driver() string {
	d, err := k.memFS.Readlink(k.devPath() + "/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(d)
}

func (k *kernelFS) ReadFile(path string) ([]byte, error) {
	if path == k.devPath()+"/driver_override" {
		if k.override == "" {
			return []byte("(null)\n"), nil
		}
		return []byte(k.override + "\n"), nil
	}
	return k.memFS.ReadFile(path)
}

func (k *kernelFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := k.memFS.WriteFile(path, data, perm); err != nil {
		return err // injected failure
	}
	const drivers = "/sys/bus/pci/drivers/"
	switch {
	case path == k.devPath()+"/driver_override":
		if len(data) == 0 || k.stickyOverride {
			return nil
		}
		v, _, _ := strings.Cut(string(data), "\n")
		k.override = v
	case path == k.devPath()+"/driver/unbind":
		if k.driver() == "" {
			return syscall.ENODEV
		}
		k.memFS.setDriver(k.addr, "")
	case path == "/sys/bus/pci/drivers_probe":
		if k.driver() != "" {
			return nil
		}
		want := k.native
		if k.override != "" {
			want = k.override
		}
		if want != "" && k.loaded[want] {
			k.memFS.setDriver(k.addr, want)
		}
	case strings.HasPrefix(path, drivers) && strings.HasSuffix(path, "/bind"):
		drv := strings.TrimSuffix(strings.TrimPrefix(path, drivers), "/bind")
		if !k.loaded[drv] {
			return syscall.ENOENT
		}
		if k.driver() != "" {
			return syscall.EBUSY
		}
		if (k.override != "" && k.override != drv) || (k.override == "" && drv != k.native) {
			return syscall.ENODEV
		}
		k.memFS.setDriver(k.addr, drv)
	}
	return nil
}

// TestUnbind_ReturnsDeviceToHostDriver is the lab V1 case: an igb VF on vfio-pci
// with driver_override=vfio-pci, released after the VM let go of it. Whatever
// driver the caller names — the original one, the "vfio-pci" an inventory rescan
// records, or none — the device must end on igbvf with the override cleared. With
// a zero-length clear the override survives, the explicit igbvf bind is refused
// (ENODEV), and drivers_probe hands the device straight back to vfio-pci.
func TestUnbind_ReturnsDeviceToHostDriver(t *testing.T) {
	for _, restore := range []string{"igbvf", "vfio-pci", ""} {
		t.Run("restore="+restore, func(t *testing.T) {
			addr := "0000:01:10.0"
			k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
			defer SetFS(k)()

			if err := Unbind(addr, restore); err != nil {
				t.Fatalf("Unbind: %v", err)
			}
			if got := k.driver(); got != "igbvf" {
				t.Fatalf("driver = %q, want igbvf", got)
			}
			if k.override != "" {
				t.Fatalf("driver_override = %q, want cleared", k.override)
			}
		})
	}
}

// TestBindUnbind_RoundTrip binds a VF the way an attach does and releases it the
// way a detach does, with the restore driver the inventory holds by then
// ("vfio-pci"). The device must come back to igbvf with no override, and Bind
// must not have added a vfio-pci dynamic ID, which would let vfio-pci claim every
// sibling VF with the same vendor:device.
func TestBindUnbind_RoundTrip(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf", "vfio-pci")
	defer SetFS(k)()

	prev, err := Bind(addr)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if prev != "igbvf" || k.driver() != "vfio-pci" || k.override != "vfio-pci" {
		t.Fatalf("after Bind: prev=%q driver=%q override=%q, want igbvf/vfio-pci/vfio-pci", prev, k.driver(), k.override)
	}
	if _, wrote := k.written[vfioDriverPath+"/new_id"]; wrote {
		t.Fatal("Bind wrote vfio-pci/new_id; driver_override alone must claim the device")
	}

	if err := Unbind(addr, "vfio-pci"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if k.driver() != "igbvf" || k.override != "" {
		t.Fatalf("after Unbind: driver=%q override=%q, want igbvf and cleared", k.driver(), k.override)
	}
}

// TestUnbind_OverrideNotClearedFailsBeforeUnbinding: when the kernel still
// reports the override after the clear, Unbind must stop with a clear error and
// leave the device on vfio-pci, not unbind it into a probe that re-claims it.
func TestUnbind_OverrideNotClearedFailsBeforeUnbinding(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "vfio-pci", "vfio-pci", "igbvf", "vfio-pci")
	k.stickyOverride = true
	defer SetFS(k)()

	err := Unbind(addr, "igbvf")
	if err == nil || !strings.Contains(err.Error(), "driver_override") {
		t.Fatalf("Unbind error = %v, want a driver_override error", err)
	}
	if k.driver() != "vfio-pci" {
		t.Fatalf("driver = %q, want vfio-pci (untouched)", k.driver())
	}
	if _, wrote := k.written[k.devPath()+"/driver/unbind"]; wrote {
		t.Fatal("Unbind unbound the device although the override was still set")
	}
}

// TestUnbind_LeftWithoutDriver: a named host driver that cannot bind and a
// reprobe that finds nothing leaves the device driverless, which Unbind reports
// as a failure. With no driver named, driverless is the device's normal state on
// that host and is accepted.
func TestUnbind_LeftWithoutDriver(t *testing.T) {
	addr := "0000:01:10.0"

	k := newKernelFS(addr, "", "vfio-pci", "vfio-pci", "vfio-pci") // igbvf not loaded
	restore := SetFS(k)
	err := Unbind(addr, "igbvf")
	restore()
	if err == nil || !strings.Contains(err.Error(), "no driver") {
		t.Fatalf("Unbind(igbvf) error = %v, want a left-with-no-driver failure", err)
	}
	if k.driver() != "" || k.override != "" {
		t.Fatalf("driver=%q override=%q, want released and cleared", k.driver(), k.override)
	}

	k = newKernelFS(addr, "", "vfio-pci", "vfio-pci", "vfio-pci")
	defer SetFS(k)()
	if err := Unbind(addr, ""); err != nil {
		t.Fatalf("Unbind(\"\") with no host driver: %v", err)
	}
}

// TestBind_FailureRestoresPreviousDriver: vfio-pci is not loaded, so the bind
// cannot happen. Bind has already taken the device off igbvf and set the
// override; it must put both back rather than leave a driverless device that the
// next probe gives to vfio-pci.
func TestBind_FailureRestoresPreviousDriver(t *testing.T) {
	addr := "0000:01:10.0"
	k := newKernelFS(addr, "igbvf", "igbvf", "", "igbvf")
	defer SetFS(k)()

	if _, err := Bind(addr); err == nil {
		t.Fatal("Bind succeeded without vfio-pci loaded")
	}
	if k.driver() != "igbvf" || k.override != "" {
		t.Fatalf("after failed Bind: driver=%q override=%q, want igbvf and cleared", k.driver(), k.override)
	}
}
