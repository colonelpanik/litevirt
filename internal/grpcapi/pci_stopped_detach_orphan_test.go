package grpcapi

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// pciUnbindRecordingFS is a vfio.SysFS that models BOTH a vfio bind and a vfio
// UNBIND (pciBindFakeFS only models bind), and records every Unbind so a detach test
// can assert whether a device was actually unbound. A bind flips the driver symlink
// to vfio-pci; an unbind honors vfio.Unbind's real sequence — the .../driver/unbind
// write clears the vfio-pci binding, and the driver_override clear that Unbind performs
// unconditionally on EVERY call is recorded per address as the unambiguous
// "Unbind was invoked" signal (nothing else writes an empty driver_override). Because
// Unbind clears the override before its drivers_probe, that probe rebinds to the
// ORIGINAL driver (not vfio-pci), so an unbound device stays unbound and Unbind's own
// verify passes.
type pciUnbindRecordingFS struct {
	mu       sync.Mutex
	bound    map[string]bool // address -> bound to vfio-pci
	override map[string]bool // address -> driver_override currently selects vfio-pci
	unbinds  map[string]int  // address -> count of vfio.Unbind invocations
	binds    int             // count of vfio-pci bind writes
}

func newPCIUnbindRecordingFS() *pciUnbindRecordingFS {
	return &pciUnbindRecordingFS{
		bound:    map[string]bool{},
		override: map[string]bool{},
		unbinds:  map[string]int{},
	}
}

func (f *pciUnbindRecordingFS) devAddr(path, suffix string) string {
	const pfx = "/sys/bus/pci/devices/"
	if !strings.HasPrefix(path, pfx) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(path, pfx), suffix)
}

func (f *pciUnbindRecordingFS) ReadFile(path string) ([]byte, error) {
	if strings.HasSuffix(path, "/vendor") {
		return []byte("0x8086\n"), nil
	}
	if strings.HasSuffix(path, "/device") {
		return []byte("0x1572\n"), nil
	}
	return nil, fmt.Errorf("pciUnbindRecordingFS: no file %s", path)
}

func (f *pciUnbindRecordingFS) WriteFile(path string, data []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	val := strings.TrimSpace(string(data))
	switch {
	case strings.HasSuffix(path, "/driver_override"):
		a := f.devAddr(path, "/driver_override")
		if val == "vfio-pci" {
			f.override[a] = true
		} else {
			// vfio.Unbind clears the override on EVERY call → the unbind signal.
			f.override[a] = false
			f.unbinds[a]++
		}
	case strings.HasSuffix(path, "/driver/unbind"):
		// Unbind from the current (vfio-pci) driver: the device is now driverless.
		f.bound[val] = false
	case strings.Contains(path, "vfio-pci/bind"):
		f.bound[val] = true
		f.binds++
	case strings.Contains(path, "drivers_probe"):
		// The kernel reprobes: to vfio-pci only if the override still selects it,
		// otherwise to the original driver (leaving it unbound from vfio-pci).
		if f.override[val] {
			f.bound[val] = true
			f.binds++
		} else {
			f.bound[val] = false
		}
	}
	// Any other write (new_id, a restore-driver bind) is a no-op.
	return nil
}

func (f *pciUnbindRecordingFS) Readlink(path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(path, "/driver") {
		if f.bound[f.devAddr(path, "/driver")] {
			return "/sys/bus/pci/drivers/vfio-pci", nil
		}
		return "", fmt.Errorf("pciUnbindRecordingFS: no driver for %s", path)
	}
	return "", fmt.Errorf("pciUnbindRecordingFS: no link %s", path)
}

func (f *pciUnbindRecordingFS) ReadDir(path string) ([]os.DirEntry, error) {
	return nil, fmt.Errorf("pciUnbindRecordingFS: no dir %s", path)
}

func (f *pciUnbindRecordingFS) isBound(addr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bound[addr]
}

func (f *pciUnbindRecordingFS) unbindCount(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unbinds[addr]
}

// TestDetachPCI_StoppedAfterStart_UnbindsAndReleases is the FIX-11 regression: the
// attach → start → stop → detach lifecycle. FIX-9b makes a latched stop RETAIN the
// vfio binding + ownership + realizations, so at detach time the stopped VM's device
// is still bound to vfio-pci. The stopped-detach branch must therefore UNBIND it
// (vfio Unbind + owner-release via releaseDeviceLeases) before releasing ownership —
// discriminated by the presence of realization rows. RED before the fix (the branch
// owner-released WITHOUT unbinding, leaving an unowned but still-vfio-bound orphan).
func TestDetachPCI_StoppedAfterStart_UnbindsAndReleases(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)

	seedNICVM(t, s, "vm1", "stopped")
	fake.SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)

	// Attach while stopped: reserves ownership + intent, NO bind, NO realization.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if fs.binds != 0 {
		t.Fatalf("stopped reserve must NOT bind vfio, got %d binds", fs.binds)
	}

	// Start: binds the reserved device to vfio-pci and writes its realization.
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !fs.isBound(addr) {
		t.Fatalf("start must bind the reserved device to vfio-pci")
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("start must write 1 realization, got %d", len(rs))
	}

	// Stop (latched): retains the vfio bind + ownership + realization (FIX-9b).
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !fs.isBound(addr) {
		t.Fatalf("latched stop must RETAIN the vfio bind (FIX-9b)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("latched stop must retain ownership, got owner %q, want vm1", o)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("latched stop must retain the realization, got %d", len(rs))
	}

	// Detach while stopped: must UNBIND then release ownership + tombstone.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: addr,
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}

	// (a) Ownership cleared.
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("detach must release ownership, got owner %q", o)
	}
	// (b) The device was UNBOUND from vfio-pci (no vfio-bound orphan).
	if n := fs.unbindCount(addr); n == 0 {
		t.Fatalf("detach of a started-then-stopped device must vfio-unbind it (0 unbinds recorded — the orphan bug)")
	}
	if fs.isBound(addr) {
		t.Fatalf("detach left the device bound to vfio-pci (unowned + vfio-bound orphan)")
	}
	// (c) Realizations + intent tombstoned.
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("realizations not tombstoned: %+v", rs)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent not tombstoned: %+v", in)
	}
}

// TestDetachPCI_StoppedNeverStarted_ReleasesOwnershipOnly is the FIX-9a-preserving
// guard: a stopped VM that was NEVER started has an ownership-reserved-only device
// (no realizations, never bound). Detaching it must release ownership WITHOUT any
// vfio Unbind — Unbind on a never-bound device is not a clean no-op (it clears
// driver_override and attempts a driver-restore), so it must not be called.
func TestDetachPCI_StoppedNeverStarted_ReleasesOwnershipOnly(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm1", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)

	// Attach while stopped only — never started, so no realization, never bound.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("stopped attach must claim ownership before detach, got owner %q", o)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("a never-started reserve must have NO realizations, got %d", len(rs))
	}

	// Detach while stopped: owner-release only, NO vfio touch.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: addr,
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}

	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("detach must release the stopped reservation, got owner %q", o)
	}
	// vfio Unbind must NOT have been invoked on a never-bound device.
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("detach of a never-started reserve must NOT vfio-unbind (got %d unbinds — clears driver_override on a never-bound device)", n)
	}
	if fs.binds != 0 {
		t.Fatalf("a never-started reserve must never have been bound, got %d binds", fs.binds)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent not tombstoned: %+v", in)
	}
}
