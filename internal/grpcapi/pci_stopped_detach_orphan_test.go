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
	mu         sync.Mutex
	bound      map[string]bool   // address -> bound to vfio-pci
	override   map[string]bool   // address -> driver_override currently selects vfio-pci
	unbinds    map[string]int    // address -> count of vfio.Unbind invocations
	failUnbind map[string]bool   // address -> the .../driver/unbind write fails (models a stuck unbind)
	failBind   map[string]bool   // address -> the vfio-pci bind never takes (models a device that won't bind)
	vf         map[string]bool   // address -> device is an SR-IOV VF (has a physfn symlink)
	binds      int               // count of vfio-pci bind writes
	onUnbind   func(addr string) // fired once per unbind (at the driver_override clear), if set
}

func newPCIUnbindRecordingFS() *pciUnbindRecordingFS {
	return &pciUnbindRecordingFS{
		bound:      map[string]bool{},
		override:   map[string]bool{},
		unbinds:    map[string]int{},
		failUnbind: map[string]bool{},
		failBind:   map[string]bool{},
		vf:         map[string]bool{},
	}
}

// setBound marks a device as currently bound to vfio-pci WITHOUT running a bind (used
// to construct a "device is vfio-bound" ground-truth state directly in a test).
func (f *pciUnbindRecordingFS) setBound(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound[addr] = true
	f.override[addr] = true
}

// setFailUnbind makes the .../driver/unbind write for addr fail, so vfio.Unbind
// returns an error and the device stays bound (models a stuck/failed unbind).
func (f *pciUnbindRecordingFS) setFailUnbind(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failUnbind[addr] = true
}

// clearFailUnbind clears a previously-injected unbind fault so a retry can converge
// (models an operator clearing the transient condition that blocked the release).
func (f *pciUnbindRecordingFS) clearFailUnbind(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failUnbind, addr)
}

// setVF marks addr as an SR-IOV Virtual Function so vfio.IsVF (which probes for a
// physfn symlink) reports true for it — used to drive the pre-migration VF-detach path.
func (f *pciUnbindRecordingFS) setVF(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vf[addr] = true
}

// setFailBind makes the vfio-pci bind for addr never take (the bind + drivers_probe
// writes are no-ops), so vfio.Bind's own driver-symlink verify fails and Bind returns
// an error while the device is left NOT bound (models a device that refuses to bind).
func (f *pciUnbindRecordingFS) setFailBind(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failBind[addr] = true
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
			if f.onUnbind != nil {
				// Fires AFTER the .../driver/unbind write already flipped the device
				// unbound but BEFORE the caller's post-unbind ReleasePCIDevice loop — lets a
				// test model a fault that appears only once the hardware mutation is done.
				f.onUnbind(a)
			}
		}
	case strings.HasSuffix(path, "/driver/unbind"):
		if f.failUnbind[val] {
			// Model a stuck unbind: the write fails and the device stays bound.
			return fmt.Errorf("pciUnbindRecordingFS: injected unbind failure for %s", val)
		}
		// Unbind from the current (vfio-pci) driver: the device is now driverless.
		f.bound[val] = false
	case strings.Contains(path, "vfio-pci/bind"):
		if f.failBind[val] {
			// The bind never takes → the device stays unbound and vfio.Bind's verify fails.
			break
		}
		f.bound[val] = true
		f.binds++
	case strings.Contains(path, "drivers_probe"):
		if f.failBind[val] {
			f.bound[val] = false
			break
		}
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
		// No driver bound → model real sysfs (ENOENT); IsBoundToVFIO reads this as
		// "not bound" (false, nil), not an unexpected FS error.
		return "", os.ErrNotExist
	}
	if strings.HasSuffix(path, "/physfn") {
		// A VF has a physfn symlink to its parent PF; a PF (or a plain device) does
		// not → ENOENT, which vfio.IsVF reads as "not a VF".
		if f.vf[f.devAddr(path, "/physfn")] {
			return "/sys/bus/pci/devices/0000:00:00.0", nil
		}
		return "", os.ErrNotExist
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
// (vfio Unbind + owner-release via unbindAndReleaseOwnership) before releasing ownership —
// discriminated by the ACTUAL vfio driver state. RED before the fix (the branch
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

// TestDetachPCI_StoppedFailedStartBoundNoRealizations_Unbinds is FIX-14 bug #3:
// FIX-9c's failed-start rollback RETAINS a self-owned device's vfio binding but
// TOMBSTONES its realization rows. A later stopped detach must NOT key its
// unbind-or-not decision on realization presence (which now lies) — it must consult
// the ACTUAL vfio driver state. Here the device is owned + vfio-BOUND but has NO
// realization rows: the detach must UNBIND it (ground truth) before releasing
// ownership, never leave an unowned-but-vfio-bound orphan. RED before the fix (the
// realization-presence discriminator took the "never bound" branch → owner-release
// WITHOUT unbind → still bound).
func TestDetachPCI_StoppedFailedStartBoundNoRealizations_Unbinds(t *testing.T) {
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

	// Stopped reserve: claims ownership + intent, reconciles the hostdev into the def,
	// NO bind, NO realization.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("a reserve must have NO realizations, got %d", len(rs))
	}
	// FIX-9c state: a failed start bound the device to vfio-pci but its rollback
	// tombstoned the realization rows while RETAINING the binding.
	fs.setBound(addr)
	if !fs.isBound(addr) {
		t.Fatal("precondition: device must be vfio-bound")
	}

	// Detach while stopped: must UNBIND by ground truth, then release + tombstone.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "vm1", PciAddress: addr,
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}

	if n := fs.unbindCount(addr); n == 0 {
		t.Fatalf("detach of a bound-but-realization-less device must vfio-unbind it (0 unbinds — the orphan bug)")
	}
	if fs.isBound(addr) {
		t.Fatal("detach left the device bound to vfio-pci (unowned + vfio-bound orphan)")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("detach must release ownership, got owner %q", o)
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 0 {
		t.Fatalf("intent not tombstoned: %+v", in)
	}
}

// TestDetachPCI_StoppedUnbindFails_LeavesRecoverable is FIX-14 bug #1: a stopped
// detach whose vfio.Unbind FAILS must leave EVERYTHING recoverable — ownership
// retained, intent + realizations NOT tombstoned, the operation barrier still set,
// and an error returned — rather than clearing ownership anyway (which would leave an
// unowned-but-vfio-bound orphan). RED before the fix (the old fire-and-forget release
// logged the unbind failure then released ownership + tombstoned + completed).
func TestDetachPCI_StoppedUnbindFails_LeavesRecoverable(t *testing.T) {
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

	// attach → start → stop leaves the device vfio-bound + owned + realized + intent.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !fs.isBound(addr) {
		t.Fatal("precondition: start must bind the device")
	}
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateDefined)

	// Force the vfio unbind to fail.
	fs.setFailUnbind(addr)

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if derr == nil {
		t.Fatal("a failed vfio unbind must fail the detach (recoverable), not report success")
	}

	// Ownership RETAINED (not released despite the unbind failure).
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("unbind failure must RETAIN ownership, got owner %q, want vm1", o)
	}
	// Nothing tombstoned.
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("unbind failure must NOT tombstone realizations, got %d", len(rs))
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("unbind failure must NOT tombstone the intent, got %d", len(in))
	}
	// Barrier still set → the operation is recovery-required.
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op == "" {
		t.Fatal("unbind failure must leave the operation barrier set (recovery-required)")
	}
	// The device is still vfio-bound (the unbind never succeeded) — owned + bound is safe.
	if !fs.isBound(addr) {
		t.Fatal("a failed unbind must leave the device still bound (owned + bound, recoverable)")
	}
}

// TestDetachPCI_StoppedNeverStartedReserve_ReleasesNoUnbind is the FIX-11 regression
// under the ground-truth protocol: a never-started reserve (owned, NOT vfio-bound, no
// realizations) detaches by releasing ownership and must NOT call vfio.Unbind —
// IsBoundToVFIO=false so no unbind is attempted (Unbind on a never-bound device clears
// driver_override + reprobes, which is not a clean no-op).
func TestDetachPCI_StoppedNeverStartedReserve_ReleasesNoUnbind(t *testing.T) {
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

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("detach must release the stopped reservation, got owner %q", o)
	}
	if n := fs.unbindCount(addr); n != 0 {
		t.Fatalf("a never-bound reserve must NOT be vfio-unbound, got %d unbinds", n)
	}
	if fs.binds != 0 {
		t.Fatalf("a never-started reserve must never have been bound, got %d binds", fs.binds)
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

// TestDetachPCI_StoppedReleaseWriteFails_LeavesRecoverable is FIX-15 Fix A: after a
// clean vfio unbind, if the ReleasePCIDevice DB write FAILS the detach must leave the
// operation recovery-required — an error is returned, the barrier is retained, and the
// intent + realizations are NOT tombstoned — rather than swallowing the write error and
// completing (which would leave a host_pci_devices row still owned by the VM with no
// intent/realization referencing it: an unclaimable leak until VM delete). RED before
// the fix (unbindAndReleaseOwnership only slog.Warn'd the release failure and returned
// nil → the caller tombstoned + completed). The retry converges: the member is already
// unbound (IsBoundToVFIO=false → skip unbind) and the owner-scoped re-release is a
// 0-row no-op.
func TestDetachPCI_StoppedReleaseWriteFails_LeavesRecoverable(t *testing.T) {
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

	// attach → start → stop leaves the device vfio-bound + owned + realized + intent.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !fs.isBound(addr) {
		t.Fatal("precondition: start must bind the device")
	}
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateDefined)

	// Force ONLY the post-unbind DB release WRITE to fail — not the primitive's ownership
	// read. The onUnbind hook fires after the vfio unbind has flipped the device unbound but
	// before the ReleasePCIDevice loop, so dropping the inventory table there leaves the
	// primitive's fail-closed ownership read (which runs first, before the unbind) intact
	// while the release UPDATE hits a missing table. The unbind still succeeds (vfio state
	// lives in the FS fake), exercising the post-unbind release-write failure specifically.
	fs.onUnbind = func(string) { _ = s.db.Execute(ctx, `DROP TABLE host_pci_devices`) }

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if derr == nil {
		t.Fatal("a failed DB release must fail the detach (recoverable), not complete with a leaked ownership row")
	}

	// The device WAS unbound (the unbind succeeded before the release write failed).
	if fs.isBound(addr) {
		t.Fatal("the unbind should have succeeded before the release write failed")
	}
	// LEFT RECOVERABLE: the intent + realizations are NOT tombstoned (a retry re-runs
	// the owner-scoped release, which converges).
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 1 {
		t.Fatalf("release failure must NOT tombstone realizations, got %d", len(rs))
	}
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("release failure must NOT tombstone the intent, got %d", len(in))
	}
	// Barrier still set → the operation is recovery-required.
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op == "" {
		t.Fatal("release failure must leave the operation barrier set (recovery-required)")
	}
}

// TestDetachPCI_StoppedTombstoneFailsAfterRelease_LeavesRecoverable is FIX-15 Fix B:
// once unbindAndReleaseOwnership SUCCEEDS (the device is already unbound + released),
// a TombstonePCIRealizations/TombstonePCIIntent failure must leave the operation
// recovery-required (recoverable error, barrier retained), NOT be routed to
// failPCIDetachClean — whose contract is a terminal failure when NOTHING was applied.
// Sending a post-release failure there marks the op terminal + clears the barrier while
// the realization/intent rows survive pointing at an already-released device, with no
// recovery. RED before the fix (terminal via failPCIDetachClean → barrier cleared). The
// retry re-tombstones (idempotent) and converges.
func TestDetachPCI_StoppedTombstoneFailsAfterRelease_LeavesRecoverable(t *testing.T) {
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

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !fs.isBound(addr) {
		t.Fatal("precondition: start must bind the device")
	}
	if _, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "vm1", Force: true}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateDefined)

	// Drop the realizations table AFTER executePCIDetach has read it (line ~772) and
	// AFTER the unbind + release succeed, but BEFORE the tombstone: fire the drop from
	// the unbind hook so ReleasePCIDevice (host_pci_devices, untouched) still succeeds
	// and only TombstonePCIRealizations fails.
	fs.onUnbind = func(string) { _ = s.db.Execute(ctx, `DROP TABLE vm_pci_realizations`) }

	_, derr := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if derr == nil {
		t.Fatal("a post-release tombstone failure must fail the detach (recoverable), not complete")
	}

	// The release DID happen (post-release failure): ownership cleared, device unbound.
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("release should have completed before the tombstone failure, got owner %q", o)
	}
	if fs.isBound(addr) {
		t.Fatal("the unbind should have completed before the tombstone failure")
	}
	// LEFT RECOVERABLE (NOT terminal via failPCIDetachClean): the barrier is retained,
	// so recovery/retry re-tombstones. failPCIDetachClean would have cleared it.
	if op := mustGetVM(t, s, "vm1").ActiveOperationID; op == "" {
		t.Fatal("a post-release tombstone failure must leave the barrier set (recovery-required), not terminalize via failPCIDetachClean")
	}
	// The intent survives (roll-forward incomplete) — a retry re-tombstones it.
	if in := liveIntents(t, ctx, s, "vm1"); len(in) != 1 {
		t.Fatalf("intent should survive a failed tombstone (retry re-tombstones), got %d", len(in))
	}
}
