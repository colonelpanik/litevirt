package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// FIX-24: the whole-VM PCI teardown (releaseDevices) must be HOST-SCOPED. It unbinds
// and releases ONLY the devices THIS host records as owned by the VM. A device the same
// (stale/migrated) VM still owns on a DIFFERENT host must be left for that host's own
// teardown — clearing it here would leave the remote device unowned-but-vfio-bound,
// because this host cannot unbind on the remote host.

// TestReleaseDevices_DoesNotClearRemoteHostOwnership proves releaseDevices never clears
// another host's ownership row. It seeds a device owned+bound by the VM on THIS host and
// another owned+bound by the SAME VM on a different host, then asserts the local one is
// unbound + released while the remote one is untouched (still owned, still bound, never
// unbound). RED against the cluster-wide ReleasePCIDevicesByVM (which cleared the remote
// ownership WITHOUT unbinding there) → GREEN with the per-device host+owner-scoped release.
func TestReleaseDevices_DoesNotClearRemoteHostOwnership(t *testing.T) {
	const (
		localAddr  = "0000:41:00.0"
		remoteAddr = "0000:42:00.0"
	)
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	// A device THIS host owns for vm-a, bound to vfio-pci.
	seedPCIGPU(t, s, localAddr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, s.hostName, localAddr, "vm-a"); err != nil {
		t.Fatalf("assign local addr to vm-a: %v", err)
	}
	fs.setBound(localAddr)

	// A device the SAME VM still owns on a DIFFERENT host (a stale/migrated ownership
	// row) — bound in the vfio fake so a spurious unbind here would be observable.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "other-host", Address: remoteAddr, Type: "gpu", VMName: "vm-a",
	}); err != nil {
		t.Fatalf("seed remote ownership row: %v", err)
	}
	fs.setBound(remoteAddr)

	if err := s.releaseDevices(ctx, "vm-a"); err != nil {
		t.Fatalf("releaseDevices: %v", err)
	}

	// (a) This host's device: unbound + owner cleared.
	if fs.isBound(localAddr) {
		t.Fatal("this host's device must be unbound from vfio-pci")
	}
	if o := pciOwnerOf(t, ctx, s, localAddr); o != "" {
		t.Fatalf("this host's device must be released, got owner %q", o)
	}

	// (b) THE INVARIANT: the remote host's ownership row is UNCHANGED and the remote
	// device was NOT unbound — this host must never clear a remote host's ownership
	// without unbinding there (which it cannot do).
	remoteDevs, err := corrosion.ListPCIDevices(ctx, s.db, "other-host", "")
	if err != nil {
		t.Fatalf("list remote devices: %v", err)
	}
	var remoteOwner string
	for _, d := range remoteDevs {
		if d.Address == remoteAddr {
			remoteOwner = d.VMName
		}
	}
	if remoteOwner != "vm-a" {
		t.Fatalf("remote host's ownership must be untouched, got owner %q", remoteOwner)
	}
	if n := fs.unbindCount(remoteAddr); n != 0 {
		t.Fatalf("the remote device must NOT be unbound, got %d unbinds", n)
	}
	if !fs.isBound(remoteAddr) {
		t.Fatal("the remote device must stay bound to vfio-pci")
	}
}

// TestReleaseDevices_ReleaseWriteFails_Recoverable exercises the new per-device release
// loop's error path: the unbind succeeds but the owner-release WRITE fails. releaseDevices
// must return the error (recoverable) and leave the device OWNED — the caller must not
// complete/tombstone over a leaked ownership row. The unbind is ground-truth done, so a
// retry converges (an already-unbound device reads IsBoundToVFIO=false and an owner-scoped
// re-release of an already-released row is a 0-row no-op).
func TestReleaseDevices_ReleaseWriteFails_Recoverable(t *testing.T) {
	const addr = "0000:41:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()

	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(adminCtx(), s.db, s.hostName, addr, "vm-a"); err != nil {
		t.Fatalf("assign addr to vm-a: %v", err)
	}
	fs.setBound(addr)

	// Let the unbind SUCCEED, then fault the post-unbind release write: cancel the
	// context the moment the hardware unbind completes (the onUnbind hook fires after
	// the device is flipped unbound but before the ReleasePCIDevice loop), so the
	// owner-release UPDATE errors while the device is already unbound.
	ctx, cancel := context.WithCancel(adminCtx())
	fs.onUnbind = func(string) { cancel() }

	if err := s.releaseDevices(ctx, "vm-a"); err == nil {
		t.Fatal("a failed release write must fail releaseDevices (recoverable), got nil")
	}

	// Recoverable: the device stays OWNED (no completion over a leaked ownership row);
	// a fresh context reads the untouched ownership.
	if o := pciOwnerOf(t, adminCtx(), s, addr); o != "vm-a" {
		t.Fatalf("a failed release write must leave the device owned (recoverable), got %q", o)
	}
	// The unbind itself completed (ground truth), so a retry converges.
	if n := fs.unbindCount(addr); n != 1 {
		t.Fatalf("the device should have been unbound exactly once, got %d", n)
	}
}
