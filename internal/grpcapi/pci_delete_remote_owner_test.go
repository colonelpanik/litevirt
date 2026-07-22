package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FIX-28: a VM delete must FAIL BEFORE tombstoning while a DIFFERENT host still holds a
// live host_pci_devices ownership row for the VM. DeleteVM forwards to the VM's home host
// before releasing locally, so after the local releaseDevices the only owner rows that can
// remain are on a remote host — a stale migration artifact (a partial/failed migration that
// left the source-host reservation). Tombstoning the vms row over it would strand that
// device assigned to a now-deleted VM, blocking every future ClaimPCIDevice CAS on that BDF
// forever (invariant (b): stale owner of a deleted VM, on the remote host). Fail closed →
// the delete is RETRYABLE once the remote host releases its row.

// remoteOwnerOf reports which VM (if any) owns addr on hostName (live rows only).
func remoteOwnerOf(t *testing.T, ctx context.Context, s *Server, hostName, addr string) string {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(ctx, s.db, hostName, "")
	if err != nil {
		t.Fatalf("ListPCIDevices(%s): %v", hostName, err)
	}
	for _, d := range devs {
		if d.Address == addr {
			return d.VMName
		}
	}
	return ""
}

// seedRemotePCIOwner inserts a live host_pci_devices ownership row for vmName on a host
// OTHER than s.hostName (a stale source-host reservation from a partial migration). The
// device need not be bound — the point is the surviving ownership row.
func seedRemotePCIOwner(t *testing.T, ctx context.Context, s *Server, hostName, addr, vmName string) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: hostName, Address: addr, Type: "gpu", VendorID: "10de", VMName: vmName,
	}); err != nil {
		t.Fatalf("seed remote PCI owner %s@%s: %v", addr, hostName, err)
	}
}

// TestDeleteVM_RemoteHostOwnsPCI_FailsBeforeTombstone: VM vm-a is on s.hostName (domain
// present → the main delete path). A DIFFERENT host (other-host) still owns the VM's PCI.
// The delete must return a FailedPrecondition error naming other-host, leave the vms row
// intact (not tombstoned), and leave the remote ownership row UNCHANGED. RED before the fix
// (delete tombstoned the row → stale remote owner) → GREEN after.
func TestDeleteVM_RemoteHostOwnsPCI_FailsBeforeTombstone(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm-a", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm-a", libvirtfake.StateDefined)
	seedRemotePCIOwner(t, ctx, s, "other-host", addr, "vm-a")

	// (a) The delete FAILS with FailedPrecondition, naming the remote owner.
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-a"})
	if err == nil {
		t.Fatal("delete must FAIL while another host still owns the VM's PCI (never tombstone over it)")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "other-host") {
		t.Fatalf("error must name the remote owner host, got %q", err.Error())
	}
	// (b) The vms row is NOT tombstoned — the delete is retryable.
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm-a"); vm == nil {
		t.Fatal("a remote PCI owner must NOT tombstone the VM row (delete must be retryable)")
	}
	// (c) The remote ownership row is UNCHANGED (still owned by vm-a on other-host).
	if o := remoteOwnerOf(t, ctx, s, "other-host", addr); o != "vm-a" {
		t.Fatalf("remote ownership row must be untouched (owner vm-a), got %q", o)
	}
}

// TestDeleteVM_RemoteOwnershipCleared_CompletesOnRetry (convergence): after the remote host
// releases its stale ownership row, retrying the delete must COMPLETE (row tombstoned).
// Demonstrates the retryable fail-closed contract.
func TestDeleteVM_RemoteOwnershipCleared_CompletesOnRetry(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm-a", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm-a", libvirtfake.StateDefined)
	seedRemotePCIOwner(t, ctx, s, "other-host", addr, "vm-a")

	// First delete fails on the remote owner (row retained).
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-a"}); err == nil {
		t.Fatal("precondition: the first delete must fail while other-host owns the PCI")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm-a"); vm == nil {
		t.Fatal("precondition: the failed delete must retain the VM row")
	}

	// The remote host releases its stale ownership row (owner-scoped release).
	if err := corrosion.ReleasePCIDevice(ctx, s.db, "other-host", addr, "vm-a"); err != nil {
		t.Fatalf("release remote ownership: %v", err)
	}

	// Retry now completes: no host owns the VM's PCI → the guard passes, row tombstoned.
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-a"}); err != nil {
		t.Fatalf("retry after the remote release must complete the delete: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm-a"); vm != nil {
		t.Fatal("the successful retry must tombstone the VM row")
	}
}

// TestDeleteVM_OnlyLocalPCI_Completes (regression): a VM that owns PCI ONLY on s.hostName
// deletes normally — the local releaseDevices clears the owner row BEFORE the guard reads,
// so the guard sees no owner and raises no false positive. GREEN before and after the fix.
func TestDeleteVM_OnlyLocalPCI_Completes(t *testing.T) {
	const addr = "0000:00:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.images = image.NewStore(s.dataDir)
	s.images.Init()
	fs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()

	seedNICVM(t, s, "vm-a", "stopped")
	s.virt.(*libvirtfake.Fake).SetState("vm-a", libvirtfake.StateDefined)
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm-a"); err != nil {
		t.Fatalf("seed local ownership: %v", err)
	}
	fs.setBound(addr) // bound but releasable (no unbind fault)

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-a"}); err != nil {
		t.Fatalf("a local-only-PCI delete must complete (no false positive from the remote guard): %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "vm-a"); vm != nil {
		t.Fatal("delete must tombstone the VM row")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("delete must release the local device, got owner %q", o)
	}
}
