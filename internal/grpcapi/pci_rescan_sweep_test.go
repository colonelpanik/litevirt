package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

// The whole of RescanHost, in the order production runs it.
//
// Every other test of the stranded-ownership sweep calls
// corrosion.SweepStrandedPCIOwnership directly, and that is precisely why the
// sweep shipped dead. The defect was not in either piece: ObservePCIDevice
// refreshing updated_at is correct, and the sweep's age guard is correct. It
// only appears in the ORDER — RescanHost observes every present device, which
// stamps updated_at with c.NowTS(), and then immediately asks the sweep to skip
// anything younger than DefaultPCIOwnershipSweepAge. Nothing could ever be old
// enough, so `cleared` was always empty and #218 stayed open while reporting
// success.
//
// A defect that lives in the order two correct pieces are called in needs a
// test that calls them in that order.
func TestRescanHost_ReclaimsADeviceWhoseVMWasDeleted(t *testing.T) {
	ctx := adminCtx()
	s := testServer(t)

	dev := pci.Device{
		Address: "0000:41:00.0", VendorID: "10de", DeviceID: "1eb8",
		VendorName: "NVIDIA", DeviceName: "T4", Type: "gpu", IOMMUGroup: 42,
	}
	s.pciScanOverride = func() ([]pci.Device, error) { return []pci.Device{dev}, nil }

	// A VM owns the device, then is deleted — the hardware never goes anywhere.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: s.hostName, State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if _, err := s.RescanHost(ctx, &pb.RescanHostRequest{}); err != nil {
		t.Fatalf("first rescan: %v", err)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, dev.Address, "vm1"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	// The rescan an operator runs to get the device back.
	if _, err := s.RescanHost(ctx, &pb.RescanHostRequest{}); err != nil {
		t.Fatalf("second rescan: %v", err)
	}

	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	var owner string
	var found bool
	for _, d := range devs {
		if d.Address == dev.Address {
			owner, found = d.VMName, true
		}
	}
	if !found {
		t.Fatalf("device %s is not in the live set after a rescan that scanned it", dev.Address)
	}
	if owner != "" {
		t.Errorf("owner = %q after a rescan; the device is still assigned to a deleted VM, so "+
			"ClaimPCIDevice (which matches only an empty vm_name) can never hand it out again",
			owner)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, dev.Address, "vm2"); err != nil || !ok {
		t.Fatalf("the reclaimed device must be assignable again: ok=%v err=%v", ok, err)
	}
}
