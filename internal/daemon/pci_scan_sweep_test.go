package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

// The daemon's own scans must reclaim a device whose VM is gone, not only an
// operator's `lv host rescan` (#218).
//
// The startup scan and the periodic scan both call ObservePCIDevice, which
// revives a tombstoned row with its vm_name intact — deliberately, so a
// transient scan drop cannot hand in-use hardware to a second VM. Nothing on
// those paths then asked whether that owner still exists, so after a reboot a
// device whose VM was deleted stayed assigned to it, and ClaimPCIDevice (which
// matches only an empty vm_name) could never hand it out again until someone
// ran a rescan by hand.
//
// Mutation: drop the SweepStrandedPCIOwnership call from runPCIScan — the
// owner stays "vm1" and the claim for vm2 matches zero rows.
func TestRunPCIScan_ReclaimsADeviceWhoseVMWasDeleted(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	const host = "node-1"
	dev := pci.Device{
		Address: "0000:41:00.0", VendorID: "10de", DeviceID: "1eb8",
		VendorName: "NVIDIA", DeviceName: "T4", Type: "gpu", IOMMUGroup: 42,
	}
	d := &Daemon{
		cfg:             &Config{HostName: host},
		db:              db,
		pciScanOverride: func() ([]pci.Device, error) { return []pci.Device{dev}, nil },
	}

	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: host, State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	d.runPCIScan(ctx)
	if ok, err := corrosion.ClaimPCIDevice(ctx, db, host, dev.Address, "vm1"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	// The device drops out (the host went down), the VM is deleted meanwhile,
	// and the host comes back with the hardware present.
	if err := corrosion.SoftDeletePCIDevice(ctx, db, host, dev.Address); err != nil {
		t.Fatalf("SoftDeletePCIDevice: %v", err)
	}
	if err := corrosion.DeleteVM(ctx, db, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	d.runPCIScan(ctx) // the startup scan after the reboot

	devs, err := corrosion.ListPCIDevices(ctx, db, host, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	var owner string
	var found bool
	for _, x := range devs {
		if x.Address == dev.Address {
			owner, found = x.VMName, true
		}
	}
	if !found {
		t.Fatalf("device %s is not live after a scan that saw it", dev.Address)
	}
	if owner != "" {
		t.Errorf("owner = %q after the daemon's scan; the device is still assigned to a deleted VM", owner)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, db, host, dev.Address, "vm2"); err != nil || !ok {
		t.Fatalf("the reclaimed device must be assignable again: ok=%v err=%v", ok, err)
	}
}
