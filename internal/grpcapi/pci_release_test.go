package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestReleaseDeviceSet_ScopedRollback is the over-release regression: rolling
// back a FAILED allocation must release only the devices that allocation
// claimed, never the VM's pre-existing passthrough devices.
func TestReleaseDeviceSet_ScopedRollback(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	// A pre-existing passthrough device (from an earlier CreateVM) + a device the
	// current, now-failed attach just claimed — both owned by vm1.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:01:00.0", Type: "gpu", VMName: "vm1",
	}); err != nil {
		t.Fatalf("seed pre-existing: %v", err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:02:00.0", Type: "gpu", VMName: "vm1",
	}); err != nil {
		t.Fatalf("seed new: %v", err)
	}

	// Roll back ONLY the just-claimed device.
	s.releaseDeviceSet(ctx, "vm1", []string{"0000:02:00.0"})

	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	owner := map[string]string{}
	for _, d := range devs {
		owner[d.Address] = d.VMName
	}
	if owner["0000:01:00.0"] != "vm1" {
		t.Fatalf("pre-existing device was over-released: owner=%q, want vm1", owner["0000:01:00.0"])
	}
	if owner["0000:02:00.0"] != "" {
		t.Fatalf("the rolled-back device should be released: owner=%q", owner["0000:02:00.0"])
	}
}
