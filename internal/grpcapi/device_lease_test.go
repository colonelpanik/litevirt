package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// TestBeginDeviceLease_Gating: the durable lease is written only when the
// operation_protocol capability is active (config flag AND latch).
func TestBeginDeviceLease_Gating(t *testing.T) {
	ctx := context.Background()

	// Inactive (default) → no-op, nothing written, and NO error (pre-latch no lease is expected).
	off := testServer(t)
	joff, _ := opjournal.Open(t.TempDir())
	off.SetOpJournal(joff)
	noopFinish, err := off.beginDeviceLease(ctx, "vm1", []string{"0000:01:00.0"}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("a gated no-op begin must not error (no lease expected pre-latch): %v", err)
	}
	noopFinish()
	if _, found, _ := joff.Read(deviceLeaseOpID("vm1")); found {
		t.Fatal("device lease must NOT be written while operation_protocol is inactive")
	}

	// Active (flag + latch) → written; finish() removes it.
	on := testServer(t)
	jon, _ := opjournal.Open(t.TempDir())
	on.SetOpJournal(jon)
	on.SetOperationProtocol(true)
	on.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.OperationProtocolV1: true}})
	finish, err := on.beginDeviceLease(ctx, "vm1", []string{"0000:01:00.0"}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("an active begin must succeed: %v", err)
	}
	if _, found, _ := jon.Read(deviceLeaseOpID("vm1")); !found {
		t.Fatal("device lease should be written when operation_protocol is active")
	}
	finish()
	if _, found, _ := jon.Read(deviceLeaseOpID("vm1")); found {
		t.Fatal("finish() should clear the device lease")
	}
}

// TestRecoverDeviceLeases: an orphaned lease (VM gone) rolls back its devices;
// a lease for an existing VM is just cleared. Both entries are removed.
func TestRecoverDeviceLeases(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	j, _ := opjournal.Open(t.TempDir())
	s.SetOpJournal(j)

	// Orphaned: device claimed to a VM that never finalized.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:01:00.0", Type: "gpu", VMName: "ghost-vm",
	}); err != nil {
		t.Fatalf("seed ghost device: %v", err)
	}
	if err := j.Write(opjournal.Entry{OperationID: deviceLeaseOpID("ghost-vm"), ResourceID: "ghost-vm",
		Kind: deviceLeaseKind, Artifacts: map[string]string{"addresses": "0000:01:00.0"}}); err != nil {
		t.Fatalf("write ghost lease: %v", err)
	}
	// Completed: VM exists and owns its device.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "real-vm", HostName: s.hostName, State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:02:00.0", Type: "gpu", VMName: "real-vm",
	}); err != nil {
		t.Fatalf("seed real device: %v", err)
	}
	if err := j.Write(opjournal.Entry{OperationID: deviceLeaseOpID("real-vm"), ResourceID: "real-vm",
		Kind: deviceLeaseKind, Artifacts: map[string]string{"addresses": "0000:02:00.0"}}); err != nil {
		t.Fatalf("write real lease: %v", err)
	}

	s.RecoverDeviceLeases(ctx)

	devs, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	owner := map[string]string{}
	for _, d := range devs {
		owner[d.Address] = d.VMName
	}
	if owner["0000:01:00.0"] != "" {
		t.Fatalf("orphaned lease device should be released, owner=%q", owner["0000:01:00.0"])
	}
	if owner["0000:02:00.0"] != "real-vm" {
		t.Fatalf("existing-VM device must be retained, owner=%q", owner["0000:02:00.0"])
	}
	if _, found, _ := j.Read(deviceLeaseOpID("ghost-vm")); found {
		t.Fatal("orphaned lease entry should be removed")
	}
	if _, found, _ := j.Read(deviceLeaseOpID("real-vm")); found {
		t.Fatal("completed lease entry should be removed")
	}
}
