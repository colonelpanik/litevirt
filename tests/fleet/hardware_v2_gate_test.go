// Fleet scenario: what the hardware_v2 latch actually GATES.
//
// hardware_v2_latch_test.go proves the token negotiates correctly across the
// fleet. This file proves the latch is load-bearing: a stopped-VM PCI attach —
// the capability's headline new power — is refused outright while the fleet has
// not latched, and stops being refused once it has. Without this pairing a
// regression that latched perfectly but never consulted the latch (or vice
// versa) would slip through.
//
// The request travels the real path: a gRPC AttachDevice over mTLS into
// AttachDevice → attachPCIEntry → attachPCIOwner, where the gate lives
// (internal/grpcapi/hotplug_pci.go:216).

package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// gateRefusal is the substring the stopped-VM hardware gate refuses with. Matched
// on text because the code (FailedPrecondition) is shared with several unrelated
// preconditions on this path, and the point is to pin THIS refusal.
const gateRefusal = "until hardware_v2 is active"

func TestFleet_HardwareV2_GatesStoppedVMPCIAttach(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)

	// operation_protocol_v1 is a hard prerequisite of the PCI attach path itself
	// (attachPCIEntry refuses without it), so latch it first — otherwise the test
	// would be observing the wrong refusal.
	latchOperationProtocol(t, c, gates)

	const (
		vmName  = "vm-hw-gate"
		pciAddr = "0000:00:1f.0"
	)
	owner := c.Nodes[0]

	// A stopped VM owned by this node, and an unowned device in its PCI inventory
	// for the attach to claim.
	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: vmName, HostName: owner.Name, Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, owner.DB, corrosion.PCIDeviceRecord{
		HostName: owner.Name, Address: pciAddr,
		VendorID: "10de", DeviceID: "1eb8", Type: "gpu", Driver: "vfio-pci",
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
	// The audit pass treats the persistent domain definition as the membership
	// authority and BLOCKS adoption for a VM it can't read one for. Define a
	// hostdev-free domain so the VM adopts cleanly and the only thing standing
	// between the request and execution is the hardware_v2 gate itself.
	if err := owner.Virt.DefineDomain(
		`<domain type='kvm'><name>` + vmName + `</name><devices></devices></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}

	client := c.SelfClient(owner)
	attach := func() error {
		_, err := client.AttachDevice(ctx, &pb.AttachDeviceRequest{
			VmName:    vmName,
			PciDevice: &pb.DeviceSpec{Address: pciAddr},
		})
		return err
	}

	// Pre-latch: no node has completed its hardware backfill, so hardware_v2 is
	// unlatched and a stopped VM may not have PCI hardware mutated.
	err := attach()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), gateRefusal) {
		t.Fatalf("pre-latch stopped-VM PCI attach: got %v, want FailedPrecondition containing %q", err, gateRefusal)
	}

	// Latch hardware_v2 fleet-wide. The VM already exists, so the audit pass
	// adopts it rather than leaving it pending.
	backfillAll(t, c)
	for _, n := range c.Nodes {
		eventually(t, 10*time.Second, "hardware_v2 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.HardwareV2)
		})
	}

	// Post-latch: the identical request now runs to completion.
	if err := attach(); err != nil {
		t.Fatalf("post-latch stopped-VM PCI attach failed: %v", err)
	}

	// And it did the work, not merely returned OK: the device is claimed by the VM
	// in the shared host inventory (the exclusivity CAS attachPCIOwner takes).
	devs, err := corrosion.ListPCIDevices(ctx, owner.DB, owner.Name, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	var owned string
	for _, d := range devs {
		if d.Address == pciAddr {
			owned = d.VMName
		}
	}
	if owned != vmName {
		t.Fatalf("device %s claimed by %q after a latched attach, want %q", pciAddr, owned, vmName)
	}
}
