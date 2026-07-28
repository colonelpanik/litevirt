package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A redefine of a VM that owns a PCI device which has since vanished from the host
// (tombstoned but still assigned) must FAIL rather than silently boot the guest
// without its passthrough hardware.
func TestUpdateVM_Redefine_MissingDevice_FailsPrecondition(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "gpu-vm", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "gpu-vm", Cpu: 4, MemoryMib: 4096}))

	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:01:00.0", Type: "gpu",
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, "test-host", "0000:01:00.0", "gpu-vm"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	// Device vanishes (tombstoned) but keeps its assignment.
	if err := corrosion.SoftDeletePCIDevice(ctx, s.db, "test-host", "0000:01:00.0"); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "gpu-vm", Cpu: 8})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for a vanished owned device, got: %v", err)
	}
}

// A CPU/memory-only redefine of a stopped VM patches the inactive XML in place,
// preserving libvirt-assigned details (here a stable PCI slot address) that a full
// regeneration would reshuffle.
func TestUpdateVM_Redefine_CPUOnly_PatchesInactiveXML(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "pin-vm", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "pin-vm", Cpu: 2, MemoryMib: 4096}))

	seeded := `<domain type='kvm'>
  <name>pin-vm</name>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <devices>
    <interface type='bridge'>
      <address type='pci' domain='0x0000' bus='0x03' slot='0x07' function='0x0'/>
    </interface>
  </devices>
</domain>`
	if err := s.virt.DefineDomain(seeded); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "pin-vm", Cpu: 6}); err != nil {
		t.Fatalf("cpu-only redefine: %v", err)
	}
	got, err := s.virt.DumpXML("pin-vm")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(got, "<vcpu placement='static'>6</vcpu>") {
		t.Errorf("cpu not patched to 6:\n%s", got)
	}
	if !strings.Contains(got, "slot='0x07' function='0x0'") {
		t.Errorf("patch reshuffled the PCI address (should be preserved verbatim):\n%s", got)
	}
}

// A full-regeneration redefine (machine change) rebuilds the VM's <hostdev>s from
// authoritative PCI ownership — the old inline builder dropped them.
func TestUpdateVM_Redefine_RebuildsHostdevsFromOwnership(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "gpu2", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "gpu2", Cpu: 4, MemoryMib: 4096, Machine: "pc"}))

	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:02:00.0", Type: "gpu",
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, "test-host", "0000:02:00.0", "gpu2"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	// Machine change → full regeneration path.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "gpu2", Machine: "q35"}); err != nil {
		t.Fatalf("redefine: %v", err)
	}
	got, err := s.virt.DumpXML("gpu2")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(got, "<hostdev") {
		t.Errorf("hostdev not rebuilt from ownership on redefine:\n%s", got)
	}
}
