package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Retrofitting a CPU mode onto an EXISTING VM is the whole point of having the
// stored spec honored verbatim: a VM created before the default existed must be
// movable forward in place, without being recreated.
//
// This pins the retrofit end to end on a VM that has real state to lose — a
// named disk and a fixed MAC — because a redefine that regenerated either would
// be a data-loss bug dressed up as a CPU change.
func TestUpdateVM_RetrofitCPUModeOntoLegacyVM(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()

	legacy := &pb.VMSpec{
		Name: "legacy-vm", Cpu: 2, MemoryMib: 4096,
		Machine: "pc-q35-9.0", Firmware: "uefi",
		Disks: []*pb.DiskSpec{{Name: "root", Size: "20G", Bus: "virtio"}},
		Network: []*pb.NetworkAttachment{
			{Name: "br0", Model: "virtio", Mac: "52:54:00:ab:cd:ef"},
		},
	}
	// Seed the NIC and disk ROWS too, not just the spec: the redefine rebuilds
	// the domain's devices from those tables (GetVMInterfaces / GetVMDisks), so a
	// spec-only fixture would assert nothing about whether they survive.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{
			Name: "legacy-vm", HostName: "test-host", State: "stopped",
			CPUActual: 2, MemActual: 4096, Spec: seedSpecJSON(t, legacy),
		},
		[]corrosion.InterfaceRecord{{
			VMName: "legacy-vm", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:ab:cd:ef",
		}},
		[]corrosion.DiskRecord{{
			VMName: "legacy-vm", DiskName: "root", HostName: "test-host",
			Path: "/data/legacy-vm/root.qcow2", SizeBytes: 20 << 30, StorageType: "local",
		}},
	); err != nil {
		t.Fatalf("InsertVM legacy-vm: %v", err)
	}

	// Precondition: it really is a qemu64 VM — no cpu_mode at all.
	if got := loadStoredSpec(t, s, "legacy-vm").GetCpuMode(); got != "" {
		t.Fatalf("fixture cpu_mode = %q, want empty (the pre-default shape)", got)
	}

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name: "legacy-vm", CpuMode: lv.CPUModeHostModel,
	}); err != nil {
		t.Fatalf("retrofitting a cpu mode onto a stopped legacy VM: %v", err)
	}

	spec := loadStoredSpec(t, s, "legacy-vm")
	if spec.GetCpuMode() != lv.CPUModeHostModel {
		t.Fatalf("cpu_mode = %q, want %q", spec.GetCpuMode(), lv.CPUModeHostModel)
	}

	// The guest must actually get it: a spec saying host-model over a domain with
	// no <cpu> element would change nothing the VM can see.
	domXML, err := s.virt.DumpXML("legacy-vm")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(domXML, `mode="`+lv.CPUModeHostModel+`"`) {
		t.Errorf("redefined domain carries no %s cpu element:\n%s", lv.CPUModeHostModel, domXML)
	}

	// Nothing else may have been recreated underneath the guest.
	if len(spec.GetDisks()) != 1 || spec.GetDisks()[0].GetName() != "root" {
		t.Errorf("disks changed across the redefine: %+v", spec.GetDisks())
	}
	if len(spec.GetNetwork()) != 1 || spec.GetNetwork()[0].GetMac() != "52:54:00:ab:cd:ef" {
		t.Errorf("NIC MAC changed across the redefine: %+v", spec.GetNetwork())
	}
	if spec.GetMachine() != "pc-q35-9.0" {
		t.Errorf("machine type changed across the redefine: %q", spec.GetMachine())
	}
	if !strings.Contains(domXML, "52:54:00:ab:cd:ef") {
		t.Errorf("redefined domain lost the NIC MAC:\n%s", domXML)
	}
	if !strings.Contains(domXML, "/data/legacy-vm/root.qcow2") {
		t.Errorf("redefined domain lost the root disk:\n%s", domXML)
	}
}

// The same retrofit on a RUNNING VM is refused rather than applied behind the
// operator's back: the CPU a guest sees cannot change under it. UpdateVM never
// restarts implicitly — --restart-if-needed (allow_restart) is the opt-in.
func TestUpdateVM_RetrofitCPUModeRefusedOnRunningVM(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "busy-vm", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "busy-vm", Cpu: 2, MemoryMib: 4096}))

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name: "busy-vm", CpuMode: lv.CPUModeHostModel,
	})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("status = %v, want FailedPrecondition (err = %v)", got, err)
	}
	// And the spec must be untouched — a refused update that still persisted
	// would leave the stored CPU disagreeing with the running domain.
	if got := loadStoredSpec(t, s, "busy-vm").GetCpuMode(); got != "" {
		t.Fatalf("refused update still wrote cpu_mode = %q", got)
	}
}

// The retrofit must PATCH libvirt's own inactive XML, not regenerate the domain
// from the spec.
//
// It matters because GenerateDomainXML emits no guest-side PCI addresses, so a
// regeneration hands libvirt an unaddressed device list and lets it re-derive
// every slot. A Windows guest that keys its licensing off stable hardware
// addresses is the case that cares.
//
// The fixture seeds an inactive XML carrying libvirt-assigned <address>
// elements and a controller model that the spec does not describe at all. If the
// redefine regenerated, they would be gone — which is exactly what this asserts
// against.
func TestUpdateVM_RetrofitCPUModePatchesInPlaceKeepingPCIAddresses(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()

	legacy := &pb.VMSpec{
		Name: "pinned-vm", Cpu: 2, MemoryMib: 4096,
		Machine: "pc-q35-9.0", Firmware: "uefi",
		Disks: []*pb.DiskSpec{{Name: "root", Size: "20G", Bus: "virtio"}},
		Network: []*pb.NetworkAttachment{
			{Name: "br0", Model: "virtio", Mac: "52:54:00:ab:cd:ef"},
		},
	}
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{
			Name: "pinned-vm", HostName: "test-host", State: "stopped",
			CPUActual: 2, MemActual: 4096, Spec: seedSpecJSON(t, legacy),
		},
		[]corrosion.InterfaceRecord{{
			VMName: "pinned-vm", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:ab:cd:ef",
		}},
		[]corrosion.DiskRecord{{
			VMName: "pinned-vm", DiskName: "root", HostName: "test-host",
			Path: "/data/pinned-vm/root.qcow2", SizeBytes: 20 << 30, StorageType: "local",
		}},
	); err != nil {
		t.Fatalf("InsertVM pinned-vm: %v", err)
	}

	// libvirt's serialized form, with the details only libvirt knows.
	const pinnedAddr = `<address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>`
	inactive := `<domain type='kvm'>
  <name>pinned-vm</name>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <os><type arch='x86_64' machine='pc-q35-9.0'>hvm</type></os>
  <devices>
    <controller type='scsi' index='0' model='virtio-scsi'/>
    <disk type='file' device='disk'>
      <source file='/data/pinned-vm/root.qcow2'/>
      <target dev='vda' bus='virtio'/>
      ` + pinnedAddr + `
    </disk>
  </devices>
</domain>`
	if err := fake.DefineDomain(inactive); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	fake.SetInactiveXML("pinned-vm", inactive)

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name: "pinned-vm", CpuMode: lv.CPUModeHostModel,
	}); err != nil {
		t.Fatalf("retrofit: %v", err)
	}

	got, err := fake.DumpXMLInactive("pinned-vm")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if !strings.Contains(got, `mode="`+lv.CPUModeHostModel+`"`) &&
		!strings.Contains(got, `mode='`+lv.CPUModeHostModel+`'`) {
		t.Fatalf("redefined domain carries no %s cpu element:\n%s", lv.CPUModeHostModel, got)
	}
	if !strings.Contains(got, pinnedAddr) {
		t.Errorf("the redefine dropped libvirt's assigned PCI address, so it regenerated "+
			"instead of patching in place:\n%s", got)
	}
	if !strings.Contains(got, `model='virtio-scsi'`) {
		t.Errorf("the redefine dropped libvirt's controller model:\n%s", got)
	}
}

// The safety half: a memory-only edit on a VM that names no CPU mode must not
// gain a <cpu> element. Otherwise resizing a legacy VM's RAM would silently
// change the CPU its guest sees — a far worse surprise than the qemu64 default.
func TestUpdateVM_MemoryOnlyEditDoesNotAddACPUElement(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "mem-only", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "mem-only", Cpu: 2, MemoryMib: 4096, Machine: "pc-q35-9.0"}))

	inactive := `<domain type='kvm'>
  <name>mem-only</name>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <os><type arch='x86_64' machine='pc-q35-9.0'>hvm</type></os>
  <devices></devices>
</domain>`
	if err := fake.DefineDomain(inactive); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	fake.SetInactiveXML("mem-only", inactive)

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "mem-only", MemoryMib: 8192}); err != nil {
		t.Fatalf("memory-only update: %v", err)
	}

	got, err := fake.DumpXMLInactive("mem-only")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if strings.Contains(got, "<cpu") {
		t.Errorf("a memory-only edit added a <cpu> element, changing the guest CPU "+
			"as a side effect:\n%s", got)
	}
	if !strings.Contains(got, "8388608</memory>") {
		t.Errorf("memory was not actually updated:\n%s", got)
	}
	if spec := loadStoredSpec(t, s, "mem-only"); spec.GetCpuMode() != "" {
		t.Errorf("a memory-only edit wrote cpu_mode = %q", spec.GetCpuMode())
	}
}
