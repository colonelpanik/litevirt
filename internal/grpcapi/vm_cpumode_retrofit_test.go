package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
