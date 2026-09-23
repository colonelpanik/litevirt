package main

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// NOTE: these exercise the pure selection only. They hand-build pb.VM values,
// so they CANNOT catch the server failing to populate Spec.CpuMode — which is
// exactly what happened: ListVMs ships a projection of the stored spec, cpu_mode
// was missing from it, and this report called every VM legacy on a live cluster
// while these tests stayed green. The projection itself is pinned by
// TestListVMsProjectsTheCPUMode in internal/grpcapi; keep both.
func TestLegacyCPUModeVMs(t *testing.T) {
	vms := []*pb.VM{
		// Reported: empty cpu_mode renders no <cpu> element → qemu64, no AVX.
		{Name: "legacy", HostName: "h1", Spec: &pb.VMSpec{Name: "legacy"}},
		// Not reported: they name a mode.
		{Name: "modern", HostName: "h1", Spec: &pb.VMSpec{Name: "modern", CpuMode: lv.CPUModeHostModel}},
		{Name: "pass", HostName: "h2", Spec: &pb.VMSpec{Name: "pass", CpuMode: lv.CPUModeHostPassthrough}},
		{Name: "pinned", HostName: "h2", Spec: &pb.VMSpec{Name: "pinned", CpuMode: lv.CPUModeCustom, CpuModel: "x86-64-v3"}},
		// Skipped: no spec at all, so there is nothing to act on.
		{Name: "specless", HostName: "h3"},
	}
	got := legacyCPUModeVMs(vms)
	if len(got) != 1 {
		t.Fatalf("legacyCPUModeVMs returned %d VMs (%+v), want just the empty-cpu_mode one", len(got), got)
	}
	if got[0].Name != "legacy" || got[0].Host != "h1" {
		t.Fatalf("legacyCPUModeVMs = %+v, want {legacy h1}", got[0])
	}
}

func TestLegacyCPUModeVMsEmptyWhenAllNameAMode(t *testing.T) {
	vms := []*pb.VM{
		{Name: "a", Spec: &pb.VMSpec{CpuMode: lv.CPUModeHostModel}},
		{Name: "b", Spec: &pb.VMSpec{CpuMode: lv.CPUModeHostPassthrough}},
	}
	if got := legacyCPUModeVMs(vms); len(got) != 0 {
		t.Fatalf("legacyCPUModeVMs = %+v, want none", got)
	}
}
