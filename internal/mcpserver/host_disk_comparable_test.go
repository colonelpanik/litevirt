package mcpserver

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// disk_used_gib and disk_total_gib are emitted side by side in the host DTO,
// so any consumer — and an agent reading this JSON above all — will divide one
// by the other. They must therefore share a basis.
//
// They did not. disk_total_gib is a statfs figure (the sum of the host's pool
// targets, measured with the same call `df` makes), while disk_used_gib was
// the sum of the VMs' ALLOCATED virtual disk sizes. Thin provisioning makes
// those diverge without limit: a host whose VMs allocate 98 GiB of a 100 GiB
// filesystem reported "98% full" while df said 27%.
//
// Allocation is still worth reporting — it is what admission spends — so it
// keeps a field of its own under a name that says what it is.
func TestHostDTO_DiskUsedAndTotalShareABasis(t *testing.T) {
	const gib = int64(1024 * 1024 * 1024)

	h := &pb.Host{
		Name:         "node1",
		DiskTotalGib: 100,
		DiskUsedGib:  98, // allocated: three thin 32 GiB disks
		StoragePools: []*pb.StoragePool{
			{Name: "default", Target: "/var/lib/litevirt", TotalBytes: 100 * gib, UsedBytes: 27 * gib},
		},
	}

	out := hostDTO(h)

	if out.DiskUsedGiB != 27 {
		t.Errorf("disk_used_gib = %d, want 27 (actual/statfs, comparable with disk_total_gib); "+
			"reporting allocation here makes a 27%%-used filesystem read as 98%% full",
			out.DiskUsedGiB)
	}
	if out.DiskTotalGiB != 100 {
		t.Errorf("disk_total_gib = %d, want 100", out.DiskTotalGiB)
	}
	if out.DiskAllocatedGiB != 98 {
		t.Errorf("disk_allocated_gib = %d, want 98 — allocation must stay reported, under its own name",
			out.DiskAllocatedGiB)
	}
}

// Pools are deduplicated by target, matching how the daemon sums the host's
// disk total at registration. Two pools on one filesystem are one filesystem.
func TestHostDTO_PoolsSharingATargetCountOnce(t *testing.T) {
	const gib = int64(1024 * 1024 * 1024)

	h := &pb.Host{
		Name:         "node1",
		DiskTotalGib: 100,
		StoragePools: []*pb.StoragePool{
			{Name: "a", Target: "/data", TotalBytes: 100 * gib, UsedBytes: 27 * gib},
			{Name: "b", Target: "/data", TotalBytes: 100 * gib, UsedBytes: 27 * gib},
		},
	}

	if out := hostDTO(h); out.DiskUsedGiB != 27 {
		t.Errorf("disk_used_gib = %d, want 27 — two pools on one target are one filesystem, not two",
			out.DiskUsedGiB)
	}
}

// A host with no pool rows yet (early startup) must not report 0 GiB total and
// invite a divide-by-zero or a false "0% used". It falls back to the host
// record's registration figure, which is the same statfs basis.
func TestHostDTO_NoPoolsFallsBackToTheRegisteredTotal(t *testing.T) {
	h := &pb.Host{Name: "node1", DiskTotalGib: 100, DiskUsedGib: 98}

	out := hostDTO(h)
	if out.DiskTotalGiB != 100 {
		t.Errorf("disk_total_gib = %d, want the registered 100 when no pools are reported", out.DiskTotalGiB)
	}
	if out.DiskUsedGiB != 0 {
		t.Errorf("disk_used_gib = %d, want 0 — with no pool measurement, actual usage is unknown, "+
			"and reporting allocation here is the bug this fixes", out.DiskUsedGiB)
	}
	if out.DiskAllocatedGiB != 98 {
		t.Errorf("disk_allocated_gib = %d, want 98", out.DiskAllocatedGiB)
	}
}
