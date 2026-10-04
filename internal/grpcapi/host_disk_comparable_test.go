package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const testGiB = int64(1024 * 1024 * 1024)

// seedHostDiskFixture builds the shape colonelpanik/litevirt#142 was found on:
//
//   - the host's recorded disk_total (written at startup from config pools) is
//     438 GiB, its root filesystem;
//   - a config pool on that filesystem, 100 GiB with 27 GiB used, registered
//     twice under two names (two pools rooted on one target are one filesystem);
//   - an API-created pool on a separate 7000 GiB filesystem, 1000 GiB used;
//   - VMs whose DECLARED disk sizes sum to 98 GiB, one of them stopped.
//
// The right answer is used=1027, total=7100 (same source, deduplicated), with
// the 98 GiB of declared size reported separately as allocation.
func seedHostDiskFixture(t *testing.T, ctx context.Context, db *corrosion.Client, host string) {
	t.Helper()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: host, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CPUTotal: 8, MemTotal: 16384, DiskTotal: 438,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: host, Name: "default", Driver: "local", Target: "/var/lib/litevirt/disks",
			TotalBytes: 100 * testGiB, UsedBytes: 27 * testGiB, State: "active"},
		{HostName: host, Name: "alias", Driver: "local", Target: "/var/lib/litevirt/disks/",
			TotalBytes: 100 * testGiB, UsedBytes: 27 * testGiB, State: "active"},
		{HostName: host, Name: "bulk", Driver: "local", Target: "/srv/bulk",
			TotalBytes: 7000 * testGiB, UsedBytes: 1000 * testGiB, State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, db, p); err != nil {
			t.Fatalf("UpsertStoragePool(%s): %v", p.Name, err)
		}
	}
	for _, vm := range []struct {
		name, state string
		size        int64
	}{{"vm-a", "running", 40 * testGiB}, {"vm-b", "stopped", 58 * testGiB}} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm.name, HostName: host, State: vm.state, CPUActual: 1, MemActual: 512,
		}, nil, []corrosion.DiskRecord{{
			VMName: vm.name, DiskName: "root", HostName: host,
			Path: "/var/lib/litevirt/disks/" + vm.name + ".qcow2", SizeBytes: vm.size,
		}}); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.name, err)
		}
	}
}

func assertHostDiskComparable(t *testing.T, surface string, h *pb.Host) {
	t.Helper()
	if h == nil {
		t.Fatalf("%s: host missing from response", surface)
	}
	if h.GetDiskTotalGib() != 7100 {
		t.Errorf("%s: disk_total_gib = %d, want 7100 — the statfs total of every pool on this host "+
			"(API-created included), each filesystem once; not the 438 recorded from config pools",
			surface, h.GetDiskTotalGib())
	}
	if h.GetDiskUsedGib() != 1027 {
		t.Errorf("%s: disk_used_gib = %d, want 1027 — statfs used over the SAME pools as the total; "+
			"98 here is declared VM disk size, which is not comparable with the total",
			surface, h.GetDiskUsedGib())
	}
	if h.GetDiskAllocatedGib() != 98 {
		t.Errorf("%s: disk_allocated_gib = %d, want 98 — declared size of every VM disk, stopped VMs included",
			surface, h.GetDiskAllocatedGib())
	}
}

// TestHostDisk_UsedAndTotalShareOneSource pins colonelpanik/litevirt#142 on
// every gRPC surface that builds a pb.Host: disk_used_gib and disk_total_gib
// come from the same storage_pools rows, so their ratio is the real fill, and
// declared allocation travels separately in disk_allocated_gib.
func TestHostDisk_UsedAndTotalShareOneSource(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	seedHostDiskFixture(t, ctx, s.db, "h1")

	list, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	var listed *pb.Host
	for _, h := range list.GetHosts() {
		if h.GetName() == "h1" {
			listed = h
		}
	}
	assertHostDiskComparable(t, "ListHosts", listed)

	inspected, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "h1"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	assertHostDiskComparable(t, "InspectHost", inspected)

	cs, err := s.GetClusterStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	var status *pb.Host
	for _, h := range cs.GetHosts() {
		if h.GetName() == "h1" {
			status = h
		}
	}
	assertHostDiskComparable(t, "GetClusterStatus", status)
}

// TestHostDisk_NoPoolRowsFallsBackWithoutInventingUsage: before any pool row
// carries capacity (early startup), total falls back to the host's recorded
// figure — the same statfs basis — and used stays 0. Substituting allocation
// for the unknown usage is exactly the bug.
func TestHostDisk_NoPoolRowsFallsBackWithoutInventingUsage(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", State: "active", DiskTotal: 438,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm-a", HostName: "h1", State: "running"},
		nil, []corrosion.DiskRecord{{VMName: "vm-a", DiskName: "root", HostName: "h1", Path: "/x", SizeBytes: 98 * testGiB}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	h, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "h1"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	list, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	cs, err := s.GetClusterStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	for surface, got := range map[string]*pb.Host{
		"InspectHost": h, "ListHosts": list.GetHosts()[0], "GetClusterStatus": cs.GetHosts()[0],
	} {
		if got.GetDiskTotalGib() != 438 {
			t.Errorf("%s: disk_total_gib = %d, want the recorded 438 when no pool carries capacity", surface, got.GetDiskTotalGib())
		}
		if got.GetDiskUsedGib() != 0 {
			t.Errorf("%s: disk_used_gib = %d, want 0 — usage is unknown, and allocation is not a stand-in", surface, got.GetDiskUsedGib())
		}
		if got.GetDiskAllocatedGib() != 98 {
			t.Errorf("%s: disk_allocated_gib = %d, want 98", surface, got.GetDiskAllocatedGib())
		}
	}
}
