package grpcapi

import (
	"context"
	"path/filepath"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostDiskFromPools is a host's disk fill as pb.Host reports it. Used and total
// are ONE measurement — the statfs figures (what `df` shows) the host writes
// into its storage_pools rows — so the ratio a consumer computes from them is
// the real fill (colonelpanik/litevirt#142).
//
// Pairing a statfs total with the VMs' declared disk sizes is what made healthy
// hosts read 98% full on a filesystem 27% used: thin provisioning lets declared
// size diverge from usage without limit. That figure is still reported, as
// disk_allocated_gib, under a name that cannot be read as usage.
//
// The pool rows cover pools created through the API as well as config pools,
// which hosts.disk_total — written once, at startup — does not.
//
// Each distinct target is counted once (after path cleaning): two pools rooted
// on one target are one filesystem, and counting both overstates both halves.
// Distinct targets that happen to share a filesystem cannot be recognised here,
// because the row carries no filesystem identity and only the owning host can
// statfs its paths. A pool with no target is counted on its own.
//
// With no pool row carrying capacity yet (early startup), total falls back to
// recordedTotalGiB, the same statfs basis, and used stays 0 rather than
// substituting allocation: actual usage is unknown, and a wrong number is worse
// than a missing one.
func hostDiskFromPools(pools []*pb.StoragePool, recordedTotalGiB int64) (usedGiB, totalGiB int64) {
	const gib = int64(1024 * 1024 * 1024)
	seen := map[string]bool{}
	var used, total int64
	for _, p := range pools {
		if t := p.GetTarget(); t != "" {
			t = filepath.Clean(t)
			if seen[t] {
				continue
			}
			seen[t] = true
		}
		used += p.GetUsedBytes()
		total += p.GetTotalBytes()
	}
	if total == 0 {
		return 0, recordedTotalGiB
	}
	return used / gib, total / gib
}

// hostUsageWithContainers is per-host resource usage as the OPERATOR-FACING views
// should report it: running-VM CPU/memory and declared disk allocation, plus
// memory held by running containers.
//
// Admission counts container memory against host capacity. A display that counts
// only VMs therefore contradicts it — a host could read "1024/2971 MiB" and still
// refuse a 1 GiB VM, because 2 GiB of containers were invisible in the column the
// operator was looking at. That reads as a litevirt bug rather than the capacity
// policy working.
//
// One helper rather than the same fold repeated at each call site: `lv host ls`
// and `lv status` build the same pb.Host from separate code, and letting them
// diverge is precisely how admission and placement came to disagree before
// HostAllocatable centralised that answer.
//
// Best-effort on the container read: an error degrades to VM-only usage rather
// than failing the whole listing.
func (s *Server) hostUsageWithContainers(ctx context.Context) map[string]corrosion.HostResourceUsage {
	usage, _ := corrosion.SumVMResourcesByHost(ctx, s.db)
	if usage == nil {
		usage = map[string]corrosion.HostResourceUsage{}
	}
	ctMem, err := corrosion.SumContainerMemoryByHost(ctx, s.db)
	if err != nil {
		return usage
	}
	for host, mem := range ctMem {
		u := usage[host]
		u.MemUsedMiB += mem
		usage[host] = u
	}
	return usage
}
