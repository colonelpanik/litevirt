package grpcapi

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostUsageWithContainers is per-host resource usage as the OPERATOR-FACING views
// should report it: running-VM CPU/memory/disk plus memory held by running
// containers.
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
