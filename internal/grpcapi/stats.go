package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (s *Server) GetVMStats(ctx context.Context, req *pb.GetVMStatsRequest) (*pb.VMStats, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	// Resolve + authorize vm.read on the VM's own path (requireVMReadByName),
	// not just the cluster-wide viewer floor above: GetVMStats used to let a
	// caller scoped to one project read live CPU/mem/disk/net metrics for
	// every VM in the cluster.
	vm, err := s.requireVMReadByName(ctx, req.Name)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.GetVMStats(ctx, req)
	}

	ds, err := s.virt.GetDomainStats(req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get domain stats: %v", err)
	}

	return &pb.VMStats{
		Name:          ds.Name,
		CpuPct:        ds.CPUPct,
		MemRssBytes:   ds.MemRSSBytes,
		MemTotalBytes: ds.MemTotalBytes,
		DiskRdBytes:   ds.DiskRdBytes,
		DiskWrBytes:   ds.DiskWrBytes,
		DiskRdReqs:    ds.DiskRdReqs,
		DiskWrReqs:    ds.DiskWrReqs,
		NetRxBytes:    ds.NetRxBytes,
		NetTxBytes:    ds.NetTxBytes,
	}, nil
}

func (s *Server) GetHostStats(ctx context.Context, req *pb.GetHostStatsRequest) (*pb.HostResourceStats, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}

	// Only return stats for the local host.
	hostName := req.Name
	if hostName == "" {
		hostName = s.hostName
	}
	if hostName != s.hostName {
		client, conn, err := s.peerClient(ctx, hostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", hostName, err)
		}
		defer conn.Close()
		resp, ferr := client.GetHostStats(ctx, req)
		if ferr != nil {
			return nil, ferr
		}
		// Re-apply the ORIGINAL caller's scope to the forwarded answer. The
		// owning host served this request under the ENTRY node's host
		// certificate (admin, unless auth.forwarded_identity is on and
		// ForwardedIdentityV1 has latched — default off), so its own per-row
		// canReadVM filter passed every VM through: it never saw a caller
		// scoped to one project, only a peer. Returning that answer verbatim
		// handed a scoped caller every VM on every OTHER host in the cluster.
		// The vms table is replicated here, so this node can judge each name
		// against the real caller's scope without another round trip.
		filtered := resp.VmStats[:0:0]
		for _, vs := range resp.VmStats {
			if s.canReadVM(ctx, vs.Name) {
				filtered = append(filtered, vs)
			}
		}
		resp.VmStats = filtered
		return resp, nil
	}

	allStats, err := s.virt.GetAllDomainStats()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get all domain stats: %v", err)
	}

	result := &pb.HostResourceStats{
		HostName: s.hostName,
	}

	// Get host total memory.
	_, memMiB, err := s.virt.NodeInfo()
	if err == nil {
		result.MemTotalBytes = int64(memMiB) * 1024 * 1024
	}

	for _, ds := range allStats {
		// The host-wide totals sum every domain regardless of visibility —
		// they name no VM, so there is nothing here for a scoped caller to
		// read it shouldn't. Only the per-VM entry below is gated: GetHostStats
		// used to hand back every VM's name and live CPU/mem/disk/net metrics
		// to any cluster-wide viewer, with no regard for a caller scoped to
		// one project (canReadVM, vm.go).
		result.CpuPct += ds.CPUPct
		result.MemUsedBytes += ds.MemRSSBytes
		result.DiskRdBytes += ds.DiskRdBytes
		result.DiskWrBytes += ds.DiskWrBytes
		if !s.canReadVM(ctx, ds.Name) {
			continue
		}
		result.VmStats = append(result.VmStats, &pb.VMStats{
			Name:          ds.Name,
			CpuPct:        ds.CPUPct,
			MemRssBytes:   ds.MemRSSBytes,
			MemTotalBytes: ds.MemTotalBytes,
			DiskRdBytes:   ds.DiskRdBytes,
			DiskWrBytes:   ds.DiskWrBytes,
			DiskRdReqs:    ds.DiskRdReqs,
			DiskWrReqs:    ds.DiskWrReqs,
			NetRxBytes:    ds.NetRxBytes,
			NetTxBytes:    ds.NetTxBytes,
		})
	}

	return result, nil
}
