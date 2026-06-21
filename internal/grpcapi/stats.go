package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func (s *Server) GetVMStats(ctx context.Context, req *pb.GetVMStatsRequest) (*pb.VMStats, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	// Verify the VM is on this host and running.
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
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
	if err := RequireRole(ctx, "viewer"); err != nil {
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
		return client.GetHostStats(ctx, req)
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
		vmStats := &pb.VMStats{
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
		}
		result.VmStats = append(result.VmStats, vmStats)
		result.CpuPct += ds.CPUPct
		result.MemUsedBytes += ds.MemRSSBytes
		result.DiskRdBytes += ds.DiskRdBytes
		result.DiskWrBytes += ds.DiskWrBytes
	}

	return result, nil
}
