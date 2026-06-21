package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func (s *Server) GetClusterStatus(ctx context.Context, _ *emptypb.Empty) (*pb.ClusterStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}

	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list VMs: %v", err)
	}

	// Single query for per-host VM counts instead of N+1.
	vmCounts, _ := corrosion.CountVMsByHost(ctx, s.db)
	// Aggregate CPU/memory/disk allocated to running VMs per host.
	resUsage, _ := corrosion.SumVMResourcesByHost(ctx, s.db)

	cs := &pb.ClusterStatus{
		HostsTotal: int32(len(hosts)),
		VmsTotal:   int32(len(vms)),
	}

	for _, h := range hosts {
		if h.State == "active" {
			cs.HostsActive++
		}
		usage := resUsage[h.Name]
		cs.Hosts = append(cs.Hosts, &pb.Host{
			Name:         h.Name,
			Address:      h.Address,
			State:        hostStateToPB(h.State),
			CpuTotal:     int32(h.CPUTotal),
			MemTotalMib:  int32(h.MemTotal),
			DiskTotalGib: int64(h.DiskTotal),
			CpuUsed:      int32(usage.CpuUsed),
			MemUsedMib:   int32(usage.MemUsedMiB),
			DiskUsedGib:  int64(usage.DiskUsedGiB),
			VmCount:      int32(vmCounts[h.Name]),
			StoragePools: s.storagePoolsForHost(ctx, h.Name),
		})
	}

	for _, vm := range vms {
		switch vm.State {
		case "running":
			cs.VmsRunning++
		case "error":
			cs.VmsError++
		}
	}

	// Get cluster name
	rows, err := s.db.Query(ctx, `SELECT name FROM cluster LIMIT 1`)
	if err == nil && len(rows) > 0 {
		cs.ClusterName = rows[0].String("name")
	}

	return cs, nil
}
