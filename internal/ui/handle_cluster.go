package ui

import (
	"context"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

type hostRow struct {
	Host         *pb.Host
	CPUPct       int
	MemPct       int
	DiskPct      int
	DiskUsedGiB  int64 // actual (statfs/df), not allocated
	DiskTotalGiB int64
}

func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	cs, err := s.grpc.GetClusterStatus(ctx, &emptypb.Empty{})
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})

	recentVMs := vms.GetVms()
	if len(recentVMs) > 10 {
		recentVMs = recentVMs[:10]
	}

	data := s.pageData("Dashboard", "cluster")
	if err != nil {
		data["Error"] = err.Error()
	} else {
		hosts := cs.GetHosts()
		stats := clusterStats(hosts, vms.GetVms())
		data["Stats"] = stats
		data["HostRows"] = buildHostRows(hosts)
		data["RecentVMs"] = recentVMs
		data["Events"] = s.recentEvents(ctx, 8)
		data["Alerts"] = cs.GetAlerts()
	}
	s.renderPage(w, "cluster.html", data)
}

func (s *Server) handleClusterStats(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	cs, err := s.grpc.GetClusterStatus(ctx, &emptypb.Empty{})
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})

	recentVMs := vms.GetVms()
	if len(recentVMs) > 10 {
		recentVMs = recentVMs[:10]
	}

	data := map[string]any{"ClusterName": s.cluster}
	if err != nil {
		data["Error"] = err.Error()
	} else {
		hosts := cs.GetHosts()
		data["Stats"] = clusterStats(hosts, vms.GetVms())
		data["HostRows"] = buildHostRows(hosts)
		data["RecentVMs"] = recentVMs
		data["Events"] = s.recentEvents(ctx, 8)
		data["Alerts"] = cs.GetAlerts()
	}
	s.renderPartial(w, "cluster.html", "cluster-live", data)
}

// recentEvents fetches the most recent cluster-wide events from the durable,
// replicated vm_events store (the same source as the /events page) for the
// dashboard's "Recent Events" panel. GetClusterStatus does not populate events,
// so the panel must read them here. Returns nil on error (panel shows empty).
func (s *Server) recentEvents(ctx context.Context, limit int32) []*pb.VMEvent {
	resp, err := s.grpc.ListVMEvents(ctx, &pb.ListVMEventsRequest{Limit: limit})
	if err != nil {
		return nil
	}
	return resp.GetEvents()
}

func buildHostRows(hosts []*pb.Host) []hostRow {
	rows := make([]hostRow, 0, len(hosts))
	for _, h := range hosts {
		cpuPct, memPct, diskPct := 0, 0, 0
		if h.CpuTotal > 0 {
			cpuPct = int(h.CpuUsed) * 100 / int(h.CpuTotal)
		}
		if h.MemTotalMib > 0 {
			memPct = int(h.MemUsedMib) * 100 / int(h.MemTotalMib)
		}
		// Disk: actual (statfs/df) usage across the host's pools, not allocated.
		diskUsed, diskTotal := sumPoolActual(h.GetStoragePools())
		if diskTotal > 0 {
			diskPct = int(diskUsed * 100 / diskTotal)
		}
		rows = append(rows, hostRow{
			Host: h, CPUPct: cpuPct, MemPct: memPct, DiskPct: diskPct,
			DiskUsedGiB:  diskUsed / (1024 * 1024 * 1024),
			DiskTotalGiB: diskTotal / (1024 * 1024 * 1024),
		})
	}
	return rows
}
