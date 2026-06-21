package ui

import (
	"context"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// StartCollector launches a background goroutine that polls host and VM
// stats every 5 seconds and stores them in in-memory ring buffers.
func (s *Server) StartCollector(ctx context.Context) {
	go s.collectLoop(ctx)
}

func (s *Server) collectLoop(ctx context.Context) {
	// Collect immediately on start.
	s.collectOnce(ctx)

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.collectOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) collectOnce(ctx context.Context) {
	now := time.Now().Unix()

	hosts, err := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return
	}

	for _, h := range hosts.GetHosts() {
		stats, err := s.grpc.GetHostStats(ctx, &pb.GetHostStatsRequest{Name: h.Name})
		if err != nil {
			continue
		}

		// Host ring.
		hr := s.getOrCreateRing("host:" + h.Name)
		var memPct float64
		if stats.MemTotalBytes > 0 {
			memPct = float64(stats.MemUsedBytes) / float64(stats.MemTotalBytes) * 100
		}
		hr.Push(StatsSample{
			Ts:     now,
			CPUPct: stats.CpuPct,
			MemPct: memPct,
		}, stats.DiskRdBytes, stats.DiskWrBytes, 0, 0)

		// Per-VM rings from host stats breakdown.
		for _, vs := range stats.VmStats {
			vr := s.getOrCreateRing("vm:" + vs.Name)
			var vmMemPct float64
			if vs.MemTotalBytes > 0 {
				vmMemPct = float64(vs.MemRssBytes) / float64(vs.MemTotalBytes) * 100
			}
			vr.Push(StatsSample{
				Ts:     now,
				CPUPct: vs.CpuPct,
				MemPct: vmMemPct,
			}, vs.DiskRdBytes, vs.DiskWrBytes, vs.NetRxBytes, vs.NetTxBytes)
		}
	}
}

func (s *Server) getOrCreateRing(key string) *StatsRing {
	if v, ok := s.statsRings.Load(key); ok {
		return v.(*StatsRing)
	}
	r := &StatsRing{}
	actual, _ := s.statsRings.LoadOrStore(key, r)
	return actual.(*StatsRing)
}
