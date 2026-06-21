package ui

import (
	"encoding/json"
	"fmt"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (s *Server) handleVMStatsPartial(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	stats, err := s.grpc.GetVMStats(s.uiBearerCtx(r), &pb.GetVMStatsRequest{Name: name})
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="card-sub" style="color:var(--muted)">stats unavailable</div>`)
		return
	}
	s.renderFragment(w, "vm_stats_partial.html", stats)
}

func (s *Server) handleHostStatsPartial(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	stats, err := s.grpc.GetHostStats(s.uiBearerCtx(r), &pb.GetHostStatsRequest{Name: name})
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="card-sub" style="color:var(--muted)">stats unavailable</div>`)
		return
	}
	s.renderFragment(w, "host_stats_partial.html", stats)
}

func (s *Server) handleHostStatsHistory(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, ok := s.statsRings.Load("host:" + name)
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.Write([]byte("[]"))
		return
	}
	json.NewEncoder(w).Encode(v.(*StatsRing).Snapshot())
}

func (s *Server) handleVMStatsHistory(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, ok := s.statsRings.Load("vm:" + name)
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.Write([]byte("[]"))
		return
	}
	json.NewEncoder(w).Encode(v.(*StatsRing).Snapshot())
}
