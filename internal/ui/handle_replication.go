package ui

import (
	"io"
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handlePromoteModal renders the "Promote replica" modal for a VM, showing its
// replication targets so the operator knows where the replica lives.
func (s *Server) handlePromoteModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var targets []*pb.ReplicationSchedule
	if resp, err := s.grpc.ListReplicationSchedules(s.uiBearerCtx(r), &pb.ListReplicationSchedulesRequest{}); err == nil {
		for _, sc := range resp.GetSchedules() {
			if sc.GetVmName() == name {
				targets = append(targets, sc)
			}
		}
	}
	s.renderFragment(w, "promote_modal.html", map[string]any{
		"VMName":  name,
		"Targets": targets,
	})
}

// handlePromoteReplica drives PromoteReplica, draining the progress stream and
// reporting the outcome as a toast. On success it redirects to the (possibly
// renamed) recovered VM.
func (s *Server) handlePromoteReplica(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	req := &pb.PromoteReplicaRequest{
		VmName:     vmName,
		NewName:    strings.TrimSpace(r.FormValue("new_name")),
		TargetPool: strings.TrimSpace(r.FormValue("pool")),
		TargetHost: strings.TrimSpace(r.FormValue("host")),
		Replica:    strings.TrimSpace(r.FormValue("replica")),
		Force:      r.FormValue("force") == "on",
		NoLocalize: r.FormValue("no_localize") == "on",
	}
	stream, err := s.grpc.PromoteReplica(s.uiBearerCtx(r), req)
	if err != nil {
		sendToast(w, "Promote failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	for {
		_, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			sendToast(w, "Promote failed: "+rerr.Error(), "error")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	target := vmName
	if req.NewName != "" {
		target = req.NewName
	}
	sendToast(w, "Promoted "+target+" from replica", "success")
	w.Header().Set("HX-Redirect", "/vms/"+target)
	w.WriteHeader(http.StatusOK)
}
