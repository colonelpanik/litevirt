package ui

import (
	"io"
	"log/slog"
	"net/http"
	"strconv"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleRestoreModal(w http.ResponseWriter, r *http.Request) {
	nets, _ := s.grpc.ListNetworks(s.uiBearerCtx(r), &emptypb.Empty{})
	s.renderFragment(w, "backup_restore_modal.html", map[string]any{
		"Networks": nets.GetNetworks(),
	})
}

func (s *Server) handleRestoreVM(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(512 << 20); err != nil { // 512MB max
		http.Error(w, "bad form: "+err.Error(), 400)
		return
	}

	name := r.FormValue("name")
	cpu, _ := strconv.Atoi(r.FormValue("cpu"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mib"))
	network := r.FormValue("network")
	if name == "" {
		http.Error(w, "name required", 400)
		return
	}
	if cpu == 0 {
		cpu = 1
	}
	if mem == 0 {
		mem = 512
	}

	file, _, err := r.FormFile("backup_file")
	if err != nil {
		http.Error(w, "backup file required", 400)
		return
	}
	defer file.Close()

	stream, err := s.grpc.RestoreVM(s.uiBearerCtx(r))
	if err != nil {
		http.Error(w, "Restore failed: "+err.Error(), 500)
		return
	}

	buf := make([]byte, 256*1024) // 256KB chunks
	first := true
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			req := &pb.RestoreVMRequest{
				Chunk: buf[:n],
				Final: readErr == io.EOF,
			}
			if first {
				req.Name = name
				req.Cpu = int32(cpu)
				req.MemoryMib = int32(mem)
				req.Network = network
				first = false
			}
			if err := stream.Send(req); err != nil {
				slog.Error("restore stream send error", "error", err)
				sendToast(w, "Restore failed: "+err.Error(), "error")
				w.WriteHeader(500)
				return
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			slog.Error("restore read error", "error", readErr)
			sendToast(w, "Restore failed: "+readErr.Error(), "error")
			w.WriteHeader(500)
			return
		}
	}

	vm, err := stream.CloseAndRecv()
	if err != nil {
		slog.Error("restore close error", "error", err)
		sendToast(w, "Restore failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}

	sendToast(w, "VM '"+vm.Name+"' restored successfully", "success")
	w.Header().Set("HX-Redirect", "/vms/"+vm.Name)
	w.WriteHeader(http.StatusOK)
}
