package ui

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleVMLogsPage renders the VM logs viewer page.
func (s *Server) handleVMLogsPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	data := s.pageData(name+" Logs", "vms")
	data["VMName"] = name
	s.renderPage(w, "vm_logs.html", data)
}

// handleVMLogsStream is an SSE endpoint that streams VM console logs.
func (s *Server) handleVMLogsStream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	lines := int32(100)
	if l, err := strconv.Atoi(r.URL.Query().Get("lines")); err == nil && l > 0 {
		lines = int32(l)
	}
	follow := r.URL.Query().Get("follow") != "false"

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	disableStreamWriteTimeout(w) // log follow is long-lived; don't let the 30s WriteTimeout drop it

	stream, err := s.grpc.GetVMLogs(s.uiBearerCtx(r), &pb.GetVMLogsRequest{
		Name:   name,
		Follow: follow,
		Lines:  lines,
	})
	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
		flusher.Flush()
		return
	}

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			fmt.Fprintf(w, "event: done\ndata: EOF\n\n")
			flusher.Flush()
			return
		}
		if err != nil {
			slog.Error("log stream error", "vm", name, "error", err)
			return
		}
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", chunk.Data)
		flusher.Flush()
	}
}

// handleStackLogsPage renders a tabbed logs viewer for all VMs in a stack.
func (s *Server) handleStackLogsPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)

	// Get stack VMs
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{StackName: name})
	var stackVMs []string
	for _, v := range vms.GetVms() {
		stackVMs = append(stackVMs, v.Name)
	}

	data := s.pageData(name+" Logs", "stacks")
	data["StackName"] = name
	data["VMNames"] = stackVMs
	s.renderPage(w, "stack_logs.html", data)
}
