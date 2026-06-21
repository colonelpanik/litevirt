package grpcapi

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetVMLogs streams the libvirt QEMU log for a VM.
func (s *Server) GetVMLogs(req *pb.GetVMLogsRequest, stream grpc.ServerStreamingServer[pb.VMLogChunk]) error {
	if err := RequireRole(stream.Context(), "viewer"); err != nil {
		return err
	}

	ctx := stream.Context()
	vm, err := corrosion.GetVM(ctx, s.db, req.Name)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", req.Name)
	}

	// Forward to peer if VM is on a different host.
	if vm.HostName != s.hostName {
		return s.forwardVMLogs(req, stream, vm.HostName)
	}

	logPath := fmt.Sprintf("%s/%s.log", s.vmLogDir(), req.Name)
	lines := int(req.Lines)
	if lines <= 0 {
		lines = 50
	}

	// Read and send the last N lines.
	if err := sendTailLines(stream, logPath, lines); err != nil {
		return err
	}

	if !req.Follow {
		return nil
	}

	// Follow mode: poll for new data.
	f, err := os.Open(logPath)
	if err != nil {
		return status.Errorf(codes.Internal, "open log: %v", err)
	}
	defer f.Close()

	// Seek to end.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return status.Errorf(codes.Internal, "seek: %v", err)
	}

	reader := bufio.NewReader(f)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if sendErr := stream.Send(&pb.VMLogChunk{Data: line}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			// No new data yet — poll.
			time.Sleep(500 * time.Millisecond)
			reader.Reset(f)
		}
	}
}

// sendTailLines reads the last N lines of a file and sends them.
func sendTailLines(stream grpc.ServerStreamingServer[pb.VMLogChunk], path string, n int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return status.Errorf(codes.NotFound, "log file not found: %s", path)
		}
		return status.Errorf(codes.Internal, "read log: %v", err)
	}

	// Find the last N newlines.
	lines := 0
	start := len(data)
	for start > 0 && lines < n {
		start--
		if data[start] == '\n' {
			lines++
		}
	}
	if start > 0 {
		start++ // skip the newline itself
	}

	chunk := data[start:]
	if len(chunk) > 0 {
		return stream.Send(&pb.VMLogChunk{Data: chunk})
	}
	return nil
}

// forwardVMLogs relays a GetVMLogs stream to a remote host.
func (s *Server) forwardVMLogs(req *pb.GetVMLogsRequest, outgoing grpc.ServerStreamingServer[pb.VMLogChunk], hostName string) error {
	ctx := outgoing.Context()
	client, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", hostName, err)
	}
	defer conn.Close()

	remote, err := client.GetVMLogs(ctx, req)
	if err != nil {
		return status.Errorf(codes.Internal, "open remote log stream: %v", err)
	}

	for {
		msg, err := remote.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := outgoing.Send(msg); err != nil {
			return err
		}
	}
}
