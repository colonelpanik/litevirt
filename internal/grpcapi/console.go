package grpcapi

import (
	"io"
	"log/slog"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ConsoleVM provides interactive console access to a VM's serial console.
//
// The VM name is passed via incoming metadata key "x-vm-name".
// It opens the PTY device that libvirt/QEMU allocates for the serial console
// and bridges it to the gRPC bidirectional stream for web UI terminal access.
func (s *Server) ConsoleVM(stream grpc.BidiStreamingServer[pb.ConsoleInput, pb.ConsoleOutput]) error {
	if err := s.requirePermPrecheck(stream.Context(), "operator"); err != nil {
		return err
	}
	md, _ := metadataFromStream(stream)
	vmName := ""
	if vals := md.Get("x-vm-name"); len(vals) > 0 {
		vmName = vals[0]
	}
	if vmName == "" {
		return status.Error(codes.InvalidArgument, "x-vm-name metadata required")
	}

	ctx := stream.Context()

	// Verify VM exists, is on this host, and is running.
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	// Path-scoped check on the VM's tenancy project (serial console = root
	// access to the guest). Enforced on the entry host where the caller's
	// identity is present, before any forward to the owning host.
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return err
	}
	// "backing-up" is an online state — the VM keeps running during a backup —
	// so the console must stay reachable (and a stuck backing-up flag must not
	// lock the operator out).
	if vm.State != "running" && vm.State != "backing-up" {
		return status.Errorf(codes.FailedPrecondition, "VM %q is not running", vmName)
	}

	// Remote VM: forward to the host that owns it.
	if vm.HostName != s.hostName {
		return s.forwardConsole(stream, vmName, vm.HostName)
	}

	// Get the PTY path from the live domain XML. Libvirt populates
	// <console type='pty'><source path='/dev/pts/N'/></console> at VM start.
	// A missing PTY is a VM-configuration condition (no serial console), not an
	// internal fault — report it as FailedPrecondition so the UI shows guidance.
	ptyPath, err := s.virt.ConsolePTYPath(vmName)
	if err != nil {
		slog.Warn("console pty unavailable", "vm", vmName, "error", err)
		return status.Errorf(codes.FailedPrecondition, "serial console not available for VM %q", vmName)
	}

	ptmx, err := os.OpenFile(ptyPath, os.O_RDWR, 0)
	if err != nil {
		return status.Errorf(codes.Internal, "open console PTY %s: %v", ptyPath, err)
	}
	defer ptmx.Close()

	slog.Info("console session started", "vm", vmName)

	errCh := make(chan error, 2)

	// PTY → gRPC stream
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&pb.ConsoleOutput{Data: buf[:n]}); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
		}
	}()

	// gRPC stream → PTY
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
			if _, err := ptmx.Write(msg.Data); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Wait for either direction to finish.
	err = <-errCh
	slog.Info("console session ended", "vm", vmName)
	if err != nil {
		return status.Errorf(codes.Internal, "console error: %v", err)
	}
	return nil
}

// forwardConsole relays a ConsoleVM stream to the remote host that owns the VM.
func (s *Server) forwardConsole(incoming grpc.BidiStreamingServer[pb.ConsoleInput, pb.ConsoleOutput], vmName, hostName string) error {
	ctx := incoming.Context()
	client, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", hostName, err)
	}
	defer conn.Close()

	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vmName))
	remote, err := client.ConsoleVM(outCtx)
	if err != nil {
		return remoteStreamErr(hostName, err)
	}

	errCh := make(chan error, 2)

	// incoming → remote
	go func() {
		for {
			msg, err := incoming.Recv()
			if err != nil {
				if err == io.EOF {
					remote.CloseSend()
					errCh <- nil
				} else {
					errCh <- err
				}
				return
			}
			if err := remote.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// remote → incoming
	go func() {
		for {
			msg, err := remote.Recv()
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
			if err := incoming.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	err = <-errCh
	return remoteStreamErr(hostName, err)
}

// remoteStreamErr converts an error from a forwarded peer console/VNC stream
// into a status that preserves the remote daemon's code and message — so
// conditions like "VM not running" / "VNC is not enabled" survive the hop —
// while classifying transport failures as Unavailable with the host name so
// the UI can show "host unreachable" instead of a generic disconnect.
func remoteStreamErr(hostName string, err error) error {
	if err == nil || err == io.EOF {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return status.Errorf(codes.Unavailable, "host %s unreachable: %v", hostName, err)
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded:
		return status.Errorf(codes.Unavailable, "host %s unreachable: %s", hostName, st.Message())
	default:
		return status.Error(st.Code(), st.Message())
	}
}
