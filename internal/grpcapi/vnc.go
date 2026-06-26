package grpcapi

import (
	"fmt"
	"io"
	"log/slog"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ProxyVNC provides a bidirectional byte stream to the VNC port of a running VM.
// The VM name is passed via incoming metadata key "x-vm-name".
// If the VM is on a remote host, this handler forwards to the remote daemon.
func (s *Server) ProxyVNC(stream grpc.BidiStreamingServer[pb.VNCData, pb.VNCData]) error {
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

	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", vmName)
	}
	// Path-scoped check on the VM's tenancy project — a console is interactive
	// root access to the guest, so a broad operator role isn't enough; the
	// caller must hold vm.console on THIS VM. Enforced on the entry host where
	// the caller's identity is present (a forwarded peer call carries the
	// daemon's identity, not the user's).
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.console", "operator"); err != nil {
		return err
	}
	// "backing-up" is an online state — the VM keeps running during a backup —
	// so VNC must stay reachable (and a stuck backing-up flag must not lock the
	// operator out).
	if vm.State != "running" && vm.State != "backing-up" {
		return status.Errorf(codes.FailedPrecondition, "VM %q is not running", vmName)
	}

	// Remote VM: forward to the host that owns it.
	if vm.HostName != s.hostName {
		return s.forwardVNC(stream, vmName, vm.HostName)
	}

	// Local VM: connect to the VNC port. A missing VNC graphics device means
	// the VM was created headless (DisableVnc) — report it as a clear
	// configuration condition rather than a vague "not available".
	port, err := s.virt.GetVMVNCPort(vmName)
	if err != nil || port < 0 {
		slog.Warn("vnc port unavailable", "vm", vmName, "error", err)
		return status.Errorf(codes.FailedPrecondition, "VNC is not enabled for VM %q", vmName)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return status.Errorf(codes.Internal, "connect to VNC port %d: %v", port, err)
	}
	defer conn.Close()

	slog.Info("VNC proxy session started", "vm", vmName, "port", port)

	errCh := make(chan error, 2)

	// VNC TCP → gRPC stream
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&pb.VNCData{Data: buf[:n]}); sendErr != nil {
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

	// gRPC stream → VNC TCP
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
			if _, err := conn.Write(msg.Data); err != nil {
				errCh <- err
				return
			}
		}
	}()

	err = <-errCh
	slog.Info("VNC proxy session ended", "vm", vmName)
	if err != nil {
		return status.Errorf(codes.Internal, "VNC proxy error: %v", err)
	}
	return nil
}

// forwardVNC relays a ProxyVNC stream to a remote daemon.
func (s *Server) forwardVNC(incoming grpc.BidiStreamingServer[pb.VNCData, pb.VNCData], vmName, hostName string) error {
	ctx := incoming.Context()
	client, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", hostName, err)
	}
	defer conn.Close()

	// Forward x-vm-name metadata to the remote daemon.
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vmName))
	remote, err := client.ProxyVNC(outCtx)
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
