package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"golang.org/x/term"
	"google.golang.org/grpc/metadata"
)

// StreamConsole opens an interactive console session to a VM via gRPC.
// The terminal is put into raw mode and stdin/stdout are bridged to the
// ConsoleVM bidirectional stream. Press Ctrl+] to disconnect.
func StreamConsole(ctx context.Context, client pb.LiteVirtClient, vmName string) error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("stdin is not a terminal")
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("set raw terminal: %w", err)
	}
	defer term.Restore(fd, oldState)

	ctx = metadata.AppendToOutgoingContext(ctx, "x-vm-name", vmName)
	stream, err := client.ConsoleVM(ctx)
	if err != nil {
		return fmt.Errorf("open console stream: %w", err)
	}

	errCh := make(chan error, 2)

	// stdin → gRPC stream
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				// Scan for Ctrl+] (0x1d) to disconnect.
				for i := 0; i < n; i++ {
					if buf[i] == 0x1d {
						stream.CloseSend()
						errCh <- nil
						return
					}
				}
				if sendErr := stream.Send(&pb.ConsoleInput{Data: buf[:n]}); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				stream.CloseSend()
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
		}
	}()

	// gRPC stream → stdout
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
			os.Stdout.Write(msg.Data)
		}
	}()

	return <-errCh
}
