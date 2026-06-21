package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// preStageSchema runs phase 1 of a rolling upgrade: it streams the new binary
// to every target and forward-migrates each one's schema WITHOUT swapping the
// live binary. It returns a non-nil error only when a host fails to pre-stage
// for a real reason (bad binary, locked DB, migration error) — in that case NO
// binary has been swapped yet, so the operator can fix the host and re-run.
//
// Hosts whose daemon predates the PreStageUpgrade RPC report Unimplemented and
// are skipped, not failed: they migrate themselves on restart, and a
// single-version skew is tolerated by the replication handshake. That makes the
// very upgrade that introduces this feature a clean no-op fallback.
func preStageSchema(ctx context.Context, client pb.LiteVirtClient, targets []*pb.Host, binaryPath string, force bool) error {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	checksum := sha256sum(data)

	fmt.Println("Pre-staging schema on all targets (safe — no restart)...")

	var prestaged, unsupported []string
	failed := map[string]string{}
	stagedSchema := int32(0)

	for _, h := range targets {
		resp, err := preStageOneHost(ctx, client, h, data, checksum, force)
		switch {
		case err == nil:
			prestaged = append(prestaged, h.Name)
			if resp != nil && resp.SchemaVersion > stagedSchema {
				stagedSchema = resp.SchemaVersion
			}
		case status.Code(err) == codes.Unimplemented:
			unsupported = append(unsupported, h.Name)
		default:
			failed[h.Name] = err.Error()
		}
	}

	// Hard failures abort the whole upgrade before any binary is swapped.
	if len(failed) > 0 {
		var b strings.Builder
		for name, msg := range failed {
			fmt.Fprintf(&b, "\n    %s: %s", name, msg)
		}
		return fmt.Errorf("pre-stage failed on %d host(s); no binaries were swapped — resolve and re-run:%s",
			len(failed), b.String())
	}

	switch {
	case len(prestaged) == 0:
		// Every target is on a daemon without the RPC (e.g. the bootstrap
		// upgrade that ships it). Fall back to the plain rolling upgrade.
		fmt.Println("  no daemon supports pre-staging yet — proceeding with rolling upgrade")
		fmt.Println("  (each node migrates its own schema on restart; single-version skew self-heals)")
	default:
		label := "schema"
		if stagedSchema > 0 {
			label = fmt.Sprintf("schema v%d", stagedSchema)
		}
		fmt.Printf("  pre-staged %s on %d host(s)", label, len(prestaged))
		if len(unsupported) > 0 {
			fmt.Printf("; %d on older daemons will migrate on restart (%s)",
				len(unsupported), strings.Join(unsupported, ", "))
		}
		fmt.Println()
	}
	fmt.Println()
	return nil
}

// preStageOneHost streams the binary to one host's PreStageUpgrade RPC.
func preStageOneHost(ctx context.Context, client pb.LiteVirtClient, h *pb.Host, data []byte, checksum string, force bool) (*pb.UpgradeHostResponse, error) {
	fmt.Printf("  %s: staging + migrating schema...\n", h.Name)
	stream, err := client.PreStageUpgrade(ctx)
	if err != nil {
		return nil, err
	}
	first := &pb.UpgradeHostRequest{
		Checksum:   checksum,
		TargetHost: h.Name,
		Force:      force,
	}
	return sendUpgradeStream(stream, data, first)
}

// sendUpgradeStream sends the first message (with metadata + initial chunk) and
// the remaining chunks, then closes and returns the server's response. A Send
// that returns io.EOF means the server already closed the stream (e.g. an
// Unimplemented RPC on an older daemon) — we stop sending and let CloseAndRecv
// surface the real status.
func sendUpgradeStream(stream grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], data []byte, first *pb.UpgradeHostRequest) (*pb.UpgradeHostResponse, error) {
	const chunkSize = 64 * 1024
	if len(data) > chunkSize {
		first.Chunk = data[:chunkSize]
		data = data[chunkSize:]
	} else {
		first.Chunk = data
		data = nil
	}
	if err := stream.Send(first); err != nil {
		if err == io.EOF {
			return stream.CloseAndRecv()
		}
		return nil, err
	}
	for len(data) > 0 {
		end := min(chunkSize, len(data))
		if err := stream.Send(&pb.UpgradeHostRequest{Chunk: data[:end]}); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		data = data[end:]
	}
	return stream.CloseAndRecv()
}
