package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// PreStageUpgrade receives the new binary, stages it next to the daemon binary,
// and forward-migrates the LOCAL state.db schema to whatever the staged binary
// expects — WITHOUT swapping the live binary or re-execing. Running it on every
// node before the rolling UpgradeHost pass guarantees no peer is ever missing
// schema when an already-upgraded node starts writing new columns, which is the
// only thing that makes a multi-version (skew > 1) rolling upgrade unsafe.
//
// It is safe to run against a live cluster: `schema-migrate` opens state.db with
// the same WAL + busy-timeout the daemon uses, and the migrations are additive
// and idempotent (a no-op when the schema didn't change). The schema bump is
// one-way per node, exactly like a normal upgrade — once staged, the running
// (old) daemon keeps serving, but it can no longer be cold-restarted on the old
// binary against the forward-migrated DB.
func (s *Server) PreStageUpgrade(stream grpc.ClientStreamingServer[pb.UpgradeHostRequest, pb.UpgradeHostResponse]) error {
	if err := RequireRole(stream.Context(), "admin"); err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "receive first chunk: %v", err)
	}

	// Forward to the peer if this stream is addressed elsewhere.
	if first.TargetHost != "" && first.TargetHost != s.hostName {
		return s.forwardPreStage(stream, first)
	}

	// Stage the binary next to (not over) the live daemon binary.
	stagingPath := s.daemonBinary() + ".new"
	if err := receiveBinaryToStaging(stream, first, stagingPath); err != nil {
		os.Remove(stagingPath)
		return err
	}

	// Run the STAGED binary's schema-migrate against our live state.db. This
	// is what actually forward-stages the schema while we keep running the old
	// binary. Shelling out also proves the new binary is executable on this
	// host (arch/glibc) before any swap — a useful pre-flight side effect.
	statePath := filepath.Join(s.dataDir, "state.db")
	mctx, cancel := context.WithTimeout(stream.Context(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(mctx, stagingPath, "schema-migrate", statePath).CombinedOutput()
	if err != nil {
		slog.Warn("prestage: schema-migrate failed", "host", s.hostName, "error", err, "output", string(out))
		return status.Errorf(codes.Internal, "schema-migrate on %s: %v (%s)", s.hostName, err, lastLine(out))
	}

	staged := parseStagedSchemaVersion(out)
	slog.Info("prestage: schema forward-migrated", "host", s.hostName, "staged_schema", staged)

	// The child process migrated the DB; THIS still-running daemon must refresh
	// its cached effective schema so its replication handshake immediately
	// advertises/accepts the freshly-staged version (otherwise it stays stale-low
	// and false-refuses peers during the rolling-binary window).
	if eff := s.db.RefreshDBSchemaVersion(stream.Context()); eff != int(staged) {
		slog.Info("prestage: refreshed effective DB schema", "host", s.hostName, "effective", eff)
	}

	return stream.SendAndClose(&pb.UpgradeHostResponse{
		HostName:      s.hostName,
		OldVersion:    s.version,
		NewVersion:    "staged",
		Status:        "ok",
		SchemaVersion: staged,
	})
}

// forwardPreStage relays a PreStageUpgrade stream to a remote peer.
func (s *Server) forwardPreStage(incoming grpc.ClientStreamingServer[pb.UpgradeHostRequest, pb.UpgradeHostResponse], first *pb.UpgradeHostRequest) error {
	ctx := incoming.Context()
	client, conn, err := s.peerClient(ctx, first.TargetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", first.TargetHost, err)
	}
	defer conn.Close()

	remote, err := client.PreStageUpgrade(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "open remote prestage stream: %v", err)
	}

	first.TargetHost = "" // remote processes it locally
	if err := remote.Send(first); err != nil {
		return err
	}
	for {
		msg, err := incoming.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := remote.Send(msg); err != nil {
			return err
		}
	}
	resp, err := remote.CloseAndRecv()
	if err != nil {
		return err
	}
	return incoming.SendAndClose(resp)
}

// receiveBinaryToStaging drains the upgrade stream into stagingPath and verifies
// the SHA-256 against the checksum carried on the first message. The first
// message (already received by the caller) supplies the initial chunk +
// checksum. Shared by UpgradeHost and PreStageUpgrade.
func receiveBinaryToStaging(stream grpc.ClientStreamingServer[pb.UpgradeHostRequest, pb.UpgradeHostResponse], first *pb.UpgradeHostRequest, stagingPath string) error {
	f, err := os.OpenFile(stagingPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return status.Errorf(codes.Internal, "create staging file: %v", err)
	}
	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)

	if len(first.Chunk) > 0 {
		if _, err := writer.Write(first.Chunk); err != nil {
			f.Close()
			return status.Errorf(codes.Internal, "write chunk: %v", err)
		}
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return status.Errorf(codes.Internal, "receive chunk: %v", err)
		}
		if len(msg.Chunk) > 0 {
			if _, err := writer.Write(msg.Chunk); err != nil {
				f.Close()
				return status.Errorf(codes.Internal, "write chunk: %v", err)
			}
		}
	}
	f.Close()

	actual := hex.EncodeToString(hasher.Sum(nil))
	if first.Checksum != "" && actual != first.Checksum {
		return status.Errorf(codes.InvalidArgument, "checksum mismatch: expected %s, got %s", first.Checksum, actual)
	}
	return nil
}

var schemaVersionRe = regexp.MustCompile(`version[=":\s]+(\d+)`)

// parseStagedSchemaVersion best-effort extracts the schema version from
// schema-migrate's log output (e.g. `... version=15`). Returns 0 if not found —
// it's informational only (shown to the operator), never load-bearing.
func parseStagedSchemaVersion(out []byte) int32 {
	m := schemaVersionRe.FindSubmatch(out)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0
	}
	return int32(n)
}

// lastLine returns the last non-empty line of out, for compact error messages.
func lastLine(out []byte) string {
	s := string(out)
	last := ""
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if line := s[start:i]; line != "" {
				last = line
			}
			start = i + 1
		}
	}
	return last
}
