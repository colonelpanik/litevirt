package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func writeFakeBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "litevirtd")
	if err := os.WriteFile(p, []byte("fake-binary-bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPreStageSchema_AllOK(t *testing.T) {
	bin := writeFakeBinary(t)
	client := &mockUpgradeClient{
		preStageStream: &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", SchemaVersion: 15}},
	}
	targets := []*pb.Host{{Name: "node1"}, {Name: "node2"}}
	if err := preStageSchema(context.Background(), client, targets, bin, false); err != nil {
		t.Fatalf("preStageSchema: %v", err)
	}
}

// An older daemon without the RPC returns Unimplemented — that's a graceful
// skip (fall back to plain rolling upgrade), NOT a failure that aborts.
func TestPreStageSchema_UnimplementedFallsBack(t *testing.T) {
	bin := writeFakeBinary(t)
	client := &mockUpgradeClient{
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Unimplemented, "method PreStageUpgrade not implemented")},
	}
	targets := []*pb.Host{{Name: "old-node"}}
	if err := preStageSchema(context.Background(), client, targets, bin, false); err != nil {
		t.Fatalf("Unimplemented must NOT abort the upgrade, got: %v", err)
	}
}

// A real pre-stage failure (e.g. migration error) must abort before any binary
// is swapped, so the operator can fix it and re-run.
func TestPreStageSchema_HardFailureAborts(t *testing.T) {
	bin := writeFakeBinary(t)
	client := &mockUpgradeClient{
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Internal, "schema-migrate: disk full")},
	}
	targets := []*pb.Host{{Name: "node1"}}
	err := preStageSchema(context.Background(), client, targets, bin, false)
	if err == nil {
		t.Fatal("expected preStageSchema to abort on a hard failure")
	}
	if !strings.Contains(err.Error(), "node1") {
		t.Errorf("error should name the failed host: %v", err)
	}
}

// HostUpgrade must abort (and swap NOTHING) when pre-staging fails.
func TestHostUpgrade_AbortsBeforeActivateOnPreStageFailure(t *testing.T) {
	bin := writeFakeBinary(t)
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &mockUpgradeClient{
		stream:         activate,
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Internal, "boom")},
		hosts:          []*pb.Host{{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"}},
	}
	err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin,
		HostNames:  []string{"node1"},
		Yes:        true,
	})
	if err == nil {
		t.Fatal("HostUpgrade should fail when pre-stage fails")
	}
	if len(activate.sent) != 0 {
		t.Errorf("no binary should have been swapped after a pre-stage failure, but %d activate chunk(s) were sent", len(activate.sent))
	}
}

// --no-prestage skips phase 1 entirely and still upgrades.
func TestHostUpgrade_NoPreStageSkipsPhase1(t *testing.T) {
	bin := writeFakeBinary(t)
	activate := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	// preStageStream returns an error — but with NoPreStage it must never be called.
	client := &mockUpgradeClient{
		stream:         activate,
		preStageStream: &mockUpgradeStream{closeErr: status.Error(codes.Internal, "should not be called")},
		hosts:          []*pb.Host{{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"}},
	}
	err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: bin,
		HostNames:  []string{"node1"},
		Yes:        true,
		NoPreStage: true,
	})
	if err != nil {
		t.Fatalf("HostUpgrade --no-prestage: %v", err)
	}
	if len(activate.sent) == 0 {
		t.Error("expected the activate phase to run with --no-prestage")
	}
}
