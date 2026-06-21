package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestPreStageUpgrade_StagesAndMigrates drives the happy path: the staged
// binary (a stub that mimics `schema-migrate`) is received, run, and its
// schema version parsed — WITHOUT swapping the live binary or re-execing.
func TestPreStageUpgrade_StagesAndMigrates(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = dir

	// A stub that behaves like `litevirt schema-migrate`: ignores its args,
	// prints the completion log line, exits 0.
	stub := []byte("#!/bin/sh\necho 'schema migration complete db=x version=15'\nexit 0\n")
	h := sha256.Sum256(stub)
	checksum := hex.EncodeToString(h[:])

	stream := &fakeUpgradeStream{
		ctx:  adminCtx(),
		msgs: []*pb.UpgradeHostRequest{{Chunk: stub, Checksum: checksum}},
	}
	if err := s.PreStageUpgrade(stream); err != nil {
		t.Fatalf("PreStageUpgrade: %v", err)
	}
	if stream.response == nil || stream.response.Status != "ok" {
		t.Fatalf("unexpected response: %+v", stream.response)
	}
	if stream.response.SchemaVersion != 15 {
		t.Errorf("schema_version = %d, want 15", stream.response.SchemaVersion)
	}

	// The LIVE binary must be untouched (prestage never swaps).
	got, _ := os.ReadFile(s.binaryPath)
	if string(got) != "old-binary-content" {
		t.Errorf("live binary was modified by prestage: %q", string(got))
	}
	// The staged binary must be present at .new.
	staged, err := os.ReadFile(s.binaryPath + ".new")
	if err != nil || string(staged) != string(stub) {
		t.Errorf("staged binary missing/wrong: err=%v", err)
	}
	// No re-exec must have been signalled.
	select {
	case <-s.ReExecCh:
		t.Error("prestage must NOT signal a re-exec")
	default:
	}
}

func TestPreStageUpgrade_InsufficientRole(t *testing.T) {
	s, _ := upgradeTestServer(t)
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")
	stream := &fakeUpgradeStream{
		ctx:  ctx,
		msgs: []*pb.UpgradeHostRequest{{Chunk: []byte("data"), Checksum: "abc"}},
	}
	err := s.PreStageUpgrade(stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

// A failing schema-migrate (non-zero exit) surfaces as an error and must NOT
// swap the live binary.
func TestPreStageUpgrade_MigrateFailureDoesNotSwap(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = dir

	stub := []byte("#!/bin/sh\necho 'boom: incompatible arch' >&2\nexit 1\n")
	h := sha256.Sum256(stub)
	checksum := hex.EncodeToString(h[:])

	stream := &fakeUpgradeStream{
		ctx:  adminCtx(),
		msgs: []*pb.UpgradeHostRequest{{Chunk: stub, Checksum: checksum}},
	}
	err := s.PreStageUpgrade(stream)
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
	got, _ := os.ReadFile(s.binaryPath)
	if string(got) != "old-binary-content" {
		t.Errorf("live binary must be unchanged after a failed prestage, got %q", string(got))
	}
}

func TestParseStagedSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int32
	}{
		{"schema migration complete db=x version=15", 15},
		{`{"msg":"done","version":42}`, 42},
		{"nothing here", 0},
		{"version=", 0},
	} {
		if got := parseStagedSchemaVersion([]byte(tc.in)); got != tc.want {
			t.Errorf("parseStagedSchemaVersion(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestLastLine(t *testing.T) {
	if got := lastLine([]byte("a\nb\nc\n")); got != "c" {
		t.Errorf("lastLine = %q, want c", got)
	}
	if got := lastLine([]byte("only")); got != "only" {
		t.Errorf("lastLine = %q, want only", got)
	}
	if got := lastLine([]byte("")); got != "" {
		t.Errorf("lastLine = %q, want empty", got)
	}
}
