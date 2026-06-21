package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// --- Mock gRPC client for upgradeOneHost tests ---

type mockUpgradeClient struct {
	pb.LiteVirtClient
	stream *mockUpgradeStream
	err    error
	hosts  []*pb.Host // returned by ListHosts (for HostUpgrade tests)

	// Pre-stage phase knobs (HostUpgrade phase 1). When preStageStream is nil
	// PreStageUpgrade returns a fresh always-ok stream, so existing activate-
	// phase assertions on `stream` aren't disturbed by the new prestage pass.
	preStageStream *mockUpgradeStream
	preStageErr    error
}

func (m *mockUpgradeClient) UpgradeHost(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.stream, nil
}

func (m *mockUpgradeClient) PreStageUpgrade(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	if m.preStageErr != nil {
		return nil, m.preStageErr
	}
	if m.preStageStream != nil {
		return m.preStageStream, nil
	}
	return &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}, nil
}

func (m *mockUpgradeClient) Ping(_ context.Context, _ *pb.PingRequest, _ ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{HostName: "test-host", Version: "v1.0.0"}, nil
}

func (m *mockUpgradeClient) ListHosts(_ context.Context, _ *pb.ListHostsRequest, _ ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: m.hosts}, nil
}

type mockUpgradeStream struct {
	grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse]
	sent     []*pb.UpgradeHostRequest
	response *pb.UpgradeHostResponse
	sendErr  error
	closeErr error
}

func (m *mockUpgradeStream) Send(req *pb.UpgradeHostRequest) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, req)
	return nil
}

func (m *mockUpgradeStream) CloseAndRecv() (*pb.UpgradeHostResponse, error) {
	if m.closeErr != nil {
		return nil, m.closeErr
	}
	return m.response, nil
}

func (m *mockUpgradeStream) Header() (metadata.MD, error) { return nil, nil }
func (m *mockUpgradeStream) Trailer() metadata.MD         { return nil }
func (m *mockUpgradeStream) CloseSend() error             { return nil }
func (m *mockUpgradeStream) Context() context.Context     { return context.Background() }
func (m *mockUpgradeStream) SendMsg(any) error            { return nil }
func (m *mockUpgradeStream) RecvMsg(any) error            { return io.EOF }

// --- sha256sum tests ---

func TestSha256sum_Empty(t *testing.T) {
	got := sha256sum([]byte{})
	h := sha256.Sum256([]byte{})
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("sha256sum(empty) = %q, want %q", got, want)
	}
}

func TestSha256sum_KnownValue(t *testing.T) {
	got := sha256sum([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("sha256sum('hello') = %q, want %q", got, want)
	}
}

func TestSha256sum_BinaryData(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	got := sha256sum(data)
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("sha256sum(binary) = %q, want %q", got, want)
	}
}

func TestSha256sum_LargeData(t *testing.T) {
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	got := sha256sum(data)
	if len(got) != 64 {
		t.Errorf("sha256sum length = %d, want 64", len(got))
	}
	got2 := sha256sum(data)
	if got != got2 {
		t.Error("sha256sum should be deterministic")
	}
}

func TestSha256sum_DifferentInputs(t *testing.T) {
	a := sha256sum([]byte("input-a"))
	b := sha256sum([]byte("input-b"))
	if a == b {
		t.Error("different inputs should produce different hashes")
	}
}

// --- versionLabel tests ---

func TestVersionLabel_Empty(t *testing.T) {
	if got := versionLabel(""); got != "(unknown)" {
		t.Errorf("versionLabel('') = %q, want '(unknown)'", got)
	}
}

func TestVersionLabel_NonEmpty(t *testing.T) {
	if got := versionLabel("v1.2.3"); got != "v1.2.3" {
		t.Errorf("versionLabel('v1.2.3') = %q", got)
	}
}

func TestVersionLabel_Dev(t *testing.T) {
	if got := versionLabel("dev"); got != "dev" {
		t.Errorf("versionLabel('dev') = %q", got)
	}
}

// --- Struct tests ---

func TestHostResult_Fields(t *testing.T) {
	r := hostResult{Name: "node1", Status: "ok", OldVersion: "v1.0", NewVersion: "v1.1"}
	if r.Name != "node1" || r.Status != "ok" {
		t.Errorf("unexpected: %+v", r)
	}
}

func TestHostResult_ErrorState(t *testing.T) {
	r := hostResult{Name: "node2", Status: "error", Error: "connection refused"}
	if r.Status != "error" || r.Error == "" {
		t.Errorf("unexpected: %+v", r)
	}
}

func TestUpgradeOpts_Fields(t *testing.T) {
	opts := UpgradeOpts{BinaryPath: "/tmp/litevirtd", HostNames: []string{"n1", "n2"}, Yes: true}
	if opts.BinaryPath != "/tmp/litevirtd" || len(opts.HostNames) != 2 || !opts.Yes {
		t.Errorf("unexpected: %+v", opts)
	}
}

// --- upgradeOneHost tests ---

func TestUpgradeOneHost_Success(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	binaryContent := []byte("#!/bin/sh\necho new-version")
	os.WriteFile(binaryPath, binaryContent, 0755)

	stream := &mockUpgradeStream{
		response: &pb.UpgradeHostResponse{
			HostName:   "node1",
			OldVersion: "v1.0",
			NewVersion: "v1.1",
			Status:     "ok",
		},
	}
	client := &mockUpgradeClient{stream: stream}

	h := &pb.Host{Name: "node1", Address: "10.0.0.1", Version: "v1.0"}
	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v1.1", false)

	if res.Status != "ok" {
		t.Errorf("status = %q, want ok", res.Status)
	}
	if res.NewVersion != "v1.1" {
		t.Errorf("new version = %q, want v1.1", res.NewVersion)
	}
	if res.Name != "node1" {
		t.Errorf("name = %q, want node1", res.Name)
	}

	// Verify chunks were sent.
	if len(stream.sent) == 0 {
		t.Fatal("no chunks sent")
	}

	// First chunk should have checksum and target_host.
	first := stream.sent[0]
	if first.Checksum == "" {
		t.Error("first chunk should have checksum")
	}
	if first.TargetHost != "node1" {
		t.Errorf("target_host = %q, want node1", first.TargetHost)
	}

	// Verify checksum matches actual binary.
	chk := sha256sum(binaryContent)
	if first.Checksum != chk {
		t.Errorf("checksum = %q, want %q", first.Checksum, chk)
	}
}

// TestUpgradeOneHost_PlumbsForce asserts --force reaches the server in the first
// UpgradeHostRequest. Without this, server-side preflight blocks (e.g. the
// failover-leader fence check) can never be overridden from the CLI — which is
// exactly the bug that left the leader host un-upgradeable.
func TestUpgradeOneHost_PlumbsForce(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	for _, force := range []bool{true, false} {
		stream := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok"}}
		client := &mockUpgradeClient{stream: stream}
		h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

		res := upgradeOneHost(context.Background(), client, h, binaryPath, "v1.0", force)
		if res.Status != "ok" {
			t.Fatalf("force=%v: status=%q err=%q", force, res.Status, res.Error)
		}
		if len(stream.sent) == 0 {
			t.Fatalf("force=%v: no chunks sent", force)
		}
		if stream.sent[0].Force != force {
			t.Errorf("force=%v: first request Force=%v, want %v", force, stream.sent[0].Force, force)
		}
	}
}

// TestHostUpgrade_NamedHostNotSkippedOnVersionMatch is the regression for the
// no-op bug: an explicitly named host whose version equals the connected host's
// must still be deployed. Before the fix the version-equality check (keyed off
// the connected daemon, not the --binary) silently skipped it, printing "All
// hosts are up-to-date" — which made seeding a node impossible.
func TestHostUpgrade_NamedHostNotSkippedOnVersionMatch(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	stream := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v1.0.0"}}
	client := &mockUpgradeClient{
		stream: stream,
		// node1 is on the SAME version the connected host reports (v1.0.0).
		hosts: []*pb.Host{{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"}},
	}

	err := HostUpgrade(context.Background(), client, UpgradeOpts{
		BinaryPath: binaryPath,
		HostNames:  []string{"node1"},
		Yes:        true,
	})
	if err != nil {
		t.Fatalf("HostUpgrade: %v", err)
	}
	if len(stream.sent) == 0 {
		t.Error("explicitly named same-version host was skipped (should be re-deployed)")
	}
}

// writeVersionStub writes an executable stub at path that prints the given
// version in litevirtd's `--version` format, so binaryVersion can probe it.
func writeVersionStub(t *testing.T, path, version string) {
	t.Helper()
	stub := "#!/bin/sh\necho \"litevirtd version=" + version + " commit=deadbeef\"\n"
	if err := os.WriteFile(path, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestHostUpgrade_NoArgRollsNewerBinaryToUniformCluster is the regression for
// the no-op bug: `lv host upgrade --binary X` (no host args) on a cluster
// uniformly on the OLD version must still roll X everywhere. The "outdated"
// check now compares each host to the BINARY's version (probed via --version),
// not the connected daemon's — which previously matched every host and printed
// "All hosts are up-to-date", deploying nothing.
func TestHostUpgrade_NoArgRollsNewerBinaryToUniformCluster(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "litevirtd")
	writeVersionStub(t, binaryPath, "v2.0.0") // newer than the cluster

	stream := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0.0"}}
	client := &mockUpgradeClient{
		stream: stream,
		// Whole cluster uniformly on v1.0.0 — same as the connected daemon (Ping → v1.0.0).
		hosts: []*pb.Host{
			{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"},
			{Name: "node2", Address: "10.0.0.2", Version: "v1.0.0"},
		},
	}

	if err := HostUpgrade(context.Background(), client, UpgradeOpts{BinaryPath: binaryPath, Yes: true}); err != nil {
		t.Fatalf("HostUpgrade: %v", err)
	}
	if len(stream.sent) == 0 {
		t.Fatal("no-arg upgrade with a newer binary rolled nothing to a uniform cluster (the no-op bug)")
	}
}

// TestHostUpgrade_NoArgSkipsWhenBinaryMatchesCluster confirms the skip still
// works: a no-arg upgrade whose binary matches the cluster's version deploys
// nothing (genuinely up-to-date).
func TestHostUpgrade_NoArgSkipsWhenBinaryMatchesCluster(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "litevirtd")
	writeVersionStub(t, binaryPath, "v1.0.0") // same as the cluster

	stream := &mockUpgradeStream{response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v1.0.0"}}
	client := &mockUpgradeClient{
		stream: stream,
		hosts:  []*pb.Host{{Name: "node1", Address: "10.0.0.1", Version: "v1.0.0"}},
	}

	if err := HostUpgrade(context.Background(), client, UpgradeOpts{BinaryPath: binaryPath, Yes: true}); err != nil {
		t.Fatalf("HostUpgrade: %v", err)
	}
	if len(stream.sent) != 0 {
		t.Fatalf("binary matches cluster version — nothing should deploy, but %d chunk(s) were sent", len(stream.sent))
	}
}

func TestUpgradeOneHost_LargeBinaryChunking(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	// 200KB binary — should be split into multiple 64KB chunks.
	data := make([]byte, 200*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(binaryPath, data, 0755)

	stream := &mockUpgradeStream{
		response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: "v2.0"},
	}
	client := &mockUpgradeClient{stream: stream}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v2.0", false)
	if res.Status != "ok" {
		t.Fatalf("status = %q, error = %q", res.Status, res.Error)
	}

	// Should have sent multiple chunks: ceil(200*1024 / 64*1024) = 4 messages.
	if len(stream.sent) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(stream.sent))
	}

	// Reassemble and verify.
	var assembled []byte
	for _, msg := range stream.sent {
		assembled = append(assembled, msg.Chunk...)
	}
	if len(assembled) != len(data) {
		t.Errorf("assembled size = %d, want %d", len(assembled), len(data))
	}
}

func TestUpgradeOneHost_BinaryNotFound(t *testing.T) {
	stream := &mockUpgradeStream{
		response: &pb.UpgradeHostResponse{Status: "ok"},
	}
	client := &mockUpgradeClient{stream: stream}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

	res := upgradeOneHost(context.Background(), client, h, "/nonexistent/binary", "v1.0", false)
	if res.Status != "error" {
		t.Errorf("status = %q, want error", res.Status)
	}
	if res.Error == "" {
		t.Error("expected error message for missing binary")
	}
}

func TestUpgradeOneHost_StreamOpenError(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	client := &mockUpgradeClient{err: io.ErrUnexpectedEOF}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v1.0", false)
	if res.Status != "error" {
		t.Errorf("status = %q, want error", res.Status)
	}
}

func TestUpgradeOneHost_SendError(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	stream := &mockUpgradeStream{sendErr: io.ErrClosedPipe}
	client := &mockUpgradeClient{stream: stream}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v1.0", false)
	if res.Status != "error" {
		t.Errorf("status = %q, want error", res.Status)
	}
}

func TestUpgradeOneHost_CloseError(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	stream := &mockUpgradeStream{closeErr: io.ErrUnexpectedEOF}
	client := &mockUpgradeClient{stream: stream}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v1.0", false)
	if res.Status != "error" {
		t.Errorf("status = %q, want error", res.Status)
	}
}

func TestUpgradeOneHost_ServerError(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	stream := &mockUpgradeStream{
		response: &pb.UpgradeHostResponse{
			Status: "error",
			Error:  "disk full",
		},
	}
	client := &mockUpgradeClient{stream: stream}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1"}

	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v1.0", false)
	if res.Status != "error" {
		t.Errorf("status = %q, want error", res.Status)
	}
	if res.Error != "disk full" {
		t.Errorf("error = %q, want 'disk full'", res.Error)
	}
}

func TestUpgradeOneHost_FallbackVersion(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "litevirtd")
	os.WriteFile(binaryPath, []byte("binary"), 0755)

	// Server returns empty NewVersion — should fall back to targetVersion.
	stream := &mockUpgradeStream{
		response: &pb.UpgradeHostResponse{Status: "ok", NewVersion: ""},
	}
	client := &mockUpgradeClient{stream: stream}
	h := &pb.Host{Name: "node1", Address: "10.0.0.1", Version: "v1.0"}

	res := upgradeOneHost(context.Background(), client, h, binaryPath, "v2.0", false)
	if res.NewVersion != "v2.0" {
		t.Errorf("new version = %q, want v2.0 (fallback)", res.NewVersion)
	}
}

// Ensure unused imports don't break (emptypb used by full LiteVirtClient interface).
var _ = (*emptypb.Empty)(nil)
