package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeUpgradeStream implements grpc.ClientStreamingServer for UpgradeHost tests.
type fakeUpgradeStream struct {
	grpc.ClientStreamingServer[pb.UpgradeHostRequest, pb.UpgradeHostResponse]
	ctx      context.Context
	msgs     []*pb.UpgradeHostRequest
	recvIdx  int
	response *pb.UpgradeHostResponse
}

func (f *fakeUpgradeStream) Context() context.Context { return f.ctx }
func (f *fakeUpgradeStream) Recv() (*pb.UpgradeHostRequest, error) {
	if f.recvIdx >= len(f.msgs) {
		return nil, io.EOF
	}
	msg := f.msgs[f.recvIdx]
	f.recvIdx++
	return msg, nil
}
func (f *fakeUpgradeStream) SendAndClose(resp *pb.UpgradeHostResponse) error {
	f.response = resp
	return nil
}

func upgradeTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)
	s.version = "v1.0.0"

	dir := t.TempDir()
	s.binaryPath = filepath.Join(dir, "litevirtd")

	// Write a fake "current" binary so backup works.
	if err := os.WriteFile(s.binaryPath, []byte("old-binary-content"), 0755); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestUpgradeHost_FullFlow(t *testing.T) {
	s, dir := upgradeTestServer(t)

	newBinary := []byte("#!/bin/sh\necho new-binary-v2")
	h := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(h[:])

	stream := &fakeUpgradeStream{
		ctx: adminCtx(),
		msgs: []*pb.UpgradeHostRequest{
			{Chunk: newBinary, Checksum: checksum},
		},
	}

	if err := s.UpgradeHost(stream); err != nil {
		t.Fatalf("UpgradeHost: %v", err)
	}

	// Verify response.
	if stream.response == nil {
		t.Fatal("no response received")
	}
	if stream.response.Status != "ok" {
		t.Errorf("status = %q, want ok", stream.response.Status)
	}
	if stream.response.HostName != s.hostName {
		t.Errorf("host = %q, want %q", stream.response.HostName, s.hostName)
	}
	if stream.response.OldVersion != "v1.0.0" {
		t.Errorf("old version = %q, want v1.0.0", stream.response.OldVersion)
	}

	// Verify the binary was swapped.
	got, err := os.ReadFile(s.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBinary) {
		t.Errorf("binary content = %q, want %q", string(got), string(newBinary))
	}

	// Verify backup exists.
	backup, err := os.ReadFile(s.binaryPath + ".old")
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != "old-binary-content" {
		t.Errorf("backup = %q, want old-binary-content", string(backup))
	}

	// Verify staging file was cleaned up (renamed to final path).
	if _, err := os.Stat(filepath.Join(dir, "litevirtd.new")); !os.IsNotExist(err) {
		t.Error("staging file should not exist after successful upgrade")
	}

	// Verify ReExecCh was signalled.
	select {
	case <-s.ReExecCh:
		// good
	default:
		t.Error("ReExecCh should have been signalled")
	}
}

func TestUpgradeHost_MultiChunk(t *testing.T) {
	s, _ := upgradeTestServer(t)

	// Split binary across multiple chunks.
	chunk1 := []byte("chunk-one-data-")
	chunk2 := []byte("chunk-two-data-")
	chunk3 := []byte("chunk-three-end")
	full := append(append(chunk1, chunk2...), chunk3...)
	h := sha256.Sum256(full)
	checksum := hex.EncodeToString(h[:])

	stream := &fakeUpgradeStream{
		ctx: adminCtx(),
		msgs: []*pb.UpgradeHostRequest{
			{Chunk: chunk1, Checksum: checksum},
			{Chunk: chunk2},
			{Chunk: chunk3},
		},
	}

	if err := s.UpgradeHost(stream); err != nil {
		t.Fatalf("UpgradeHost: %v", err)
	}

	got, err := os.ReadFile(s.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(full) {
		t.Errorf("binary = %q, want %q", string(got), string(full))
	}
}

func TestUpgradeHost_ChecksumMismatch(t *testing.T) {
	s, dir := upgradeTestServer(t)

	stream := &fakeUpgradeStream{
		ctx: adminCtx(),
		msgs: []*pb.UpgradeHostRequest{
			{Chunk: []byte("binary data"), Checksum: "definitely-wrong-checksum"},
		},
	}

	err := s.UpgradeHost(stream)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", st.Code())
	}
	if !strings.Contains(st.Message(), "checksum mismatch") {
		t.Errorf("message = %q, want checksum mismatch", st.Message())
	}

	// Staging file should be cleaned up on checksum failure.
	if _, err := os.Stat(filepath.Join(dir, "litevirtd.new")); !os.IsNotExist(err) {
		t.Error("staging file should be removed after checksum mismatch")
	}

	// Original binary should be untouched.
	got, _ := os.ReadFile(s.binaryPath)
	if string(got) != "old-binary-content" {
		t.Errorf("original binary was modified: %q", string(got))
	}
}

func TestUpgradeHost_NoChecksumSkipsVerification(t *testing.T) {
	s, _ := upgradeTestServer(t)

	stream := &fakeUpgradeStream{
		ctx: adminCtx(),
		msgs: []*pb.UpgradeHostRequest{
			{Chunk: []byte("no-checksum-binary"), Checksum: ""},
		},
	}

	if err := s.UpgradeHost(stream); err != nil {
		t.Fatalf("UpgradeHost: %v", err)
	}

	got, _ := os.ReadFile(s.binaryPath)
	if string(got) != "no-checksum-binary" {
		t.Errorf("binary = %q, want no-checksum-binary", string(got))
	}
}

func TestUpgradeHost_InsufficientRole(t *testing.T) {
	s, _ := upgradeTestServer(t)

	ctx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")

	stream := &fakeUpgradeStream{
		ctx:  ctx,
		msgs: []*pb.UpgradeHostRequest{{Chunk: []byte("data"), Checksum: "abc"}},
	}

	err := s.UpgradeHost(stream)
	if err == nil {
		t.Fatal("expected permission denied")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", st.Code())
	}
}

func TestUpgradeHost_EmptyStream(t *testing.T) {
	s, _ := upgradeTestServer(t)

	stream := &fakeUpgradeStream{
		ctx:  adminCtx(),
		msgs: nil,
	}

	err := s.UpgradeHost(stream)
	if err == nil {
		t.Fatal("expected error for empty stream")
	}
}

func TestUpgradeHost_ForwardToPeer(t *testing.T) {
	s, _ := upgradeTestServer(t)

	stream := &fakeUpgradeStream{
		ctx: adminCtx(),
		msgs: []*pb.UpgradeHostRequest{
			{Chunk: []byte("data"), Checksum: "abc", TargetHost: "remote-peer"},
		},
	}

	err := s.UpgradeHost(stream)
	if err == nil {
		t.Fatal("expected error for unreachable peer")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code())
	}
}

func TestUpgradeHost_SelfTarget(t *testing.T) {
	s, _ := upgradeTestServer(t)

	data := []byte("self-target-binary")
	h := sha256.Sum256(data)

	stream := &fakeUpgradeStream{
		ctx: adminCtx(),
		msgs: []*pb.UpgradeHostRequest{
			{Chunk: data, Checksum: hex.EncodeToString(h[:]), TargetHost: s.hostName},
		},
	}

	// Self-target should process locally, not forward.
	if err := s.UpgradeHost(stream); err != nil {
		t.Fatalf("UpgradeHost with self target: %v", err)
	}
	got, _ := os.ReadFile(s.binaryPath)
	if string(got) != string(data) {
		t.Errorf("binary = %q, want %q", string(got), string(data))
	}
}

func TestUpgradeHost_LargeBinary(t *testing.T) {
	s, _ := upgradeTestServer(t)

	// 512KB binary in chunks.
	data := make([]byte, 512*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	h := sha256.Sum256(data)
	checksum := hex.EncodeToString(h[:])

	const chunkSize = 64 * 1024
	var msgs []*pb.UpgradeHostRequest
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		msg := &pb.UpgradeHostRequest{Chunk: data[i:end]}
		if i == 0 {
			msg.Checksum = checksum
		}
		msgs = append(msgs, msg)
	}

	stream := &fakeUpgradeStream{ctx: adminCtx(), msgs: msgs}
	if err := s.UpgradeHost(stream); err != nil {
		t.Fatalf("UpgradeHost: %v", err)
	}

	got, _ := os.ReadFile(s.binaryPath)
	if len(got) != len(data) {
		t.Errorf("size = %d, want %d", len(got), len(data))
	}
	gotH := sha256.Sum256(got)
	if hex.EncodeToString(gotH[:]) != checksum {
		t.Error("written binary checksum doesn't match")
	}
}

func TestUpgradeHost_ReExecSignal(t *testing.T) {
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	select {
	case s.ReExecCh <- struct{}{}:
	default:
		t.Error("ReExecCh should accept a signal")
	}
	select {
	case s.ReExecCh <- struct{}{}:
		t.Error("ReExecCh should be full after one signal")
	default:
	}
}

func TestCopyFile_Success(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	content := []byte("binary data with \x00 bytes \xff")
	if err := os.WriteFile(src, content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != string(content) {
		t.Errorf("copied content mismatch")
	}
	info, _ := os.Stat(dst)
	if info.Mode()&0111 == 0 {
		t.Errorf("dst should be executable, mode = %v", info.Mode())
	}
}

func TestCopyFile_SrcNotExist(t *testing.T) {
	dir := t.TempDir()
	if err := copyFile("/nonexistent/src", filepath.Join(dir, "dst")); err == nil {
		t.Fatal("expected error")
	}
}

func TestCopyFile_DstDirNotExist(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("data"), 0644)
	if err := copyFile(src, "/nonexistent/dir/dst"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCopyFile_LargeFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "large")
	dst := filepath.Join(dir, "large_copy")
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(src, data, 0644)
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if len(got) != len(data) {
		t.Errorf("size = %d, want %d", len(got), len(data))
	}
}

func TestCopyFile_Overwrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	os.WriteFile(src, []byte("new content"), 0644)
	os.WriteFile(dst, []byte("old content that is longer"), 0644)
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "new content" {
		t.Errorf("got %q, want %q", string(got), "new content")
	}
}

func TestDaemonBinary_Default(t *testing.T) {
	s := &Server{}
	if got := s.daemonBinary(); got != "/usr/local/bin/litevirt" {
		t.Errorf("daemonBinary() = %q, want default", got)
	}
}

func TestDaemonBinary_Override(t *testing.T) {
	s := &Server{binaryPath: "/tmp/test/litevirtd"}
	if got := s.daemonBinary(); got != "/tmp/test/litevirtd" {
		t.Errorf("daemonBinary() = %q, want /tmp/test/litevirtd", got)
	}
}
