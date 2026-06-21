package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeLogStream implements grpc.ServerStreamingServer[pb.VMLogChunk] for tests.
type fakeLogStream struct {
	grpc.ServerStreamingServer[pb.VMLogChunk]
	ctx    context.Context
	chunks []*pb.VMLogChunk
}

func (f *fakeLogStream) Context() context.Context { return f.ctx }
func (f *fakeLogStream) Send(c *pb.VMLogChunk) error {
	f.chunks = append(f.chunks, c)
	return nil
}

func logsTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := testServer(t)
	s.ReExecCh = make(chan struct{}, 1)
	s.ShutdownCh = make(chan struct{}, 1)

	logDir := t.TempDir()
	s.logDir = logDir
	return s, logDir
}

// --- sendTailLines unit tests ---

func TestSendTailLines_LastNLines(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	content := "line1\nline2\nline3\nline4\nline5\n"
	os.WriteFile(logFile, []byte(content), 0644)

	stream := &fakeLogStream{ctx: adminCtx()}
	if err := sendTailLines(stream, logFile, 3); err != nil {
		t.Fatalf("sendTailLines: %v", err)
	}
	if len(stream.chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(stream.chunks))
	}
	got := string(stream.chunks[0].Data)
	if !strings.Contains(got, "line4") || !strings.Contains(got, "line5") {
		t.Errorf("expected last lines, got: %q", got)
	}
	if strings.Contains(got, "line1") || strings.Contains(got, "line2") {
		t.Errorf("should not contain early lines, got: %q", got)
	}
}

func TestSendTailLines_FewerLinesThanRequested(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	content := "only\ntwo\n"
	os.WriteFile(logFile, []byte(content), 0644)

	stream := &fakeLogStream{ctx: adminCtx()}
	if err := sendTailLines(stream, logFile, 100); err != nil {
		t.Fatalf("sendTailLines: %v", err)
	}
	if len(stream.chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(stream.chunks))
	}
	if got := string(stream.chunks[0].Data); got != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestSendTailLines_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "empty.log")
	os.WriteFile(logFile, []byte{}, 0644)

	stream := &fakeLogStream{ctx: adminCtx()}
	if err := sendTailLines(stream, logFile, 10); err != nil {
		t.Fatalf("sendTailLines: %v", err)
	}
	if len(stream.chunks) != 0 {
		t.Errorf("expected no chunks for empty file, got %d", len(stream.chunks))
	}
}

func TestSendTailLines_MissingFile(t *testing.T) {
	stream := &fakeLogStream{ctx: adminCtx()}
	err := sendTailLines(stream, "/nonexistent/log.log", 10)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("code = %v, want NotFound", st.Code())
	}
}

func TestSendTailLines_SingleLine(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "single.log")
	os.WriteFile(logFile, []byte("single line\n"), 0644)

	stream := &fakeLogStream{ctx: adminCtx()}
	if err := sendTailLines(stream, logFile, 10); err != nil {
		t.Fatalf("sendTailLines: %v", err)
	}
	if len(stream.chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(stream.chunks))
	}
	if got := string(stream.chunks[0].Data); got != "single line\n" {
		t.Errorf("got %q, want %q", got, "single line\n")
	}
}

func TestSendTailLines_NoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "notail.log")
	os.WriteFile(logFile, []byte("line1\nline2\nline3"), 0644)

	stream := &fakeLogStream{ctx: adminCtx()}
	if err := sendTailLines(stream, logFile, 2); err != nil {
		t.Fatalf("sendTailLines: %v", err)
	}
	if len(stream.chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(stream.chunks))
	}
	got := string(stream.chunks[0].Data)
	if !strings.Contains(got, "line2") || !strings.Contains(got, "line3") {
		t.Errorf("expected last 2 lines, got: %q", got)
	}
}

func TestSendTailLines_LargeFile(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "large.log")
	var lines []string
	for i := 0; i < 1000; i++ {
		lines = append(lines, strings.Repeat("x", 80))
	}
	content := strings.Join(lines, "\n") + "\n"
	os.WriteFile(logFile, []byte(content), 0644)

	stream := &fakeLogStream{ctx: adminCtx()}
	if err := sendTailLines(stream, logFile, 5); err != nil {
		t.Fatalf("sendTailLines: %v", err)
	}
	if len(stream.chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(stream.chunks))
	}
	count := strings.Count(string(stream.chunks[0].Data), "\n")
	if count < 1 || count > 5 {
		t.Errorf("got %d newlines, want between 1 and 5", count)
	}
}

// --- Full GetVMLogs handler tests (using logDir) ---

func TestGetVMLogs_VMNotFound(t *testing.T) {
	s, _ := logsTestServer(t)

	req := &pb.GetVMLogsRequest{Name: "nonexistent-vm"}
	stream := &fakeLogStream{ctx: adminCtx()}

	err := s.GetVMLogs(req, stream)
	if err == nil {
		t.Fatal("expected error for nonexistent VM")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("code = %v, want NotFound", st.Code())
	}
}

func TestGetVMLogs_LocalVM_NoFollow(t *testing.T) {
	s, logDir := logsTestServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "my-vm",
		HostName:  s.hostName,
		State:     "running",
		CPUActual: 1,
		MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	logContent := "boot msg 1\nboot msg 2\nboot msg 3\nboot msg 4\nboot msg 5\n"
	os.WriteFile(filepath.Join(logDir, "my-vm.log"), []byte(logContent), 0644)

	req := &pb.GetVMLogsRequest{Name: "my-vm", Lines: 3, Follow: false}
	stream := &fakeLogStream{ctx: ctx}

	if err := s.GetVMLogs(req, stream); err != nil {
		t.Fatalf("GetVMLogs: %v", err)
	}

	if len(stream.chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(stream.chunks))
	}
	got := string(stream.chunks[0].Data)
	if !strings.Contains(got, "boot msg 4") || !strings.Contains(got, "boot msg 5") {
		t.Errorf("expected last lines, got: %q", got)
	}
	if strings.Contains(got, "boot msg 1") {
		t.Errorf("should not contain early lines, got: %q", got)
	}
}

func TestGetVMLogs_DefaultLines(t *testing.T) {
	s, logDir := logsTestServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "default-vm",
		HostName:  s.hostName,
		State:     "running",
		CPUActual: 1,
		MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Write 100 lines; requesting Lines=0 should default to 50.
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "log line")
	}
	os.WriteFile(filepath.Join(logDir, "default-vm.log"), []byte(strings.Join(lines, "\n")+"\n"), 0644)

	req := &pb.GetVMLogsRequest{Name: "default-vm", Lines: 0}
	stream := &fakeLogStream{ctx: ctx}

	if err := s.GetVMLogs(req, stream); err != nil {
		t.Fatalf("GetVMLogs: %v", err)
	}

	if len(stream.chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	// Should not contain all 100 lines (default is 50).
	count := strings.Count(string(stream.chunks[0].Data), "\n")
	if count > 50 {
		t.Errorf("got %d newlines with default, want <= 50", count)
	}
}

func TestGetVMLogs_LogFileMissing(t *testing.T) {
	s, _ := logsTestServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "no-log-vm",
		HostName: s.hostName,
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Don't create the log file — should get NotFound for the log.
	req := &pb.GetVMLogsRequest{Name: "no-log-vm", Lines: 10}
	stream := &fakeLogStream{ctx: ctx}

	err := s.GetVMLogs(req, stream)
	if err == nil {
		t.Fatal("expected error for missing log file")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("code = %v, want NotFound", st.Code())
	}
	if !strings.Contains(st.Message(), "log file") {
		t.Errorf("message = %q, expected to mention log file", st.Message())
	}
}

func TestGetVMLogs_EmptyLog(t *testing.T) {
	s, logDir := logsTestServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "empty-log-vm",
		HostName: s.hostName,
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	os.WriteFile(filepath.Join(logDir, "empty-log-vm.log"), []byte{}, 0644)

	req := &pb.GetVMLogsRequest{Name: "empty-log-vm", Lines: 10}
	stream := &fakeLogStream{ctx: ctx}

	if err := s.GetVMLogs(req, stream); err != nil {
		t.Fatalf("GetVMLogs: %v", err)
	}
	if len(stream.chunks) != 0 {
		t.Errorf("expected no chunks for empty log, got %d", len(stream.chunks))
	}
}

func TestGetVMLogs_InsufficientRole(t *testing.T) {
	s, _ := logsTestServer(t)

	ctx := context.Background()
	req := &pb.GetVMLogsRequest{Name: "some-vm"}
	stream := &fakeLogStream{ctx: ctx}

	err := s.GetVMLogs(req, stream)
	if err == nil {
		t.Fatal("expected permission denied error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", st.Code())
	}
}

func TestGetVMLogs_ForwardToPeer(t *testing.T) {
	s, _ := logsTestServer(t)
	ctx := adminCtx()

	// Insert VM on a different host to trigger forwarding.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "remote-vm",
		HostName: "other-host",
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	req := &pb.GetVMLogsRequest{Name: "remote-vm", Lines: 10}
	stream := &fakeLogStream{ctx: ctx}

	err := s.GetVMLogs(req, stream)
	if err == nil {
		t.Fatal("expected error (peer not reachable)")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code())
	}
}

func TestVmLogDir_Default(t *testing.T) {
	s := &Server{}
	if got := s.vmLogDir(); got != "/var/log/libvirt/qemu" {
		t.Errorf("vmLogDir() = %q, want default", got)
	}
}

func TestVmLogDir_Override(t *testing.T) {
	s := &Server{logDir: "/tmp/test/logs"}
	if got := s.vmLogDir(); got != "/tmp/test/logs" {
		t.Errorf("vmLogDir() = %q, want /tmp/test/logs", got)
	}
}
