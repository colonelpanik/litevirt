package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// boundsCLIDaemon registers srv behind a bufconn listener and points
// withClient at it, so the commands run against a real gRPC connection.
func boundsCLIDaemon(t *testing.T, srv pb.LiteVirtServer) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	pb.RegisterLiteVirtServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	client := pb.NewLiteVirtClient(conn)
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, client)
	}
	t.Cleanup(func() {
		withClient = orig
		_ = conn.Close()
		gs.Stop()
		_ = listener.Close()
	})
}

// boundsRecorder is a daemon that records the time bounds each RPC was sent.
type boundsRecorder struct {
	pb.UnimplementedLiteVirtServer
	mu           sync.Mutex
	since, until []string
}

func (r *boundsRecorder) record(since, until string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.since, r.until = append(r.since, since), append(r.until, until)
}

func (r *boundsRecorder) ListAuditLog(_ context.Context, req *pb.ListAuditLogRequest) (*pb.ListAuditLogResponse, error) {
	r.record(req.Since, req.Until)
	return &pb.ListAuditLogResponse{}, nil
}

func (r *boundsRecorder) ExportAuditChain(_ context.Context, req *pb.ExportAuditChainRequest) (*pb.ExportAuditChainResponse, error) {
	r.record(req.Since, req.Until)
	return &pb.ExportAuditChainResponse{Json: `{"rows":[]}`}, nil
}

func (r *boundsRecorder) ListVMEvents(_ context.Context, req *pb.ListVMEventsRequest) (*pb.ListVMEventsResponse, error) {
	r.record(req.Since, "")
	return &pb.ListVMEventsResponse{}, nil
}

func runBoundsCmd(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var err error
	captureStdout(t, func() { err = cmd.Execute() })
	return err
}

// The CLI sends the daemon resolved, fixed-width UTC bounds, never what the
// user typed. A daemon older than ParseTimeWindow compares the bound to its
// stamps as TEXT; a fixed-width UTC bound is the one form that comparison gets
// right, so `lv audit ls --since 24h` against a node not yet upgraded returns
// the last day rather than every row. It also fixes a relative bound once, on
// the client, for every page of an export.
func TestAuditCLI_SendsResolvedBounds(t *testing.T) {
	rec := &boundsRecorder{}
	boundsCLIDaemon(t, rec)

	before := time.Now().UTC()
	if err := runBoundsCmd(t, newAuditLsCmd(), "--since", "24h"); err != nil {
		t.Fatalf("lv audit ls: %v", err)
	}
	if err := runBoundsCmd(t, newAuditExportCmd(), "--since", "2026-10-04T00:16:30+02:00", "--until", "2026-10-03"); err != nil {
		t.Fatalf("lv audit export: %v", err)
	}
	if err := runBoundsCmd(t, newEventsCmd(), "web", "--since", "2026-10-03T22:16:30Z"); err != nil {
		t.Fatalf("lv events: %v", err)
	}
	after := time.Now().UTC()

	if len(rec.since) != 3 {
		t.Fatalf("recorded %d requests, want 3", len(rec.since))
	}
	got, err := time.Parse(time.RFC3339Nano, rec.since[0])
	if err != nil || len(rec.since[0]) != 30 || !strings.HasSuffix(rec.since[0], "Z") {
		t.Fatalf("ls --since 24h sent %q, want a fixed-width UTC stamp", rec.since[0])
	}
	if got.Before(before.Add(-24*time.Hour)) || got.After(after.Add(-24*time.Hour)) {
		t.Errorf("ls --since 24h sent %s, want 24h before now", rec.since[0])
	}
	for i, want := range [][2]string{
		{"2026-10-03T22:16:30.000000000Z", "2026-10-03T23:59:59.999999999Z"},
		{"2026-10-03T22:16:30.000000000Z", ""},
	} {
		if rec.since[i+1] != want[0] || rec.until[i+1] != want[1] {
			t.Errorf("request %d sent since=%q until=%q, want %q / %q", i+1, rec.since[i+1], rec.until[i+1], want[0], want[1])
		}
	}

	if err := runBoundsCmd(t, newAuditLsCmd(), "--since", "yesterday"); err == nil || !strings.Contains(err.Error(), "since") {
		t.Errorf("lv audit ls --since yesterday = %v, want an error naming --since", err)
	}
	if len(rec.since) != 3 {
		t.Errorf("an unparseable bound still reached the daemon")
	}
}

// A "forever" bound written with a negative offset is past the last
// representable stamp in UTC. The CLI sends that last stamp, never a year-10000
// one, which an older daemon's text comparison would sort below every row.
func TestAuditCLI_ClampsABoundPastTheMax(t *testing.T) {
	rec := &boundsRecorder{}
	boundsCLIDaemon(t, rec)
	if err := runBoundsCmd(t, newAuditExportCmd(), "--until", "9999-12-31T23:59:59-01:00"); err != nil {
		t.Fatalf("lv audit export: %v", err)
	}
	if len(rec.until) != 1 || rec.until[0] != "9999-12-31T23:59:59.999999999Z" {
		t.Fatalf("sent until=%v, want [9999-12-31T23:59:59.999999999Z]", rec.until)
	}
}

// `lv audit ls` takes --until as export and MCP do, resolved the same way:
// a date runs to the end of that day, and a bad bound is refused naming the
// flag before anything reaches the daemon.
func TestAuditCLI_LsSendsResolvedUntil(t *testing.T) {
	rec := &boundsRecorder{}
	boundsCLIDaemon(t, rec)
	if err := runBoundsCmd(t, newAuditLsCmd(), "--since", "2026-10-04T00:16:30+02:00", "--until", "2026-10-03"); err != nil {
		t.Fatalf("lv audit ls: %v", err)
	}
	if len(rec.since) != 1 || rec.since[0] != "2026-10-03T22:16:30.000000000Z" || rec.until[0] != "2026-10-03T23:59:59.999999999Z" {
		t.Fatalf("sent since=%v until=%v, want [2026-10-03T22:16:30.000000000Z] / [2026-10-03T23:59:59.999999999Z]", rec.since, rec.until)
	}
	if err := runBoundsCmd(t, newAuditLsCmd(), "--until", "tomorrow"); err == nil || !strings.Contains(err.Error(), "until") {
		t.Errorf("lv audit ls --until tomorrow = %v, want an error naming --until", err)
	}
	if len(rec.since) != 1 {
		t.Errorf("an unparseable bound still reached the daemon")
	}
}
