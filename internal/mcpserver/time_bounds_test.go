package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// boundsClient records the time bounds the MCP tools send.
type boundsClient struct {
	fakeLiteVirtClient
	audit  []*pb.ListAuditLogRequest
	events []*pb.ListVMEventsRequest
}

func (b *boundsClient) ListAuditLog(_ context.Context, req *pb.ListAuditLogRequest, _ ...grpc.CallOption) (*pb.ListAuditLogResponse, error) {
	b.audit = append(b.audit, req)
	return &pb.ListAuditLogResponse{}, nil
}

func (b *boundsClient) ListVMEvents(_ context.Context, req *pb.ListVMEventsRequest, _ ...grpc.CallOption) (*pb.ListVMEventsResponse, error) {
	b.events = append(b.events, req)
	return &pb.ListVMEventsResponse{}, nil
}

// `lv mcp` is a client of the daemon like the CLI, and its tool schema invites
// the same forms (24h, a date, an offset). It resolves them to fixed-width UTC
// stamps before sending, so a daemon not yet upgraded, which compares the bound
// as text, still answers correctly, and a bad bound is refused before any RPC.
func TestMCPTools_SendResolvedBounds(t *testing.T) {
	fake := &boundsClient{}
	s := testServer(fake, false)
	ctx := context.Background()

	before := time.Now().UTC()
	if res := s.handleListAuditLog(ctx, map[string]any{"since": "24h", "until": "2026-10-03"}); res.IsError {
		t.Fatalf("list_audit_log: %+v", resultEnvelope(t, res).Error)
	}
	if res := s.handleListVMEvents(ctx, map[string]any{"vm_name": "web", "since": "2026-10-04T00:16:30+02:00"}); res.IsError {
		t.Fatalf("list_vm_events: %+v", resultEnvelope(t, res).Error)
	}
	after := time.Now().UTC()

	if len(fake.audit) != 1 || len(fake.events) != 1 {
		t.Fatalf("calls: audit=%d events=%d, want 1 each", len(fake.audit), len(fake.events))
	}
	since, err := time.Parse(time.RFC3339Nano, fake.audit[0].Since)
	if err != nil || len(fake.audit[0].Since) != 30 || since.Before(before.Add(-24*time.Hour)) || since.After(after.Add(-24*time.Hour)) {
		t.Errorf("list_audit_log since=24h sent %q, want a fixed-width stamp 24h ago", fake.audit[0].Since)
	}
	if fake.audit[0].Until != "2026-10-03T23:59:59.999999999Z" {
		t.Errorf("list_audit_log until=2026-10-03 sent %q, want the end of that day", fake.audit[0].Until)
	}
	if fake.events[0].Since != "2026-10-03T22:16:30.000000000Z" {
		t.Errorf("list_vm_events sent since=%q, want 2026-10-03T22:16:30.000000000Z", fake.events[0].Since)
	}

	res := s.handleListAuditLog(ctx, map[string]any{"since": "yesterday"})
	env := resultEnvelope(t, res)
	if !res.IsError || env.Error == nil || env.Error.Code != codes.InvalidArgument.String() || !strings.Contains(env.Error.Message, "since") {
		t.Errorf("list_audit_log since=yesterday = %+v, want an InvalidArgument tool error naming since", env.Error)
	}
	res = s.handleListVMEvents(ctx, map[string]any{"since": "yesterday"})
	if env := resultEnvelope(t, res); !res.IsError || env.Error == nil || env.Error.Code != codes.InvalidArgument.String() {
		t.Errorf("list_vm_events since=yesterday = %+v, want an InvalidArgument tool error", env.Error)
	}
	if len(fake.audit) != 1 || len(fake.events) != 1 {
		t.Errorf("an unparseable bound reached the daemon")
	}
}
