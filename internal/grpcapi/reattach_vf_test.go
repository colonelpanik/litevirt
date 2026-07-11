package grpcapi

import (
	"context"
	"sync"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ctxCapturingClient records the context handed to each AttachDevice call so a
// test can assert what the outbound RPC would carry. Only AttachDevice is
// exercised; the embedded interface leaves every other method nil.
type ctxCapturingClient struct {
	pb.LiteVirtClient
	mu   sync.Mutex
	ctxs []context.Context
}

func (c *ctxCapturingClient) AttachDevice(ctx context.Context, _ *pb.AttachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.mu.Lock()
	c.ctxs = append(c.ctxs, ctx)
	c.mu.Unlock()
	return &pb.VM{}, nil
}

// Post-cutover VF reattach must run on a context detached from the inbound RPC
// (like the migrate notify): a long migration can outlive the forwarded user
// bearer, and under ForwardedIdentityV1 the target has no peer fallback, so a
// relayed stale bearer would fail AttachDevice and the VM would come up without
// its passthrough NICs/GPUs. The span must survive so the reattach still links
// into the vm.migrate trace, and the context must be bounded by a timeout.
func TestSendReattachVFs_DetachesInboundBearerKeepsSpan(t *testing.T) {
	md := metadata.Pairs(
		"authorization", "Bearer expired-user-token",
		"x-litevirt-fwd-bearer", "Bearer already-relayed",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, span := sdktrace.NewTracerProvider().Tracer("test").Start(ctx, "vm.migrate")
	defer span.End()
	wantSpan := oteltrace.SpanContextFromContext(ctx)

	fake := &ctxCapturingClient{}
	s := &Server{hostName: "src"}
	s.sendReattachVFs(ctx, fake, "target", "vm1", []corrosion.PCIDeviceRecord{
		{Type: "net", VendorID: "8086"},
	})

	if len(fake.ctxs) != 1 {
		t.Fatalf("AttachDevice called %d times; want 1", len(fake.ctxs))
	}
	got := fake.ctxs[0]
	if gotMD, ok := metadata.FromIncomingContext(got); ok && len(gotMD) != 0 {
		t.Errorf("reattach kept inbound metadata %v; a forwarded bearer would relay onto AttachDevice and fail under an expired TTL", gotMD)
	}
	if !oteltrace.SpanContextFromContext(got).Equal(wantSpan) {
		t.Error("reattach lost the span; AttachDevice would not link into the migrate trace")
	}
	if _, ok := got.Deadline(); !ok {
		t.Error("reattach did not bound the outbound context with a timeout")
	}
}
