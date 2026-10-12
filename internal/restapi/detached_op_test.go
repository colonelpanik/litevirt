package restapi

import (
	"context"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// fakeDrainStream yields one progress message, then blocks until released, then
// ends. The block models the real thing: DrainHost has written
// UpdateHostState(..., "draining") and has not yet reached placement.Select.
type fakeDrainStream struct {
	grpc.ClientStream
	mu      sync.Mutex
	recvs   int
	release chan struct{}
}

func (f *fakeDrainStream) Recv() (*pb.DrainProgress, error) {
	f.mu.Lock()
	f.recvs++
	n := f.recvs
	f.mu.Unlock()
	if n == 1 {
		return &pb.DrainProgress{Status: "draining"}, nil
	}
	<-f.release
	return nil, io.EOF
}

func (f *fakeDrainStream) recvCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recvs
}

type detachCapturingGRPC struct {
	pb.LiteVirtClient
	mu       sync.Mutex
	drainCtx context.Context
	stream   *fakeDrainStream
}

func (m *detachCapturingGRPC) DrainHost(ctx context.Context, _ *pb.DrainHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DrainProgress], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drainCtx = ctx
	return m.stream, nil
}

func (m *detachCapturingGRPC) capturedCtx() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drainCtx
}

// TestDrainHost_DetachedOperationSurvivesTheResponse is the #192 regression.
//
// The handler opened the server-streaming RPC on r.Context(), never called
// Recv, wrote {"status":"draining"} and returned 200 — at which point net/http
// cancels r.Context(), which is the stream's parent. DrainHost runs off
// stream.Context(), so it was cancelled mid-flight: usually after
// UpdateHostState(..., "draining") and before placement.Select. The host was
// left parked in `draining` with every VM still on it, and the operator's
// script saw a 200.
//
// Reporting an operation as started is a promise that it will run. The ack path
// therefore has to hand the RPC a context that outlives the request.
func TestDrainHost_DetachedOperationSurvivesTheResponse(t *testing.T) {
	stream := &fakeDrainStream{release: make(chan struct{})}
	mock := &detachCapturingGRPC{stream: stream}
	s := NewServer(mock, "test-token")

	// httptest does not cancel a request context on its own, so model what
	// net/http really does: the handler returns, then the request context dies.
	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/api/v1/hosts/node1/drain", nil).WithContext(reqCtx)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	cancelReq()

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	opCtx := mock.capturedCtx()
	if opCtx == nil {
		t.Fatal("DrainHost was never called")
	}

	// The operation's context must not have died with the request.
	select {
	case <-opCtx.Done():
		t.Fatalf("the drain's context was cancelled when the handler returned (%v); "+
			"the host is parked in `draining` with its VMs still on it and the "+
			"caller saw a 200", opCtx.Err())
	default:
	}

	// It must also still be being read, or the server blocks on Send as soon as
	// the flow-control window fills and the operation stalls anyway.
	deadline := time.Now().Add(2 * time.Second)
	for stream.recvCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := stream.recvCount(); got < 2 {
		t.Errorf("the detached stream was read %d time(s); nothing is draining it, "+
			"so the operation stalls once the window fills", got)
	}
	close(stream.release)
}

// The detached context must still carry the request's values — the gRPC call
// is authenticated by metadata taken from it, and a context stripped of that
// would turn every detached operation into an unauthenticated one.
func TestDetachedContext_KeepsValuesAndDropsCancellation(t *testing.T) {
	type key struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "v"))

	opCtx, done := detachedOpContext(parent)
	defer done()

	cancel()
	select {
	case <-opCtx.Done():
		t.Fatal("the detached context was cancelled with its parent")
	default:
	}
	if got := opCtx.Value(key{}); got != "v" {
		t.Errorf("value = %v, want v — auth metadata rides on the context", got)
	}
}

// It must not live forever either: a detached operation that never ends would
// otherwise leak a goroutine and a gRPC stream per request.
func TestDetachedContext_HasACeiling(t *testing.T) {
	opCtx, done := detachedOpContext(context.Background())
	defer done()
	dl, ok := opCtx.Deadline()
	if !ok {
		t.Fatal("the detached context has no deadline; a stuck operation leaks forever")
	}
	if until := time.Until(dl); until < time.Minute {
		t.Errorf("detached ceiling is %s — too short for a real drain or migration", until)
	}
}
