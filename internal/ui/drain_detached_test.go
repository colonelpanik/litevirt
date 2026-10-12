package ui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The web UI's drain buttons were the #192 bug the REST API had already fixed:
// DrainHost was opened on the request context and the handler returned after
// at most one frame. net/http then cancels the request context, the stream's
// parent, and DrainHost runs off stream.Context() — so the host was left in
// `draining` with its VMs still on it, under a "Drain started" toast.

type blockingDrainStream struct {
	grpc.ClientStream
	mu      sync.Mutex
	recvs   int
	release chan struct{}
}

func (f *blockingDrainStream) Recv() (*pb.DrainProgress, error) {
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

func (f *blockingDrainStream) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.recvs }

func TestUIDrain_TheDrainSurvivesTheResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func() *http.Request
	}{
		{"host page", func() *http.Request { return httptest.NewRequest("POST", "/ui/hosts/host1/drain", nil) }},
		{"bulk", func() *http.Request {
			r := httptest.NewRequest("POST", "/ui/hosts/bulk", strings.NewReader("action=drain&names=host1"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newDefaultMock()
			stream := &blockingDrainStream{release: make(chan struct{})}
			defer close(stream.release)
			mock.drainStream = stream
			s := newTestUIServer(t, mock)

			reqCtx, cancelReq := context.WithCancel(context.Background())
			r := withAuth(tc.req().WithContext(reqCtx))
			w := serveRequest(s, r)
			cancelReq() // what net/http does once the handler returns

			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			mock.mu.Lock()
			opCtx := mock.drainCtx
			mock.mu.Unlock()
			if opCtx == nil {
				t.Fatal("DrainHost was never called")
			}
			select {
			case <-opCtx.Done():
				t.Fatalf("the drain's context died with the request (%v): the host is left draining with its VMs on it", opCtx.Err())
			default:
			}
			deadline := time.Now().Add(2 * time.Second)
			for stream.count() < 2 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := stream.count(); got < 2 {
				t.Fatalf("the drain stream was read %d time(s) after the response; nothing drains it", got)
			}
		})
	}
}
