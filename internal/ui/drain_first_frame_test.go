package ui

import (
	"context"
	"fmt"
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

// DrainHost sends its first frame only once the first VM has been drained —
// a whole live migration. The UI's drain button and the bulk drain waited
// synchronously for that frame, so a drain of a host with a large VM held the
// request far past the 30s WriteTimeout (the toast was lost and the operator
// clicked again), and a bulk drain held one of its eight slots per host for a
// whole migration, serialising the rest behind it.

// lateFirstFrameStream produces nothing until release is closed — the first
// migration finishing — then one frame, then EOF.
type lateFirstFrameStream struct {
	grpc.ClientStream
	release chan struct{}

	mu    sync.Mutex
	reads int
}

func (s *lateFirstFrameStream) Recv() (*pb.DrainProgress, error) {
	s.mu.Lock()
	s.reads++
	n := s.reads
	s.mu.Unlock()
	if n == 1 {
		<-s.release
		return &pb.DrainProgress{Status: "migrated", VmName: "big-vm"}, nil
	}
	return nil, io.EOF
}

func (s *lateFirstFrameStream) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.reads }

// lateDrainGRPC gives every DrainHost its own late stream, so a bulk drain of
// several hosts has several migrations in flight.
type lateDrainGRPC struct {
	*mockGRPC
	release chan struct{}

	smu     sync.Mutex
	streams map[string]*lateFirstFrameStream
}

func (m *lateDrainGRPC) DrainHost(_ context.Context, in *pb.DrainHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DrainProgress], error) {
	m.smu.Lock()
	defer m.smu.Unlock()
	st := &lateFirstFrameStream{release: m.release}
	m.streams[in.Name] = st
	return st, nil
}

func (m *lateDrainGRPC) all() []*lateFirstFrameStream {
	m.smu.Lock()
	defer m.smu.Unlock()
	out := make([]*lateFirstFrameStream, 0, len(m.streams))
	for _, st := range m.streams {
		out = append(out, st)
	}
	return out
}

func shrinkDrainAck(t *testing.T, d time.Duration) {
	t.Helper()
	old := drainAckTimeout
	drainAckTimeout = d
	t.Cleanup(func() { drainAckTimeout = old })
}

func TestUIDrain_AnswersBeforeTheFirstMigrationFinishes(t *testing.T) {
	shrinkDrainAck(t, 100*time.Millisecond)

	hosts := make([]string, 12) // more hosts than the bulk has slots
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	for _, tc := range []struct {
		name  string
		hosts int
		req   func() *http.Request
	}{
		{"host page", 1, func() *http.Request { return httptest.NewRequest("POST", "/ui/hosts/host1/drain", nil) }},
		{"bulk", len(hosts), func() *http.Request {
			r := httptest.NewRequest("POST", "/ui/hosts/bulk", strings.NewReader("action=drain&names="+strings.Join(hosts, ",")))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &lateDrainGRPC{mockGRPC: newDefaultMock(), release: make(chan struct{}), streams: map[string]*lateFirstFrameStream{}}
			s, err := NewServer(m, "test-cluster")
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}

			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- serveRequest(s, withAuth(tc.req())) }()
			var w *httptest.ResponseRecorder
			select {
			case w = <-done:
			case <-time.After(3 * time.Second):
				close(m.release)
				<-done
				t.Fatal("the drain request waited for the first VM migration to finish before answering")
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			trig := w.Header().Get("HX-Trigger")
			if tc.name == "host page" && !strings.Contains(trig, "Drain started") {
				t.Errorf("toast = %q, want \"Drain started\"", trig)
			}
			if tc.name == "bulk" && !strings.Contains(trig, fmt.Sprintf("%d ok, 0 failed", tc.hosts)) {
				t.Errorf("toast = %q, want every host's drain reported started", trig)
			}
			if got := len(m.all()); got != tc.hosts {
				t.Fatalf("DrainHost was opened for %d host(s), want %d", got, tc.hosts)
			}

			// The drains keep running: once the migration finishes, each stream
			// is read on to its end, first frame included.
			close(m.release)
			deadline := time.Now().Add(3 * time.Second)
			for _, st := range m.all() {
				for st.count() < 2 && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				if got := st.count(); got < 2 {
					t.Errorf("a drain stream was read %d time(s) after the answer; nothing is draining it", got)
				}
			}
		})
	}
}

// A first Recv still in flight when the bound passes belongs to the background
// reader: dropping it would lose the first frame, or the refusal it carries.
func TestUIFirstOrDetach_TheInFlightFirstRecvIsNotDropped(t *testing.T) {
	release := make(chan struct{})
	first := fmt.Errorf("the first frame")
	var mu sync.Mutex
	calls := 0
	recv := func() error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			<-release
			return first
		}
		return io.EOF
	}
	err, timedOut, rest := firstOrDetach(recv, 20*time.Millisecond)
	if !timedOut || err != nil {
		t.Fatalf("firstOrDetach = (%v, timedOut %v), want a timeout with no error", err, timedOut)
	}
	close(release)
	if got := rest(); got != first {
		t.Fatalf("the background reader's first read = %v, want the in-flight first Recv's result", got)
	}
	if got := rest(); got != io.EOF {
		t.Fatalf("the second read = %v, want the stream read on (io.EOF)", got)
	}
}
