package restapi

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The #192 fix (drain, migrate, stack migrate-volumes) was not applied to the
// other server-streaming routes. Without SSE they opened the stream on the
// request context, answered with the first frame and returned — net/http then
// cancels the request context, the stream's parent, and every one of these RPCs
// runs off stream.Context(): a volume move, replication, backup, restore or
// cross-region migration was cancelled part-way, after the caller got a 200.

// ackStream yields one frame, then blocks until released, then ends.
type ackStream[T any] struct {
	grpc.ClientStream
	mu      sync.Mutex
	recvs   int
	release chan struct{}
}

func (f *ackStream[T]) Recv() (*T, error) {
	f.mu.Lock()
	f.recvs++
	n := f.recvs
	f.mu.Unlock()
	if n == 1 {
		return new(T), nil
	}
	<-f.release
	return nil, io.EOF
}

func (f *ackStream[T]) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.recvs }

type ackCapturingGRPC struct {
	pb.LiteVirtClient
	mu  sync.Mutex
	ctx context.Context

	move      *ackStream[pb.MoveVolumeProgress]
	replicate *ackStream[pb.ReplicateVolumeProgress]
	backup    *ackStream[pb.BackupSnapshotProgress]
	restore   *ackStream[pb.RestoreFromBackupProgress]
	region    *ackStream[pb.MigrateProgress]
}

func (m *ackCapturingGRPC) keep(ctx context.Context) { m.mu.Lock(); m.ctx = ctx; m.mu.Unlock() }
func (m *ackCapturingGRPC) captured() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ctx
}

func (m *ackCapturingGRPC) MoveVolume(ctx context.Context, _ *pb.MoveVolumeRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MoveVolumeProgress], error) {
	m.keep(ctx)
	return m.move, nil
}
func (m *ackCapturingGRPC) ReplicateVolume(ctx context.Context, _ *pb.ReplicateVolumeRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ReplicateVolumeProgress], error) {
	m.keep(ctx)
	return m.replicate, nil
}
func (m *ackCapturingGRPC) BackupSnapshot(ctx context.Context, _ *pb.BackupSnapshotRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.BackupSnapshotProgress], error) {
	m.keep(ctx)
	return m.backup, nil
}
func (m *ackCapturingGRPC) RestoreFromBackup(ctx context.Context, _ *pb.RestoreFromBackupRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreFromBackupProgress], error) {
	m.keep(ctx)
	return m.restore, nil
}
func (m *ackCapturingGRPC) CrossRegionMigrate(ctx context.Context, _ *pb.CrossRegionMigrateRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	m.keep(ctx)
	return m.region, nil
}

func TestStreamingRoutes_TheOperationSurvivesTheResponse(t *testing.T) {
	for _, tc := range []struct {
		path  string
		count func(*ackCapturingGRPC) int
		done  func(*ackCapturingGRPC)
	}{
		{"/api/v1/vms/move-volume", func(m *ackCapturingGRPC) int { return m.move.count() }, func(m *ackCapturingGRPC) { close(m.move.release) }},
		{"/api/v1/vms/replicate-volume", func(m *ackCapturingGRPC) int { return m.replicate.count() }, func(m *ackCapturingGRPC) { close(m.replicate.release) }},
		{"/api/v1/backup/snapshot", func(m *ackCapturingGRPC) int { return m.backup.count() }, func(m *ackCapturingGRPC) { close(m.backup.release) }},
		{"/api/v1/backup/restore", func(m *ackCapturingGRPC) int { return m.restore.count() }, func(m *ackCapturingGRPC) { close(m.restore.release) }},
		{"/api/v1/regions/migrate", func(m *ackCapturingGRPC) int { return m.region.count() }, func(m *ackCapturingGRPC) { close(m.region.release) }},
	} {
		t.Run(strings.TrimPrefix(tc.path, "/api/v1/"), func(t *testing.T) {
			mock := &ackCapturingGRPC{
				move:      &ackStream[pb.MoveVolumeProgress]{release: make(chan struct{})},
				replicate: &ackStream[pb.ReplicateVolumeProgress]{release: make(chan struct{})},
				backup:    &ackStream[pb.BackupSnapshotProgress]{release: make(chan struct{})},
				restore:   &ackStream[pb.RestoreFromBackupProgress]{release: make(chan struct{})},
				region:    &ackStream[pb.MigrateProgress]{release: make(chan struct{})},
			}
			defer tc.done(mock)
			s := NewServer(mock, "test-token")

			reqCtx, cancelReq := context.WithCancel(context.Background())
			req := httptest.NewRequest("POST", tc.path, strings.NewReader(`{}`)).WithContext(reqCtx)
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, req)
			cancelReq() // what net/http does once the handler returns

			if w.Code != 200 {
				t.Fatalf("status = %d, want 200 (the ack): %s", w.Code, w.Body.String())
			}
			opCtx := mock.captured()
			if opCtx == nil {
				t.Fatal("the RPC was never called")
			}
			select {
			case <-opCtx.Done():
				t.Fatalf("the operation's context died with the request (%v): it is cancelled part-way after a 200", opCtx.Err())
			default:
			}
			deadline := time.Now().Add(2 * time.Second)
			for tc.count(mock) < 2 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := tc.count(mock); got < 2 {
				t.Fatalf("the stream was read %d time(s) after the ack; nothing drains it, so the operation stalls once the window fills", got)
			}
		})
	}
}
