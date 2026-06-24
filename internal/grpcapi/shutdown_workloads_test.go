package grpcapi

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// mockShutdownStream implements pb.LiteVirt_ShutdownHostWorkloadsServer.
type mockShutdownStream struct {
	ctx  context.Context
	mu   sync.Mutex
	sent []*pb.ShutdownProgress
}

func (m *mockShutdownStream) Send(p *pb.ShutdownProgress) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockShutdownStream) Context() context.Context       { return m.ctx }
func (m *mockShutdownStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockShutdownStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockShutdownStream) SetTrailer(_ metadata.MD)       {}
func (m *mockShutdownStream) SendMsg(_ interface{}) error    { return nil }
func (m *mockShutdownStream) RecvMsg(_ interface{}) error    { return nil }

func orderSpec(order, stopDelay int) string {
	return fmt.Sprintf(`{"startup_order":%d,"stop_delay_sec":%d}`, order, stopDelay)
}

// Stops happen in REVERSE startup order; stopped VMs and VMs on other hosts are
// skipped; tie broken by name.
func TestShutdownHostWorkloads_ReverseOrder(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "sw-host", "active")
	// startup_order 1,2,3 → expect stops in order 3,2,1.
	insertTestVMR2WithSpec(t, ctx, s.db, "sw-low", "sw-host", "running", orderSpec(1, 0))
	insertTestVMR2WithSpec(t, ctx, s.db, "sw-mid", "sw-host", "running", orderSpec(2, 0))
	insertTestVMR2WithSpec(t, ctx, s.db, "sw-high", "sw-host", "running", orderSpec(3, 0))
	// A stopped VM (should be skipped) and one on another host (should be skipped).
	insertTestVMR2WithSpec(t, ctx, s.db, "sw-stopped", "sw-host", "stopped", orderSpec(5, 0))
	insertTestVMR2WithSpec(t, ctx, s.db, "sw-elsewhere", "other-host", "running", orderSpec(9, 0))

	var stopped []string
	var mu sync.Mutex
	s.stopVMOverride = func(_ context.Context, req *pb.StopVMRequest) (*pb.VM, error) {
		mu.Lock()
		stopped = append(stopped, req.Name)
		mu.Unlock()
		return &pb.VM{Name: req.Name}, nil
	}

	stream := &mockShutdownStream{ctx: ctx}
	if err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "sw-host"}, stream); err != nil {
		t.Fatalf("ShutdownHostWorkloads: %v", err)
	}

	want := []string{"sw-high", "sw-mid", "sw-low"}
	if len(stopped) != len(want) {
		t.Fatalf("stopped %v, want %v", stopped, want)
	}
	for i := range want {
		if stopped[i] != want[i] {
			t.Fatalf("stop order %v, want %v", stopped, want)
		}
	}
}

// Tie on startup_order is broken by name (ascending).
func TestShutdownHostWorkloads_TieBrokenByName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "tie-host", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "tie-b", "tie-host", "running", orderSpec(1, 0))
	insertTestVMR2WithSpec(t, ctx, s.db, "tie-a", "tie-host", "running", orderSpec(1, 0))

	var stopped []string
	s.stopVMOverride = func(_ context.Context, req *pb.StopVMRequest) (*pb.VM, error) {
		stopped = append(stopped, req.Name)
		return &pb.VM{Name: req.Name}, nil
	}
	stream := &mockShutdownStream{ctx: ctx}
	if err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "tie-host"}, stream); err != nil {
		t.Fatalf("ShutdownHostWorkloads: %v", err)
	}
	if len(stopped) != 2 || stopped[0] != "tie-a" || stopped[1] != "tie-b" {
		t.Fatalf("tie order %v, want [tie-a tie-b]", stopped)
	}
}

// stop_delay_sec is actually waited between stops (not after the last).
func TestShutdownHostWorkloads_WaitsStopDelay(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "delay-host", "active")
	// order 2 stops first with a 1s delay, then order 1.
	insertTestVMR2WithSpec(t, ctx, s.db, "delay-first", "delay-host", "running", orderSpec(2, 1))
	insertTestVMR2WithSpec(t, ctx, s.db, "delay-second", "delay-host", "running", orderSpec(1, 0))

	s.stopVMOverride = func(_ context.Context, req *pb.StopVMRequest) (*pb.VM, error) {
		return &pb.VM{Name: req.Name}, nil
	}
	stream := &mockShutdownStream{ctx: ctx}
	start := time.Now()
	if err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "delay-host"}, stream); err != nil {
		t.Fatalf("ShutdownHostWorkloads: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("expected ~1s delay between stops, took %v", elapsed)
	}
}

// The delay is interruptible: cancelling the context during the wait returns
// ctx.Err() and does not stop the remaining VMs.
func TestShutdownHostWorkloads_ContextCancelDuringDelay(t *testing.T) {
	s := testServerR2(t)
	base := adminContext(context.Background())
	ctx, cancel := context.WithTimeout(base, 50*time.Millisecond)
	defer cancel()

	insertTestHostR2(t, ctx, s.db, "cancel-host", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "cancel-first", "cancel-host", "running", orderSpec(2, 10))
	insertTestVMR2WithSpec(t, ctx, s.db, "cancel-second", "cancel-host", "running", orderSpec(1, 0))

	var stopped []string
	s.stopVMOverride = func(_ context.Context, req *pb.StopVMRequest) (*pb.VM, error) {
		stopped = append(stopped, req.Name)
		return &pb.VM{Name: req.Name}, nil
	}
	stream := &mockShutdownStream{ctx: ctx}
	err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "cancel-host"}, stream)
	if err == nil {
		t.Fatal("expected context error from cancelled delay, got nil")
	}
	// Only the first VM was stopped; the wait was interrupted before the second.
	if len(stopped) != 1 || stopped[0] != "cancel-first" {
		t.Fatalf("stopped %v, want only [cancel-first]", stopped)
	}
}

// A failed stop is best-effort: it is reported as an error but the remaining
// VMs are still stopped.
func TestShutdownHostWorkloads_ContinuesOnStopError(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "err-host", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "err-first", "err-host", "running", orderSpec(2, 0))
	insertTestVMR2WithSpec(t, ctx, s.db, "err-second", "err-host", "running", orderSpec(1, 0))

	var stopped []string
	s.stopVMOverride = func(_ context.Context, req *pb.StopVMRequest) (*pb.VM, error) {
		stopped = append(stopped, req.Name)
		if req.Name == "err-first" {
			return nil, fmt.Errorf("boom")
		}
		return &pb.VM{Name: req.Name}, nil
	}
	stream := &mockShutdownStream{ctx: ctx}
	if err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "err-host"}, stream); err != nil {
		t.Fatalf("ShutdownHostWorkloads should be best-effort, got: %v", err)
	}
	if len(stopped) != 2 {
		t.Fatalf("both VMs should be attempted, got %v", stopped)
	}
	// An error progress message for the failed VM must be emitted.
	var sawErr bool
	for _, p := range stream.sent {
		if p.VmName == "err-first" && p.Status == "error" && p.Error != "" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatalf("expected an error ShutdownProgress for err-first; got %+v", stream.sent)
	}
}

// Non-admin callers are rejected.
func TestShutdownHostWorkloads_RequiresAdmin(t *testing.T) {
	s := testServerR2(t)
	ctx := context.WithValue(context.Background(), ctxKeyRole, "viewer")
	ctx = context.WithValue(ctx, ctxKeyUsername, "bob")

	insertTestHostR2(t, ctx, s.db, "auth-host", "active")
	stream := &mockShutdownStream{ctx: ctx}
	err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "auth-host"}, stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

// An unknown host is NotFound.
func TestShutdownHostWorkloads_UnknownHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	stream := &mockShutdownStream{ctx: ctx}
	err := s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: "ghost"}, stream)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}
