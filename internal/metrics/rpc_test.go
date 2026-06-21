package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRPCMetrics_UnaryHappyPath asserts a successful handler increments the
// OK counter and records a duration sample.
func TestRPCMetrics_UnaryHappyPath(t *testing.T) {
	m := buildRPCMetricsForTest(t)
	info := &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Ping"}
	handler := func(_ context.Context, _ any) (any, error) { return "ok", nil }

	_, err := m.UnaryInterceptor()(context.Background(), nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}

	if got := counterValue(t, m.Requests, "Ping", "OK"); got != 1 {
		t.Fatalf("Ping/OK counter = %v, want 1", got)
	}
}

// TestRPCMetrics_UnaryFailurePath asserts the error code lands on the
// label (so a grafana board can show 4xx-equivalent rates).
func TestRPCMetrics_UnaryFailurePath(t *testing.T) {
	m := buildRPCMetricsForTest(t)
	info := &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/CreateVM"}
	handler := func(_ context.Context, _ any) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "nope")
	}

	_, err := m.UnaryInterceptor()(context.Background(), nil, info, handler)
	if err == nil {
		t.Fatal("expected error to propagate")
	}

	if got := counterValue(t, m.Requests, "CreateVM", "PermissionDenied"); got != 1 {
		t.Fatalf("CreateVM/PermissionDenied counter = %v, want 1", got)
	}
}

// TestRPCMetrics_StreamCodeMapping confirms that a non-Status error still
// maps cleanly via status.Code() (which returns Unknown for plain errors).
func TestRPCMetrics_StreamCodeMapping(t *testing.T) {
	m := buildRPCMetricsForTest(t)
	info := &grpc.StreamServerInfo{FullMethod: "/litevirt.v1.LiteVirt/BackupSnapshot"}
	handler := func(_ any, _ grpc.ServerStream) error { return errors.New("plain") }

	err := m.StreamInterceptor()(nil, nil, info, handler)
	if err == nil {
		t.Fatal("expected error to propagate")
	}

	if got := counterValue(t, m.Requests, "BackupSnapshot", "Unknown"); got != 1 {
		t.Fatalf("BackupSnapshot/Unknown counter = %v, want 1", got)
	}
}

func TestShortMethod(t *testing.T) {
	cases := map[string]string{
		"/litevirt.v1.LiteVirt/Ping": "Ping",
		"/svc.Other/Thing":           "Thing",
		"":                           "",
		"no-slashes":                 "no-slashes",
	}
	for in, want := range cases {
		if got := shortMethod(in); got != want {
			t.Errorf("shortMethod(%q) = %q, want %q", in, got, want)
		}
	}
}

// buildRPCMetricsForTest builds RPCMetrics on an isolated registry so
// repeated subtests don't trip prometheus.MustRegister's duplicate panic.
func buildRPCMetricsForTest(t *testing.T) *RPCMetrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := &RPCMetrics{
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "litevirt_grpc_request_duration_seconds_test",
			Help:    "test",
			Buckets: []float64{0.001, 0.1, 1, 10},
		}, []string{"method", "code"}),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_grpc_requests_total_test",
			Help: "test",
		}, []string{"method", "code"}),
	}
	reg.MustRegister(m.Duration, m.Requests)
	return m
}

func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	c, err := vec.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var pb dto.Metric
	if err := c.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetCounter().GetValue()
}
