package metrics

import (
	"context"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// RPCMetrics holds Prometheus collectors for per-method gRPC observability.
// One HistogramVec for end-to-end duration + one CounterVec for completed
// requests, both labelled by short method name + gRPC code. The labels stay
// bounded — there are ~80 RPCs and ~17 gRPC codes, so cardinality tops out
// around 1.3k series which is well inside Prometheus's comfort zone.
type RPCMetrics struct {
	Duration *prometheus.HistogramVec
	Requests *prometheus.CounterVec
}

// NewRPCMetrics registers and returns the gRPC observability collectors.
// Safe to call once at daemon startup. The histograms cover a wide range
// because some RPCs are sub-ms (Ping) while others are minute-long streams
// (BackupSnapshot) — the bucket layout matches Google's standard SRE set.
func NewRPCMetrics() *RPCMetrics {
	m := &RPCMetrics{
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "litevirt_grpc_request_duration_seconds",
			Help: "Wall-clock duration of completed gRPC requests, by method.",
			Buckets: []float64{
				0.001, 0.005, 0.01, 0.05, 0.1,
				0.5, 1, 5, 10, 30, 60, 300,
			},
		}, []string{"method", "code"}),

		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_grpc_requests_total",
			Help: "Total gRPC requests completed, by method and gRPC status code.",
		}, []string{"method", "code"}),
	}
	prometheus.MustRegister(m.Duration, m.Requests)
	return m
}

// UnaryInterceptor returns a grpc.UnaryServerInterceptor that records each
// completed RPC's duration + result. Chain it BEFORE the auth interceptor
// so that auth failures are themselves observable (otherwise an attacker
// flooding bad tokens shows up as zero RPC traffic in Grafana).
func (m *RPCMetrics) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		m.observe(info.FullMethod, err, time.Since(start))
		return resp, err
	}
}

// StreamInterceptor mirrors UnaryInterceptor for streaming RPCs. The
// duration is the entire stream lifetime (open → close), which is the right
// metric for capacity planning even though it conflates "long-running by
// design" with "actually slow."
func (m *RPCMetrics) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		err := handler(srv, ss)
		m.observe(info.FullMethod, err, time.Since(start))
		return err
	}
}

func (m *RPCMetrics) observe(fullMethod string, err error, dur time.Duration) {
	method := shortMethod(fullMethod)
	code := status.Code(err).String()
	m.Duration.WithLabelValues(method, code).Observe(dur.Seconds())
	m.Requests.WithLabelValues(method, code).Inc()
}

// shortMethod strips the "/litevirt.v1.LiteVirt/" prefix so the label is
// just "Ping" / "CreateVM" / etc. Falls back to the full path if the prefix
// is unfamiliar (other gRPC services registered against the same server).
func shortMethod(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 && i < len(full)-1 {
		return full[i+1:]
	}
	return full
}
