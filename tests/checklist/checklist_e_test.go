// Package checklist holds Mac-runnable verification for the telemetry
// pass-2 review items that need multi-package wiring (obs + pki + gRPC).
//
//	go test ./tests/checklist/ -count=1 -v
package checklist

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/obs"
	"github.com/litevirt/litevirt/internal/pki"
)

// Checklist (e) — every pki.PeerDial (including corrosion paths that pass no
// dial opts of their own) injects W3C traceparent when the daemon has wired
// pki.SetTraceDialOptions(obs.ClientDialOptions) after obs.Setup.
//
// Runnable on macOS: loopback mTLS + fake OTLP endpoint, no libvirt/QEMU.
//
//	go test ./tests/checklist/ -count=1 -v -run TestChecklist_E
func TestChecklist_E_PeerDialInjectsTraceparent(t *testing.T) {
	cleanTelemetryEnv(t)

	// Fake collector so Setup treats the endpoint as valid and builds the
	// sampler-bearing tracer provider (otlptracehttp dials lazily).
	lnOTLP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lnOTLP.Close() })
	go acceptAndDrop(lnOTLP)
	endpoint := "http://" + lnOTLP.Addr().String()

	shutdown, err := obs.Setup(context.Background(), obs.Config{
		ServiceName:  "checklist-e",
		OTLPEndpoint: endpoint,
		SampleRate:   f64p(1),
	})
	if err != nil {
		t.Logf("Setup err (fail-open ok): %v", err)
	}
	if shutdown == nil {
		t.Fatal("nil shutdown")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	})

	if !obs.TracingActive() {
		t.Fatal("TracingActive()=false; checklist (e) requires tracing on")
	}

	// Daemon boot wiring: after Setup, install the hook so every PeerDial
	// (replicator/anti-entropy included) gets client trace options.
	pki.SetTraceDialOptions(obs.ClientDialOptions)
	t.Cleanup(func() { pki.SetTraceDialOptions(nil) })

	// Peer mTLS server that captures inbound metadata on Health/Check
	// (not in obs noisyMethods, so the client filter will instrument it).
	pkiDir := setupLoopbackPKI(t)
	var (
		mu     sync.Mutex
		lastMD metadata.MD
	)
	srvTLS, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(srvTLS)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				mu.Lock()
				lastMD = md.Copy()
				mu.Unlock()
			}
			return handler(ctx, req)
		}),
	)
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)

	target := ln.Addr().String()
	conn, err := pki.PeerDial(pkiDir, target)
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Start a real sampled span so the client has a valid SpanContext to inject.
	// Use the global provider (obs injects its *sdktrace.TracerProvider).
	tp := otel.GetTracerProvider()
	if _, ok := tp.(*sdktrace.TracerProvider); !ok {
		t.Fatalf("global TracerProvider type %T; want *sdktrace.TracerProvider", tp)
	}
	ctx, span := tp.Tracer("checklist-e").Start(context.Background(), "peer.probe")
	defer span.End()
	if !span.SpanContext().IsSampled() {
		t.Fatal("root span not sampled at rate 1.0; cannot assert traceparent injection")
	}

	client := healthpb.NewHealthClient(conn)
	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := client.Check(rpcCtx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("Health/Check RPC: %v", err)
	}

	mu.Lock()
	md := lastMD
	mu.Unlock()
	tps := md.Get("traceparent")
	if len(tps) == 0 || tps[0] == "" {
		t.Fatalf("(e) PeerDial RPC arrived without traceparent; metadata=%v — "+
			"SetTraceDialOptions(obs.ClientDialOptions) must inject W3C context on every peer dial", md)
	}
	// Sanity: trace-id in traceparent should match our span (00-traceid-spanid-flags).
	wantTrace := span.SpanContext().TraceID().String()
	if !strings.Contains(tps[0], wantTrace) {
		t.Errorf("(e) traceparent=%q does not contain span trace id %s", tps[0], wantTrace)
	}
	t.Logf("checklist (e) OK: traceparent=%s", tps[0])
}

// Negative control: with no hook and tracing off, PeerDial still works and
// must not require obs (corrosion boot order / tracing-disabled nodes).
func TestChecklist_E_PeerDialWithoutHook_NoTraceparentRequired(t *testing.T) {
	cleanTelemetryEnv(t)
	pki.SetTraceDialOptions(nil)

	pkiDir := setupLoopbackPKI(t)
	var (
		mu     sync.Mutex
		lastMD metadata.MD
	)
	srvTLS, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(srvTLS)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				mu.Lock()
				lastMD = md.Copy()
				mu.Unlock()
			}
			return handler(ctx, req)
		}),
	)
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); gs.Stop() })
	go func() { _ = gs.Serve(ln) }()

	conn, err := pki.PeerDial(pkiDir, ln.Addr().String())
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("Health/Check: %v", err)
	}
	mu.Lock()
	md := lastMD
	mu.Unlock()
	if tps := md.Get("traceparent"); len(tps) > 0 && tps[0] != "" {
		// Without obs hook there should be no automatic injection. If some
		// ambient global interceptor appears in future, this flags it.
		t.Logf("note: traceparent present without hook (%v) — unexpected but not a checklist failure", tps)
	}
}

func f64p(v float64) *float64 { return &v }

func acceptAndDrop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}

func setupLoopbackPKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(ca, caKey); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	hostCrt := filepath.Join(dir, "host.crt")
	hostKey := filepath.Join(dir, "host.key")
	if err := pki.GenerateHostCert(ca, caKey, hostCrt, hostKey, "checklist-e", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}
	return dir
}

func cleanTelemetryEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
		"PROVIDE_TELEMETRY_SERVICE_NAME", "PROVIDE_TELEMETRY_ENV", "PROVIDE_TELEMETRY_VERSION",
		"PROVIDE_LOG_LEVEL", "PROVIDE_LOG_FORMAT", "PROVIDE_LOG_OTLP_ENABLED", "PROVIDE_LOG_SANITIZE",
		"PROVIDE_SAMPLING_TRACES_RATE", "PROVIDE_METRICS_ENABLED",
		"LITEVIRT_OTEL_ENDPOINT", "LITEVIRT_OTEL_HEADERS",
		"LITEVIRT_TELEMETRY_SERVICE", "LITEVIRT_TELEMETRY_ENV", "LITEVIRT_TELEMETRY_VERSION",
		"LITEVIRT_LOG_LEVEL", "LITEVIRT_LOG_FORMAT", "LITEVIRT_TRACES_SAMPLE_RATE",
		"LITEVIRT_OTEL_TIMEOUT", "LITEVIRT_OTEL_RETRIES", "LITEVIRT_OTEL_BACKOFF",
		"LITEVIRT_OTEL_FAIL_OPEN", "LITEVIRT_OTEL_SHUTDOWN_TIMEOUT",
	}
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, v) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		_ = os.Unsetenv(k)
	}
}

