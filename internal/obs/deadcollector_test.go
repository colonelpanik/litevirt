package obs

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// blackHole is a TCP listener that accepts connections and never replies —
// simulating a hung/unreachable OTLP collector (the worst case: the socket is
// open so the exporter blocks on a read instead of failing fast).
type blackHole struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newBlackHole(t *testing.T) *blackHole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &blackHole{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns = append(b.conns, c)
			b.mu.Unlock()
			// hold the connection open, never respond
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		b.mu.Lock()
		for _, c := range b.conns {
			_ = c.Close()
		}
		b.mu.Unlock()
	})
	return b
}

func (b *blackHole) endpoint() string { return "http://" + b.ln.Addr().String() }

// A dead/hung collector must never degrade the control plane: telemetry setup
// must not hang, span/log emission must stay non-blocking (async batch export),
// and shutdown must be bounded — it may drop pending data (fail-open) but must
// return, never wedge the daemon.
func TestDeadCollector_DoesNotDegradeControlPlane(t *testing.T) {
	cleanEnv(t)
	bh := newBlackHole(t)

	// Keep exporter attempts short so a hung export can't drag the test.
	t.Setenv("PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS", "1")
	t.Setenv("PROVIDE_EXPORTER_LOGS_TIMEOUT_SECONDS", "1")
	t.Setenv("PROVIDE_EXPORTER_METRICS_TIMEOUT_SECONDS", "1")
	t.Setenv("PROVIDE_EXPORTER_LOGS_SHUTDOWN_TIMEOUT_SECONDS", "1")

	ctx := context.Background()

	// 1) Setup must not block on the unreachable collector.
	setupDone := make(chan struct{})
	var shutdown func(context.Context) error
	go func() {
		s, err := Setup(ctx, Config{
			ServiceName:  "deadcollector-test",
			HostName:     "node-dead",
			OTLPEndpoint: bh.endpoint(),
			SampleRate:   f64p(1.0),
		})
		if err != nil {
			t.Logf("Setup returned (fail-open, non-fatal): %v", err)
		}
		shutdown = s
		close(setupDone)
	}()
	select {
	case <-setupDone:
	case <-time.After(10 * time.Second):
		t.Fatal("obs.Setup blocked >10s on an unreachable OTLP collector")
	}
	if !TracingActive() {
		t.Fatal("tracing should be active (endpoint configured)")
	}
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = shutdown(sctx)
	})

	// 2) Emitting spans + logs must stay non-blocking regardless of collector
	// state — the batch exporter enqueues and returns; it must never block a
	// hot path (an RPC handler, a migration step) on the network.
	const n = 500
	log := Logger(ctx, "dead")
	start := time.Now()
	for i := 0; i < n; i++ {
		_, span := Span(ctx, "dead.collector.span")
		span.SetAttribute("i", strconv.Itoa(i))
		span.End()
		if i%100 == 0 { // exercise the log-export path too, without spamming output
			log.InfoContext(ctx, "dead.collector.log", "i", i)
		}
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("emitting %d spans+logs took %v against a dead collector; expected non-blocking (<3s)", n, elapsed)
	}

	// 3) Shutdown must be bounded even when the collector never responds — it
	// may fail to flush (data dropped, fail-open) but must return, not wedge.
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shutdown(sctx) }()
	select {
	case <-done: // returned (nil or error both acceptable — fail-open)
	case <-time.After(10 * time.Second):
		t.Fatal("ShutdownTelemetry did not return within 10s against a hung collector")
	}
	// shutdown ran; make the deferred cleanup shutdown a harmless no-op re-call
	shutdown = func(context.Context) error { return nil }
}

// A collector that refuses connections (nothing listening) must be handled the
// same way — fail-open, non-blocking.
func TestDeadCollector_ConnectionRefused(t *testing.T) {
	cleanEnv(t)
	// Grab a port then close it so connects are refused immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	endpoint := "http://" + ln.Addr().String()
	_ = ln.Close()

	t.Setenv("PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS", "1")
	t.Setenv("PROVIDE_EXPORTER_LOGS_TIMEOUT_SECONDS", "1")

	ctx := context.Background()
	shutdown, err := Setup(ctx, Config{ServiceName: "refused-test", OTLPEndpoint: endpoint, SampleRate: f64p(1.0)})
	if err != nil {
		t.Logf("Setup (fail-open): %v", err)
	}

	start := time.Now()
	for i := 0; i < 200; i++ {
		_, span := Span(ctx, "refused.span")
		span.End()
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("span emission took %v with a refused collector; expected non-blocking", elapsed)
	}

	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shutdown(sctx) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("shutdown did not return within 8s (connection-refused collector)")
	}
}
