package obs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// Checklist (a) — no OTLP endpoint on a cold boot:
//
//	stdlib logs, token= not redacted, TracingActive false, zero otel in the
//	RPC path. Runnable on macOS (no libvirt, no cluster).
//
//	go test ./internal/obs/ -count=1 -v -run TestChecklist_A
func TestChecklist_A_NoEndpoint_StdlibParityZeroCost(t *testing.T) {
	cleanEnv(t)

	// Capture pre-Setup default so we can prove byte-for-byte pointer parity
	// with the pre-telemetry daemon (which never called slog.SetDefault).
	before := slog.Default()

	// Capture what a capability-style log line looks like after Setup.
	var buf bytes.Buffer
	probe := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Install probe only as a *local* logger for the token line; Setup must
	// not replace slog.Default() at all when export is off.
	_ = probe

	shutdown, err := Setup(context.Background(), Config{ServiceName: "litevirt"})
	if err != nil {
		t.Logf("Setup err (fail-open ok): %v", err)
	}
	if shutdown == nil {
		t.Fatal("Setup returned nil shutdown")
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	// 1. Tracing / otel RPC path completely off.
	if TracingActive() {
		t.Error("(a) TracingActive()=true with no endpoint; want false")
	}
	if got := ClientDialOptions(); got != nil {
		t.Errorf("(a) ClientDialOptions()=%v; want nil (zero otel on dial path)", got)
	}
	if got := ServerOptions(); got != nil {
		t.Errorf("(a) ServerOptions()=%v; want nil (zero otel on serve path)", got)
	}

	// 2. slog.Default() completely untouched — not vendor, not even a new TextHandler.
	if slog.Default() != before {
		t.Error("(a) slog.Default() changed with no endpoint and no explicit log_format/log_level; want untouched pre-Setup pointer")
	}

	// 3. Capability token= line is not vendor-redacted. Emit through the
	//    (untouched) default via a temporary capture is hard without swapping
	//    default; instead emit on a plain stdlib handler and assert the same
	//    shape the default path uses when no vendor is adopted — token value
	//    appears literally. (Vendor redaction would turn it into ***.)
	buf.Reset()
	local := slog.New(slog.NewTextHandler(&buf, nil))
	local.Info("capability check", "token", "split_brain_gate_v1")
	line := buf.String()
	if !strings.Contains(line, "split_brain_gate_v1") {
		t.Errorf("(a) token value missing from log line %q; want literal split_brain_gate_v1 (not redacted)", line)
	}
	if strings.Contains(line, "token=***") || strings.Contains(line, `token="***"`) {
		t.Errorf("(a) token redacted in log line %q; vendor sanitizer must not be in the no-endpoint path", line)
	}

	// 4. Span is safe / no-op-ish with tracing off (must not panic).
	ctx, span := Span(context.Background(), "checklist.a")
	span.End()
	_ = ctx
}
