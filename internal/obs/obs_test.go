package obs

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/stats"
)

// telemetryEnvKeys are every env var Setup reads or writes. cleanEnv isolates a
// test from ambient/leftover values by unsetting them all and restoring on
// cleanup, so the gated defaults are exercised deterministically.
var telemetryEnvKeys = []string{
	"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_RESOURCE_ATTRIBUTES",
	"PROVIDE_TELEMETRY_SERVICE_NAME", "PROVIDE_TELEMETRY_ENV", "PROVIDE_TELEMETRY_VERSION",
	"PROVIDE_LOG_LEVEL", "PROVIDE_LOG_FORMAT", "PROVIDE_LOG_OTLP_ENABLED",
	"PROVIDE_SAMPLING_TRACES_RATE", "PROVIDE_METRICS_ENABLED",
	"LITEVIRT_OTEL_ENDPOINT", "LITEVIRT_OTEL_HEADERS",
	"LITEVIRT_TELEMETRY_SERVICE", "LITEVIRT_TELEMETRY_ENV", "LITEVIRT_TELEMETRY_VERSION",
	"LITEVIRT_LOG_LEVEL", "LITEVIRT_LOG_FORMAT", "LITEVIRT_TRACES_SAMPLE_RATE",
}

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, k := range telemetryEnvKeys {
		if v, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, v) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		_ = os.Unsetenv(k)
	}
	// Leave tracing off between tests regardless of Setup ordering.
	t.Cleanup(func() { tracingActive.Store(false) })
}

func setup(t *testing.T, cfg Config) {
	t.Helper()
	shutdown, err := Setup(context.Background(), cfg)
	if err != nil {
		// Setup is fail-open: a config that can't build an exporter must still
		// return a usable shutdown and never a hard failure here.
		t.Logf("Setup returned (non-fatal): %v", err)
	}
	if shutdown == nil {
		t.Fatal("Setup returned a nil shutdown func")
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })
}

// Tracing must be OFF and no otel gRPC options attached when no endpoint is set.
func TestSetup_NoEndpoint_TracingOff(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "litevirt-test"})

	if TracingActive() {
		t.Error("TracingActive() = true with no endpoint; want false")
	}
	if got := ServerOptions(); got != nil {
		t.Errorf("ServerOptions() = %v with tracing off; want nil", got)
	}
	if got := ClientDialOptions(); got != nil {
		t.Errorf("ClientDialOptions() = %v with tracing off; want nil", got)
	}
}

// A configured endpoint turns tracing on and attaches exactly one otel option to
// each of the server and client sides.
func TestSetup_Endpoint_TracingOnAndOptionsAttached(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "litevirt-test", OTLPEndpoint: "http://127.0.0.1:4317"})

	if !TracingActive() {
		t.Fatal("TracingActive() = false with an endpoint set; want true")
	}
	if got := ServerOptions(); len(got) != 1 {
		t.Errorf("ServerOptions() len = %d; want 1", len(got))
	}
	if got := ClientDialOptions(); len(got) != 1 {
		t.Errorf("ClientDialOptions() len = %d; want 1", len(got))
	}
}

// Setup is idempotent: a first call with an endpoint then a second without one
// must turn instrumentation back off (regression guard for the gating flag).
func TestSetup_Idempotent_ResetsTracing(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{OTLPEndpoint: "http://127.0.0.1:4317"})
	if !TracingActive() {
		t.Fatal("first Setup with endpoint: TracingActive() = false; want true")
	}
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	setup(t, Config{})
	if TracingActive() {
		t.Error("second Setup without endpoint: TracingActive() = true; want false")
	}
}

// Config fields map onto the vendor env contract.
func TestSetup_ConfigMapsToVendorEnv(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{
		ServiceName:  "svc-x",
		Version:      "1.2.3",
		Environment:  "staging",
		OTLPEndpoint: "http://127.0.0.1:4317",
		SampleRate:   0.5,
		LogLevel:     "WARNING",
		LogFormat:    "console",
	})

	want := map[string]string{
		"PROVIDE_TELEMETRY_SERVICE_NAME": "svc-x",
		"PROVIDE_TELEMETRY_VERSION":      "1.2.3",
		"PROVIDE_TELEMETRY_ENV":          "staging",
		"OTEL_EXPORTER_OTLP_ENDPOINT":    "http://127.0.0.1:4317",
		"PROVIDE_SAMPLING_TRACES_RATE":   "0.5",
		"PROVIDE_LOG_LEVEL":              "WARNING",
		"PROVIDE_LOG_FORMAT":             "console",
		"PROVIDE_LOG_OTLP_ENABLED":       "true",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q; want %q", k, got, v)
		}
	}
	// Metrics export stays off — obs is logs+traces only (Prometheus owns metrics).
	if got := os.Getenv("PROVIDE_METRICS_ENABLED"); got != "" {
		t.Errorf("PROVIDE_METRICS_ENABLED = %q; obs must not enable OTLP metrics", got)
	}
}

// HostName becomes host.name + service.instance.id via the standard
// OTEL_RESOURCE_ATTRIBUTES, so mesh spans are attributable to a host.
func TestSetup_HostIdentityResourceAttrs(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "litevirt", HostName: "node-7"})

	got := os.Getenv("OTEL_RESOURCE_ATTRIBUTES")
	if want := "host.name=node-7,service.instance.id=node-7"; got != want {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES = %q; want %q", got, want)
	}
}

// An operator-set OTEL_RESOURCE_ATTRIBUTES is preserved; host attrs append.
func TestSetup_HostIdentityMergesWithOperatorAttrs(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("OTEL_RESOURCE_ATTRIBUTES", "team=infra")
	setup(t, Config{HostName: "node-7"})

	got := os.Getenv("OTEL_RESOURCE_ATTRIBUTES")
	if want := "team=infra,host.name=node-7,service.instance.id=node-7"; got != want {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES = %q; want %q (operator attrs preserved, host appended)", got, want)
	}
}

// A LITEVIRT_* operator override wins over the daemon config value.
func TestSetup_LitevirtEnvOverridesConfig(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_LOG_LEVEL", "DEBUG")
	_ = os.Setenv("LITEVIRT_OTEL_ENDPOINT", "http://collector:4317")

	setup(t, Config{LogLevel: "ERROR", OTLPEndpoint: "http://config-endpoint:4317"})

	if got := os.Getenv("PROVIDE_LOG_LEVEL"); got != "DEBUG" {
		t.Errorf("PROVIDE_LOG_LEVEL = %q; LITEVIRT_LOG_LEVEL must win over config, want DEBUG", got)
	}
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != "http://collector:4317" {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q; LITEVIRT_OTEL_ENDPOINT must win, want http://collector:4317", got)
	}
	if !TracingActive() {
		t.Error("TracingActive() = false; LITEVIRT_OTEL_ENDPOINT should activate tracing")
	}
}

// A directly-exported vendor var is respected (config only fills unset values).
func TestSetup_DirectVendorEnvRespected(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("PROVIDE_LOG_LEVEL", "TRACE")

	setup(t, Config{LogLevel: "INFO"}) // config must not clobber the operator's var

	if got := os.Getenv("PROVIDE_LOG_LEVEL"); got != "TRACE" {
		t.Errorf("PROVIDE_LOG_LEVEL = %q; a directly-set vendor var must not be overwritten by config, want TRACE", got)
	}
}

// Setup installs a usable slog default and Logger returns a non-nil logger.
func TestSetup_InstallsLoggerDefault(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "litevirt-test"})

	if slog.Default() == nil {
		t.Fatal("slog.Default() is nil after Setup")
	}
	if Logger(context.Background(), "unit") == nil {
		t.Fatal("Logger() returned nil")
	}
}

// Span is always safe to call (no-op tracer when tracing is off) and returns a
// usable span whose End does not panic.
func TestSpan_SafeWhenTracingOff(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{})

	ctx, span := Span(context.Background(), "unit.span")
	if ctx == nil {
		t.Fatal("Span returned a nil context")
	}
	span.SetAttribute("k", "v")
	span.End() // must not panic
}

// Noisy machine-to-machine RPCs are suppressed from tracing; real operations
// are traced.
func TestTraceFilter_SuppressesNoisyRPCs(t *testing.T) {
	trace := map[string]bool{ // full method -> should be instrumented
		"/litevirt.v1.LiteVirt/MigrateVM":      true,
		"/litevirt.v1.LiteVirt/CreateVM":       true,
		"/litevirt.v1.LiteVirt/BackupVM":       true,
		"/litevirt.v1.LiteVirt/Ping":           false,
		"/litevirt.v1.LiteVirt/PushMutations":  false,
		"/litevirt.v1.LiteVirt/AckMutations":   false,
		"/litevirt.v1.LiteVirt/GetStateDigest": false,
		"/litevirt.v1.LiteVirt/GetHostHealth":  false,
	}
	for method, want := range trace {
		if got := traceFilter(&stats.RPCTagInfo{FullMethodName: method}); got != want {
			t.Errorf("traceFilter(%q) = %v; want %v", method, got, want)
		}
	}
}

// OTLP export errors are counted (surfaced to Prometheus), not swallowed.
func TestExportErrorCounter(t *testing.T) {
	cleanEnv(t)
	before := ExportErrors()
	setup(t, Config{ServiceName: "err-test", OTLPEndpoint: "http://127.0.0.1:4317"})
	// The global error handler installed by Setup must feed the counter.
	otel.Handle(errors.New("simulated export failure"))
	otel.Handle(errors.New("second failure"))
	if delta := ExportErrors() - before; delta < 2 {
		t.Errorf("ExportErrors delta = %d; want >= 2 (handler must count export failures)", delta)
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("", "fallback"); got != "fallback" {
		t.Errorf("orDefault(\"\", ...) = %q; want fallback", got)
	}
	if got := orDefault("set", "fallback"); got != "set" {
		t.Errorf("orDefault(\"set\", ...) = %q; want set", got)
	}
}
