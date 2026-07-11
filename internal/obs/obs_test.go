package obs

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/stats"
)

// telemetryEnvKeys are every env var Setup reads or writes. cleanEnv isolates a
// test from ambient/leftover values by unsetting them all and restoring on
// cleanup, so the gated defaults are exercised deterministically.
var telemetryEnvKeys = []string{
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
	"PROVIDE_EXPORTER_LOGS_TIMEOUT_SECONDS", "PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS",
	"PROVIDE_EXPORTER_LOGS_RETRIES", "PROVIDE_EXPORTER_TRACES_RETRIES",
	"PROVIDE_EXPORTER_LOGS_BACKOFF_SECONDS", "PROVIDE_EXPORTER_TRACES_BACKOFF_SECONDS",
	"PROVIDE_EXPORTER_LOGS_FAIL_OPEN", "PROVIDE_EXPORTER_TRACES_FAIL_OPEN",
	"PROVIDE_EXPORTER_LOGS_SHUTDOWN_TIMEOUT_SECONDS",
}

func f64p(v float64) *float64 { return &v }

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
		SampleRate:   f64p(0.5),
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
	// Metrics export is forced OFF — obs is logs+traces only (Prometheus owns
	// metrics). Asserting "false" (not empty): the vendor defaults metrics ON and
	// maps the shared OTLP endpoint onto them, so obs must actively disable them.
	if got := os.Getenv("PROVIDE_METRICS_ENABLED"); got != "false" {
		t.Errorf("PROVIDE_METRICS_ENABLED = %q; obs must set it to \"false\" to keep OTLP metrics off", got)
	}
}

// Log format defaults to console (human text) so an upgrade doesn't silently flip
// fleet log format to JSON and break journalctl/grep/alerts. Finding 5.
func TestSetup_LogFormatDefaultsConsole(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "s"}) // no LogFormat set
	if got := os.Getenv("PROVIDE_LOG_FORMAT"); got != "console" {
		t.Errorf("PROVIDE_LOG_FORMAT = %q; default must be console (not json), want console", got)
	}
}

// sample_rate is a tristate at the vendor-env boundary: nil leaves
// PROVIDE_SAMPLING_TRACES_RATE unset (library default 100%); an explicit 0 sets
// "0" (sampling disabled) rather than being swallowed as "unset".
func TestSetup_SampleRateTristate(t *testing.T) {
	t.Run("nil leaves rate unset", func(t *testing.T) {
		cleanEnv(t)
		setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318"})
		if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "" {
			t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q; nil SampleRate must leave it unset (library default)", got)
		}
	})
	t.Run("zero sets 0 (disabled)", func(t *testing.T) {
		cleanEnv(t)
		setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318", SampleRate: f64p(0)})
		if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "0" {
			t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q; SampleRate 0 must set \"0\" (disabled), want \"0\"", got)
		}
	})
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

// Pins the mechanism behind the re-exec fix (findings 1 & 2): calling Setup
// twice on the SAME mutated env (simulating a re-exec that inherited the live,
// obs-mutated os.Environ()) accumulates OTEL_RESOURCE_ATTRIBUTES across calls.
// Restoring the pristine pre-Setup env between calls (simulating a re-exec
// that carries the snapshot taken before Setup ran) does not.
func TestSetup_RepeatedSetupOnMutatedEnv_AccumulatesResourceAttrs(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{HostName: "node-7"})
	first := os.Getenv("OTEL_RESOURCE_ATTRIBUTES")

	// Re-exec inheriting the live, already-mutated env (the bug): Setup runs
	// again on top of its own prior output.
	setup(t, Config{HostName: "node-7"})
	second := os.Getenv("OTEL_RESOURCE_ATTRIBUTES")

	if second == first {
		t.Fatalf("expected accumulation when Setup runs twice on a mutated env; got same value %q both times", first)
	}
	if want := first + "," + first; second != want {
		t.Fatalf("OTEL_RESOURCE_ATTRIBUTES after 2nd Setup = %q; want accumulated %q", second, want)
	}
}

func TestSetup_ReSetupOnPristineEnv_NoResourceAttrAccumulation(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{HostName: "node-7"})
	first := os.Getenv("OTEL_RESOURCE_ATTRIBUTES")

	// A pristine-env re-exec (the fix) starts obs from the same clean slate
	// every time — none of the telemetry env vars Setup writes carry forward.
	for _, k := range telemetryEnvKeys {
		_ = os.Unsetenv(k)
	}

	setup(t, Config{HostName: "node-7"})
	second := os.Getenv("OTEL_RESOURCE_ATTRIBUTES")

	if second != first {
		t.Fatalf("OTEL_RESOURCE_ATTRIBUTES after re-exec on pristine env = %q; want no accumulation (%q)", second, first)
	}
}

// A directly-exported OTEL_EXPORTER_OTLP_ENDPOINT that has no scheme (e.g. a
// bare gRPC "host:port") bypasses daemon.normalizeTelemetry's config-file
// guard entirely — it never touches the config struct. obs must validate the
// resolved endpoint itself: tracing must stay off and the malformed value
// must not survive Setup (otherwise otelgrpc attaches and every export
// fails). Finding 5.
func TestSetup_InvalidEndpointEnv_TracingOffAndUnset(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317") // no scheme, gRPC port
	setup(t, Config{ServiceName: "s"})

	if TracingActive() {
		t.Error("TracingActive() = true with an invalid (schemeless) endpoint; want false")
	}
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != "" {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q after Setup; invalid endpoint must be unset", got)
	}
	if got := os.Getenv("PROVIDE_LOG_OTLP_ENABLED"); got != "" {
		t.Errorf("PROVIDE_LOG_OTLP_ENABLED = %q after Setup; must not stay enabled for an invalid endpoint", got)
	}
}

// A config-sourced endpoint with a non-http(s) scheme or missing host must be
// rejected the same way as normalizeTelemetry would reject it in the config
// file — obs is the runtime authority and must not trust the caller.
func TestSetup_InvalidEndpointConfig_TracingOff(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "otel-collector:4317"})

	if TracingActive() {
		t.Error("TracingActive() = true with an invalid config endpoint; want false")
	}
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != "" {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q after Setup; invalid endpoint must be unset", got)
	}
}

// A directly-exported LITEVIRT_TRACES_SAMPLE_RATE bypasses
// normalizeTelemetry's NaN/range guard entirely (it's mapped straight onto
// PROVIDE_SAMPLING_TRACES_RATE before any config validation runs). obs must
// reject it and fall back to the library default rather than feed a bogus
// value downstream. Finding 5.
func TestSetup_InvalidSampleRateEnv_FallsBackToDefault(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_TRACES_SAMPLE_RATE", "7")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318"})

	if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "" {
		t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q after Setup with out-of-range input 7; want unset (library default)", got)
	}
}

func TestSetup_NaNSampleRateEnv_FallsBackToDefault(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_TRACES_SAMPLE_RATE", "NaN")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318"})

	if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "" {
		t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q after Setup with NaN input; want unset (library default)", got)
	}
}

// A valid sample rate arriving via env is left untouched.
func TestSetup_ValidSampleRateEnv_Passthrough(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_TRACES_SAMPLE_RATE", "0.25")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318"})

	if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "0.25" {
		t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q; want 0.25 (valid value must pass through)", got)
	}
}

// otelHTTPServer is a minimal httptest server standing in for an OTLP HTTP
// collector: it accepts any POST and returns 200 OK while recording the
// Authorization header of each request it sees.
func otelHTTPServer(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() string { mu.Lock(); defer mu.Unlock(); return lastAuth }
}

// The real root-cause fix for finding 3: obs must build and inject its own
// sampler-bearing TracerProvider, because the vendor builds its default
// tracer provider with NO sampler at all (SDK default: AlwaysSample). A
// sample_rate of 0 must actually stop spans from being sampled — obs.Span and
// otelgrpc both read the OTel *global* tracer provider, so this exercises the
// injected provider end-to-end via the standard otel API.
func TestSetup_SamplerWired_ZeroRateNeverSamples(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "sampler-test", OTLPEndpoint: srv.URL, SampleRate: f64p(0)})

	ctx, span := Span(context.Background(), "unit.span")
	sc := oteltrace.SpanContextFromContext(ctx)
	span.End()

	if sc.IsSampled() {
		t.Error("span was sampled with sample_rate=0; the injected sampler must gate real spans, not just the vendor's unused telemetry.Trace() path")
	}
}

// A sample_rate of 1.0 (or unset) must sample every root span — the
// complementary case proving the sampler is wired, not just always-off.
func TestSetup_SamplerWired_FullRateAlwaysSamples(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "sampler-test", OTLPEndpoint: srv.URL, SampleRate: f64p(1)})

	ctx, span := Span(context.Background(), "unit.span")
	sc := oteltrace.SpanContextFromContext(ctx)
	span.End()

	if !sc.IsSampled() {
		t.Error("span was not sampled with sample_rate=1.0; want always sampled")
	}
}

// Pins the vendor promotion this fix relies on: after Setup, the OTel global
// tracer provider must be the *sdktrace.TracerProvider obs built and
// injected via WithTracerProvider — not the vendor's own default (unsampled)
// one. A vendor bump that stopped promoting an injected provider would
// silently revert finding 3.
func TestSetup_InjectedTracerProviderBecomesGlobal(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "promo-test", OTLPEndpoint: srv.URL, SampleRate: f64p(0)})

	// The vendor's default (unsampled) provider would sample everything; ours
	// with rate 0 samples nothing. Use that behavioral difference to prove
	// otel.GetTracerProvider() is serving OUR provider, since the vendor
	// exposes no exported type to compare pointers against directly.
	tracer := otel.GetTracerProvider().Tracer("promo-check")
	_, span := tracer.Start(context.Background(), "promo.span")
	sampled := span.SpanContext().IsSampled()
	span.End()

	if sampled {
		t.Error("otel.GetTracerProvider() still samples everything at rate 0; the injected provider was not promoted to the OTel global")
	}
}

// Ordering invariant: the trace exporter must be built (reading
// OTEL_EXPORTER_OTLP_HEADERS) BEFORE Setup scrubs the credential env vars, or
// a re-exec/upgrade race would silently produce an unauthenticated exporter.
func TestSetup_TraceExporterBuiltBeforeCredentialScrub(t *testing.T) {
	cleanEnv(t)
	srv, lastAuth := otelHTTPServer(t)
	t.Setenv("LITEVIRT_OTEL_HEADERS", "Authorization=Bearer secret123")

	shutdown, err := Setup(context.Background(), Config{
		ServiceName: "auth-test", OTLPEndpoint: srv.URL, SampleRate: f64p(1),
	})
	if err != nil {
		t.Logf("Setup returned (non-fatal): %v", err)
	}
	_, span := Span(context.Background(), "auth.span")
	span.End()

	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(sctx); err != nil {
		t.Logf("shutdown: %v", err)
	}

	if got := lastAuth(); got != "Bearer secret123" {
		t.Errorf("collector saw Authorization = %q; want \"Bearer secret123\" — the exporter must be built before the credential is scrubbed from env", got)
	}
}

// The obs-owned traces provider bypasses the vendor's own resilience/health
// wrapper entirely, so export failures must surface via an obs-installed
// otel.SetErrorHandler, not the (now-idle-for-traces) vendor health snapshot.
func TestSetup_TraceExportErrorCounter_ErroringCollector(t *testing.T) {
	if testing.Short() {
		t.Skip("drives a real batch export against an erroring collector")
	}
	cleanEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv("LITEVIRT_OTEL_TIMEOUT", "1")
	t.Setenv("LITEVIRT_OTEL_RETRIES", "0")

	before := ExportErrors()
	shutdown, err := Setup(context.Background(), Config{
		ServiceName: "trace-err-test", OTLPEndpoint: srv.URL, SampleRate: f64p(1),
	})
	if err != nil {
		t.Logf("Setup (non-fatal): %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, span := Span(context.Background(), "trace-err.span")
		span.End()
		if ExportErrors()-before > 0 {
			sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = shutdown(sctx)
			cancel()
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = shutdown(sctx)
	cancel()
	t.Errorf("ExportErrors did not increment against a 503-returning collector (still %d)", ExportErrors())
}

// Since the obs-owned traces provider makes drop/circuit state genuinely
// unobservable for the traces signal, Health() must report "unknown" for
// TracesCircuit rather than a stale/misleading vendor constant that never
// moves (which would read as a permanently healthy dashboard).
func TestHealth_TracesCircuitUnknown_WhenTracingActive(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "circuit-test", OTLPEndpoint: srv.URL, SampleRate: f64p(1)})

	if got := Health().TracesCircuit; got != "unknown" {
		t.Errorf("Health().TracesCircuit = %q; want \"unknown\" (obs-owned traces provider has no observable vendor circuit)", got)
	}
}

// With no OTLP endpoint and no explicit log_format/log_level, Setup must
// leave slog.Default() completely untouched — byte-for-byte parity with the
// pre-telemetry daemon, which never called slog.SetDefault at all. Adopting
// even a plain stdlib handler would change the journalctl/grep surface
// (finding 4), and adopting the vendor logger pays PII-redaction/schema cost
// on every record and mangles litevirt's deliberately-non-secret token= lines.
func TestSetup_NoEndpointNoExplicitFormat_LeavesSlogDefaultUntouched(t *testing.T) {
	cleanEnv(t)
	before := slog.Default()
	setup(t, Config{ServiceName: "s"})
	if slog.Default() != before {
		t.Error("slog.Default() changed with no endpoint and no explicit log_format/log_level; want untouched")
	}
}

// An operator who explicitly asks for structured/leveled local logs (no
// endpoint) gets a plain stdlib handler — not the vendor logger, which would
// pay PII-redaction/schema cost per record and default-redact litevirt's
// token= capability lines. json -> JSONHandler.
func TestSetup_NoEndpointExplicitJSONFormat_InstallsStdlibJSONHandler(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "s", LogFormat: "json"})

	if _, ok := slog.Default().Handler().(*slog.JSONHandler); !ok {
		t.Errorf("slog.Default().Handler() = %T; want *slog.JSONHandler (stdlib, not vendor) for explicit log_format=json with no endpoint", slog.Default().Handler())
	}
}

// A non-json explicit format (or an explicit log_level with the default
// format) gets the stdlib TextHandler.
func TestSetup_NoEndpointExplicitLogLevel_InstallsStdlibTextHandler(t *testing.T) {
	cleanEnv(t)
	setup(t, Config{ServiceName: "s", LogLevel: "DEBUG"})

	if _, ok := slog.Default().Handler().(*slog.TextHandler); !ok {
		t.Errorf("slog.Default().Handler() = %T; want *slog.TextHandler (stdlib, not vendor) for explicit log_level with no endpoint", slog.Default().Handler())
	}
}

// An endpoint adopts the vendor logger as before, and defaults
// PROVIDE_LOG_SANITIZE to false so litevirt's deliberately-non-secret
// token=split_brain_gate_v1-style capability lines aren't redacted in the
// exported stream either — litevirt owns its own log hygiene; the real
// collector credential is scrubbed separately. Finding 4.
func TestSetup_Endpoint_LogSanitizeDefaultsFalse(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL})

	if got := os.Getenv("PROVIDE_LOG_SANITIZE"); got != "false" {
		t.Errorf("PROVIDE_LOG_SANITIZE = %q; want \"false\" by default when an endpoint is set", got)
	}
}

// An operator who explicitly wants vendor PII redaction back can still opt in.
func TestSetup_Endpoint_LogSanitizeOperatorOverrideRespected(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	_ = os.Setenv("PROVIDE_LOG_SANITIZE", "true")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL})

	if got := os.Getenv("PROVIDE_LOG_SANITIZE"); got != "true" {
		t.Errorf("PROVIDE_LOG_SANITIZE = %q; an operator-set value must not be overridden, want true", got)
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

// A resilience knob fans out onto every per-signal vendor var it covers, and
// wins over a directly-set PROVIDE_EXPORTER_* value (LITEVIRT_* precedence).
func TestSetup_ResilienceKnobsFanOut(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_OTEL_TIMEOUT", "3")
	_ = os.Setenv("LITEVIRT_OTEL_FAIL_OPEN", "true")
	_ = os.Setenv("LITEVIRT_OTEL_SHUTDOWN_TIMEOUT", "2")
	// A direct vendor value must be overridden by the LITEVIRT_* knob.
	_ = os.Setenv("PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS", "60")

	setup(t, Config{ServiceName: "resilience-test", OTLPEndpoint: "http://127.0.0.1:4318"})

	want := map[string]string{
		"PROVIDE_EXPORTER_LOGS_TIMEOUT_SECONDS":          "3",
		"PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS":        "3", // overrode the direct "60"
		"PROVIDE_EXPORTER_LOGS_FAIL_OPEN":                "true",
		"PROVIDE_EXPORTER_TRACES_FAIL_OPEN":              "true",
		"PROVIDE_EXPORTER_LOGS_SHUTDOWN_TIMEOUT_SECONDS": "2",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q; want %q", k, got, v)
		}
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

// ExportErrors() must register REAL OTLP export failures at a dead collector,
// read from the vendor health snapshot. Regression guard for the root cause: the
// fail-open resilience wrapper swallows export errors and returns success to the
// SDK, so an otel.SetErrorHandler-based counter reads 0 here (it did — that was
// the bug). Drives a real batch export, so it is slow; skipped under -short.
func TestExportErrorCounter_DeadCollector(t *testing.T) {
	if testing.Short() {
		t.Skip("drives a real batch export against a dead collector (~5s)")
	}
	cleanEnv(t)
	// Bound each export attempt so a dead collector fails fast instead of sitting
	// in the OTLP exporter's own multi-second retry.
	t.Setenv("LITEVIRT_OTEL_TIMEOUT", "1")
	t.Setenv("LITEVIRT_OTEL_RETRIES", "0")
	before := ExportErrors()
	setup(t, Config{ServiceName: "err-test", OTLPEndpoint: "http://127.0.0.1:59999"})

	// Emit spans + logs, then poll until the scheduled batch export fires against
	// the dead port and the vendor records the failures.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		slog.Info("dead-collector probe")
		_ = Trace(context.Background(), "probe.span", func(context.Context) error { return nil })
		if ExportErrors()-before > 0 {
			return // failures observed — the counter is live
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("ExportErrors did not increment at a dead collector (still %d); the counter is dead — "+
		"the fail-open wrapper swallows errors before otel.Handle", ExportErrors())
}

// The OTLP auth credential must NOT survive Setup in the process environment, so
// daemon-forked children (QEMU, libvirt helpers, hooks, gh) can't inherit it. The
// non-secret endpoint must remain. Guards finding 6.
func TestSetup_ScrubsCredentialEnvAfterSetup(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_OTEL_HEADERS", "Authorization=Basic c2VjcmV0")   // via mapping
	_ = os.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-api-key=direct")   // direct vendor var
	setup(t, Config{ServiceName: "cred-test", OTLPEndpoint: "http://127.0.0.1:4318"})

	for _, k := range []string{
		"LITEVIRT_OTEL_HEADERS",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
		"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
	} {
		if v := os.Getenv(k); v != "" {
			t.Errorf("%s = %q after Setup; credential must be scrubbed so children don't inherit it", k, v)
		}
	}
	// The endpoint is not secret and must survive (children/telemetry still need it).
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got == "" {
		t.Error("OTEL_EXPORTER_OTLP_ENDPOINT was scrubbed; only the credential should be")
	}
}

// adoptLogger never returns nil, so slog.SetDefault can't panic even if the vendor
// hands back a nil logger on its error path (fail-open, not fail-closed). Finding 10.
func TestAdoptLogger_NilSafe(t *testing.T) {
	if got := adoptLogger(nil); got == nil {
		t.Error("adoptLogger(nil) = nil; must fall back to a usable logger")
	}
	l := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if got := adoptLogger(l); got != l {
		t.Error("adoptLogger(l) must return l unchanged when non-nil")
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
