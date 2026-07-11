// Package obs is litevirt's single integration point for two observability
// pillars: structured logging and distributed tracing. It wraps
// provide-telemetry (github.com/provide-io/provide-telemetry/go) so the rest of
// the codebase depends on this package, not the vendor API directly — the
// backend can be swapped without touching call sites.
//
// Metrics are intentionally OUT of scope here: internal/metrics owns them via
// Prometheus (pull, /metrics). provide-telemetry is OTLP-only with no Prometheus
// exporter, so obs stays logs+traces and metrics stay Prometheus — one system
// per signal, no overlap.
//
// Design:
//   - Logging is the standard library slog. Setup routes slog's *default* logger
//     through provide-telemetry, so every existing slog.Info/Warn/Error call in
//     the tree is enriched (and OTLP-exported when configured) with zero
//     call-site changes.
//   - Tracing/metrics activate only when an OTLP endpoint is configured; with no
//     endpoint the library degrades gracefully to no-op tracers/meters (fail
//     open — the daemon never fails to boot because telemetry is misconfigured).
//   - Trace context propagates across the peer mesh via the W3C tracecontext
//     propagator installed here and the otelgrpc stats handlers exposed by
//     ServerHandler/ClientHandler.
package obs

import (
	"context"
	"io"
	"log/slog"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	telemetry "github.com/provide-io/provide-telemetry/go"
	_ "github.com/provide-io/provide-telemetry/go/otel" // activates OTLP env wiring for SetupTelemetry

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"
)

// scopeName is the instrumentation scope for tracers/loggers created without an
// explicit name.
const scopeName = "litevirt"

// litevirtEnvMap translates litevirt-native operator env vars onto the
// provide-telemetry contract. Operators use the LITEVIRT_* names (consistent
// with LITEVIRT_CONFIG etc.) and never need to know the vendor's PROVIDE_*/OTEL_*
// names — those stay an implementation detail of this package. A LITEVIRT_*
// value, when set, takes precedence over both the daemon config and any directly
// exported vendor var.
var litevirtEnvMap = map[string]string{
	"LITEVIRT_OTEL_ENDPOINT":      "OTEL_EXPORTER_OTLP_ENDPOINT",
	"LITEVIRT_OTEL_HEADERS":       "OTEL_EXPORTER_OTLP_HEADERS",
	"LITEVIRT_TELEMETRY_SERVICE":  "PROVIDE_TELEMETRY_SERVICE_NAME",
	"LITEVIRT_TELEMETRY_ENV":      "PROVIDE_TELEMETRY_ENV",
	"LITEVIRT_TELEMETRY_VERSION":  "PROVIDE_TELEMETRY_VERSION",
	"LITEVIRT_LOG_LEVEL":          "PROVIDE_LOG_LEVEL",
	"LITEVIRT_LOG_FORMAT":         "PROVIDE_LOG_FORMAT",
	"LITEVIRT_TRACES_SAMPLE_RATE": "PROVIDE_SAMPLING_TRACES_RATE",
}

// litevirtResilienceMap fans a single operator-facing exporter-resilience knob
// onto the vendor's per-signal PROVIDE_EXPORTER_* vars. obs exports only LOGS +
// TRACES (metrics are held off, see Setup), so each knob targets exactly those
// two signals — an operator tunes the whole export path with one LITEVIRT_* var
// instead of the vendor's 2–3 per-signal names. LITEVIRT_OTEL_SHUTDOWN_TIMEOUT
// maps to the logs signal only: the vendor exposes a shutdown-drain cap for logs
// alone (traces flush on the batch processor's own timeout).
//
// These caps matter operationally: production sets none of them by default, so a
// slow/unreachable collector can make export calls hang — bounding them keeps
// telemetry init and shutdown from stalling boot / a rolling upgrade.
var litevirtResilienceMap = map[string][]string{
	"LITEVIRT_OTEL_TIMEOUT":          {"PROVIDE_EXPORTER_LOGS_TIMEOUT_SECONDS", "PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS"},
	"LITEVIRT_OTEL_RETRIES":          {"PROVIDE_EXPORTER_LOGS_RETRIES", "PROVIDE_EXPORTER_TRACES_RETRIES"},
	"LITEVIRT_OTEL_BACKOFF":          {"PROVIDE_EXPORTER_LOGS_BACKOFF_SECONDS", "PROVIDE_EXPORTER_TRACES_BACKOFF_SECONDS"},
	"LITEVIRT_OTEL_FAIL_OPEN":        {"PROVIDE_EXPORTER_LOGS_FAIL_OPEN", "PROVIDE_EXPORTER_TRACES_FAIL_OPEN"},
	"LITEVIRT_OTEL_SHUTDOWN_TIMEOUT": {"PROVIDE_EXPORTER_LOGS_SHUTDOWN_TIMEOUT_SECONDS"},
}

// tracingActive gates the gRPC otel instrumentation. It flips true only when an
// OTLP endpoint is configured, so with tracing off there is ZERO otel in the
// RPC dial/serve path — the stats handlers are never attached. Logging still
// routes through provide-telemetry regardless (that path degrades gracefully to
// local structured output and needs no collector).
var tracingActive atomic.Bool

// TracingActive reports whether OTLP tracing/metrics export is on.
func TracingActive() bool { return tracingActive.Load() }

// TelemetryHealth is a point-in-time view of OTLP export health across the
// signals obs exports (logs + traces). Counters are cumulative since telemetry
// setup. Surfaced to Prometheus by internal/metrics. See Health() for the
// per-signal sourcing rules (vendor snapshot vs obs-owned traces provider).
type TelemetryHealth struct {
	ExportFailures int64  // failed export attempts (logs vendor + traces error handler)
	Dropped        int64  // log records shed when the async export queue is full (logs only)
	Retries        int64  // export retry attempts (logs+traces, vendor snapshot)
	LogsCircuit    string // logs-signal circuit-breaker state (closed|half-open|open)
	TracesCircuit  string // always "unknown" — obs-owned traces provider has no observable circuit
}

// traceExportErrors counts export failures for the obs-owned traces provider,
// fed by the otel.SetErrorHandler installed in Setup. It exists because that
// provider bypasses the vendor's own fail-open resilience wrapper (the only
// place the vendor's TracesExportFailures counter is incremented), so the
// vendor's traces snapshot stays permanently at 0 once obs injects its own
// provider — this is the only observable source for that signal.
var traceExportErrors atomic.Int64

// Health returns the current telemetry export health.
//
// Logs stay on the vendor's own exporter/wrapper, so LogsExportFailures/
// LogsDropped/LogsCircuitState MUST read the vendor snapshot: its fail-open
// resilience wrapper (default on) swallows export errors and returns success
// to the OTel SDK, so the SDK never calls otel.Handle for logs — a
// handler-based counter would never move on a dead collector — verified.
//
// Traces run through obs's own injected TracerProvider (see Setup / finding
// 3), which bypasses that vendor wrapper entirely — the vendor's per-signal
// counters and circuit breaker never see a traces export at all. Traces
// export failures are read from traceExportErrors instead. Dropped spans
// (backpressure) and circuit-breaker state for the obs-owned provider are
// genuinely unobservable — reporting the vendor's stale/always-empty traces
// values here would misrepresent them as a healthy circuit. Dropped is
// therefore logs-only, and TracesCircuit is always "unknown".
func Health() TelemetryHealth {
	h := telemetry.GetHealthSnapshot()
	return TelemetryHealth{
		ExportFailures: h.LogsExportFailures + traceExportErrors.Load(),
		Dropped:        h.LogsDropped,
		Retries:        h.LogsRetries + h.TracesRetries,
		LogsCircuit:    h.LogsCircuitState,
		TracesCircuit:  "unknown",
	}
}

// ExportErrors returns the cumulative OTLP export-failure count across logs +
// traces. A nonzero, growing value means the collector is unreachable or
// rejecting data.
func ExportErrors() int64 { return Health().ExportFailures }

// noisyMethods are high-frequency machine-to-machine RPCs — WAL replication,
// anti-entropy state sync, health probes, keepalive — suppressed from tracing so
// they don't bury real operations (migrate/failover/create) in a span flood.
// The library samples traces at 1.0 by default, so without this every 2s health
// probe and every replication push would emit a span. Matched on the trailing
// method name, so it is proto-package-agnostic.
var noisyMethods = map[string]struct{}{
	"Ping":                     {},
	"GetStateDigest":           {},
	"GetStateDump":             {},
	"StreamStateDump":          {},
	"GetSensitiveStateDigest":  {},
	"StreamSensitiveStateDump": {},
	"PushMutations":            {},
	"AckMutations":             {},
	"PushReplicaIncrement":     {},
	"GetHostHealth":            {},
}

// traceFilter reports whether an RPC should be traced (true = instrument).
// Suppresses the noisy machine-to-machine set.
func traceFilter(info *stats.RPCTagInfo) bool {
	m := info.FullMethodName
	if i := strings.LastIndexByte(m, '/'); i >= 0 {
		m = m[i+1:]
	}
	_, noisy := noisyMethods[m]
	return !noisy
}

// Config is the litevirt-facing telemetry configuration, mapped onto the
// provide-telemetry environment contract by Setup. All fields are optional;
// zero values fall back to library defaults (and an empty OTLPEndpoint disables
// OTLP export entirely, leaving local structured logging only).
type Config struct {
	ServiceName  string  // logical service name (default "litevirt")
	Version      string  // build version, surfaced as service.version
	Environment  string  // deployment env, e.g. "prod"/"homelab"
	HostName     string  // this daemon's cluster host name → host.name / service.instance.id
	OTLPEndpoint string  // OTLP HTTP endpoint URL, e.g. "http://otel-collector:4318" (http://|https://, no URL userinfo; auth via LITEVIRT_OTEL_HEADERS); empty = no export
	SampleRate   *float64 // trace sample rate 0.0–1.0; nil = library default (100%), 0 = disabled (0%)
	LogLevel     string  // TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL (default INFO)
	LogFormat    string  // json|console|pretty (default console; set json for structured export)
}

// Setup initializes telemetry and installs the enriched slog default logger.
// It is fail-open: on any setup error it returns the error but the returned
// shutdown func is always safe to call, and slog keeps working. Call once at
// daemon boot; defer the returned shutdown.
//
// Precedence, highest first: LITEVIRT_* operator env (see litevirtEnvMap) >
// directly-exported vendor vars > daemon config > library defaults. Operators
// use the LITEVIRT_* names (e.g. LITEVIRT_OTEL_ENDPOINT, LITEVIRT_LOG_LEVEL);
// the vendor's PROVIDE_*/OTEL_* names are an internal detail of this package.
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	// Captured before SetupTelemetry runs: the vendor's own _configureLogger
	// calls slog.SetDefault unconditionally as part of SetupTelemetry,
	// regardless of any option obs passes — there's no way to opt out of that
	// call itself. So "leave slog.Default() untouched" (finding 4) means obs
	// must explicitly restore this value afterward, not merely skip its own
	// SetDefault call.
	preSetupDefault := slog.Default()
	// Highest precedence: litevirt-native LITEVIRT_* operator overrides, mapped
	// onto the vendor env contract. Applied first so the config-derived defaults
	// below (setEnvDefault) will not clobber them.
	for src, dst := range litevirtEnvMap {
		if v, ok := os.LookupEnv(src); ok {
			_ = os.Setenv(dst, v)
		}
	}
	// Resilience knobs fan one LITEVIRT_* value onto every per-signal vendor var
	// it covers. Same precedence as above: an operator LITEVIRT_* wins over any
	// directly-set PROVIDE_EXPORTER_* value.
	for src, dsts := range litevirtResilienceMap {
		if v, ok := os.LookupEnv(src); ok {
			for _, dst := range dsts {
				_ = os.Setenv(dst, v)
			}
		}
	}

	svc := orDefault(cfg.ServiceName, scopeName)
	setEnvDefault("PROVIDE_TELEMETRY_SERVICE_NAME", svc)
	if cfg.Version != "" {
		setEnvDefault("PROVIDE_TELEMETRY_VERSION", cfg.Version)
	}
	if cfg.Environment != "" {
		setEnvDefault("PROVIDE_TELEMETRY_ENV", cfg.Environment)
	}
	// Captured before the env is filled with defaults below, so it reflects
	// only an actual operator/config ask (cfg field or a directly-exported
	// PROVIDE_LOG_*/LITEVIRT_LOG_* value already mapped above) — used to decide
	// whether local logging (no endpoint) adopts a stdlib handler at all
	// (finding 4).
	explicitLogLevel := cfg.LogLevel != "" || os.Getenv("PROVIDE_LOG_LEVEL") != ""
	explicitLogFormat := cfg.LogFormat != "" || os.Getenv("PROVIDE_LOG_FORMAT") != ""
	if cfg.LogLevel != "" {
		setEnvDefault("PROVIDE_LOG_LEVEL", cfg.LogLevel)
	}
	// Default to "console" (human-readable text), matching the pre-telemetry
	// daemon's stdlib text handler so an upgrade does not silently flip fleet log
	// format and break journalctl/grep/alerts. Operators opt into structured logs
	// with log_format: json.
	setEnvDefault("PROVIDE_LOG_FORMAT", orDefault(cfg.LogFormat, "console"))
	// obs exports LOGS + TRACES only — metrics stay on Prometheus (internal/metrics,
	// pull /metrics). provide-telemetry defaults PROVIDE_METRICS_ENABLED=true and
	// maps the generic OTEL_EXPORTER_OTLP_ENDPOINT onto the metrics signal, so
	// leaving it unset would silently stand up a second, unowned OTLP metrics
	// exporter the moment an endpoint is configured. Force it off. setEnvDefault so
	// an operator can still opt in by exporting PROVIDE_METRICS_ENABLED=true.
	setEnvDefault("PROVIDE_METRICS_ENABLED", "false")
	// nil leaves the vendor sampling default (100%); a set value — including 0,
	// which disables sampling entirely — is passed through explicitly.
	if cfg.SampleRate != nil {
		setEnvDefault("PROVIDE_SAMPLING_TRACES_RATE", strconv.FormatFloat(*cfg.SampleRate, 'f', -1, 64))
	}

	// Host identity on every span/metric/log via the OTel-standard
	// OTEL_RESOURCE_ATTRIBUTES. Without this every daemon emits an identical
	// service.name and a mesh trace can't be attributed to a host. We speak only
	// the standard var — any conformant OTel backend (incl. provide-telemetry once
	// its resource honors WithFromEnv) picks it up; we do not reach into the
	// vendor's Resource. Merge, never clobber, an operator-set value.
	if cfg.HostName != "" {
		hostAttrs := "host.name=" + cfg.HostName + ",service.instance.id=" + cfg.HostName
		if existing := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); existing != "" {
			_ = os.Setenv("OTEL_RESOURCE_ATTRIBUTES", existing+","+hostAttrs)
		} else {
			_ = os.Setenv("OTEL_RESOURCE_ATTRIBUTES", hostAttrs)
		}
	}
	if cfg.OTLPEndpoint != "" {
		// The blank-imported /go/otel wires OTLP export from the standard OTEL_*
		// env. Logs are enabled here and traces via the gating below; metrics are
		// held off above (PROVIDE_METRICS_ENABLED=false) so the shared endpoint
		// does not stand up an OTLP metrics exporter — metrics stay on Prometheus.
		setEnvDefault("OTEL_EXPORTER_OTLP_ENDPOINT", cfg.OTLPEndpoint)
		setEnvDefault("PROVIDE_LOG_OTLP_ENABLED", "true")
	}

	// The resolved sample rate is validated here regardless of source: a
	// directly-exported LITEVIRT_TRACES_SAMPLE_RATE (mapped onto
	// PROVIDE_SAMPLING_TRACES_RATE above, before normalizeTelemetry's
	// config-file NaN/range guard ever runs) can carry a bogus value straight
	// through. obs is the runtime authority — mirror that guard here so a bad
	// value never reaches the sampler: fall back to the library default (1.0)
	// rather than pass it on.
	if raw := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); raw != "" {
		if _, ok := validSampleRate(raw); !ok {
			_ = os.Unsetenv("PROVIDE_SAMPLING_TRACES_RATE")
			// A bogus operator override must not silently discard a valid
			// configured rate: fall back to cfg.SampleRate (already range-
			// checked by normalizeTelemetry) rather than the library default
			// (1.0), which would flip sampling back to 100% behind the
			// operator's back. Only the library default remains if neither the
			// env value nor config is usable.
			fallback := "library default (1.0)"
			if cfg.SampleRate != nil {
				_ = os.Setenv("PROVIDE_SAMPLING_TRACES_RATE", strconv.FormatFloat(*cfg.SampleRate, 'f', -1, 64))
				fallback = "configured sample_rate"
			}
			slog.Warn("telemetry: sample rate is invalid — using "+fallback,
				"sample_rate", raw, "valid_range", "0.0-1.0")
		}
	}

	// Tracing is active only when the resolved endpoint — from config or
	// directly-exported operator env — is a valid http(s) URL with a host.
	// A bare presence check would let a schemeless/gRPC-port value (e.g.
	// "otel-collector:4317") through, making otelgrpc attach and every export
	// fail 100%. Invalid → warn and actively unset the endpoint (and log-OTLP
	// enablement) so the vendor doesn't build a broken exporter either. Stored
	// unconditionally so Setup is idempotent (a later call with no endpoint
	// correctly turns instrumentation back off).
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	active := validEndpoint(endpoint)
	if endpoint != "" && !active {
		slog.Warn("telemetry: otlp_endpoint is invalid — disabling OTLP export",
			"otlp_endpoint", SafeEndpointForLog(endpoint),
			"requires", "http:// or https:// scheme with a host, no URL userinfo (use LITEVIRT_OTEL_HEADERS for auth)")
		_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		_ = os.Unsetenv("PROVIDE_LOG_OTLP_ENABLED")
	}
	tracingActive.Store(active)
	var setupOpts []telemetry.SetupOption
	var appliedRate float64 = 1.0
	if active {
		// W3C tracecontext + baggage so otelgrpc injects on dial and extracts on
		// serve — this is what carries a trace across the peer mesh.
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))

		// The vendor builds its default tracer provider with NO sampler at all
		// (SDK default: AlwaysSample) — PROVIDE_SAMPLING_TRACES_RATE only gates
		// the vendor's own telemetry.Trace() helper, which litevirt never calls.
		// obs.Span and otelgrpc both read the OTel *global* provider, so a real
		// sample rate requires obs to build and inject its own. Ordering is
		// load-bearing: otlptracehttp.New reads OTEL_EXPORTER_OTLP_HEADERS at
		// construction time, so the exporter MUST be built here, before
		// SetupTelemetry (which is followed by the credential scrub below) —
		// building it after the scrub would silently produce an unauthenticated
		// exporter.
		if raw := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); raw != "" {
			if r, ok := validSampleRate(raw); ok {
				appliedRate = r
			}
		}
		if tp, err := buildTracerProvider(ctx, svc, cfg, appliedRate); err != nil {
			slog.Warn("telemetry: failed to build sampler-bearing tracer provider — tracing degraded to vendor default",
				"error", err)
		} else {
			setupOpts = append(setupOpts, telemetry.WithTracerProvider(tp))
		}

		// The obs-owned traces provider bypasses the vendor's own fail-open
		// resilience wrapper (that wrapper only ever applies to a
		// vendor-*built* exporter), so export failures DO reach otel.Handle for
		// this signal — unlike the vendor-managed logs signal, where the
		// comment on Health() still applies. Approximate: this is a
		// process-global handler, so it also catches any other stray SDK error;
		// in practice traces export failures dominate.
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			traceExportErrors.Add(1)
		}))

		// litevirt's deliberately-non-secret token= capability lines (e.g.
		// token=split_brain_gate_v1) must not be redacted in the exported log
		// stream — litevirt owns its own log hygiene; the real collector
		// credential is scrubbed separately (see credentialEnvVars below).
		// Default OFF; an operator can re-enable vendor PII redaction with
		// PROVIDE_LOG_SANITIZE=true. Must be set before SetupTelemetry, which
		// reads it at logger-construction time.
		setEnvDefault("PROVIDE_LOG_SANITIZE", "false")
	}

	_, err := telemetry.SetupTelemetry(setupOpts...)
	// SetupTelemetry has now read the OTLP auth headers into the built exporters,
	// so the header env vars are no longer needed. Scrub them from the process
	// environment: otherwise every child the daemon forks (QEMU, libvirt helpers,
	// hook scripts, gh) inherits the collector credential. Endpoint and other vars
	// are not secret and stay in place. (This Setup path is env-driven, so the
	// header must transit env today; scrubbing after it is consumed is the
	// mitigation. Vendor v0.5.1 added an in-memory config API — WithConfig — plus
	// otlptracehttp.WithHeaders, so a follow-up can pass config + credentials
	// entirely in-memory and retire this env round-trip and scrub. Until then the
	// pristine-env re-exec in cmd/litevirt/daemon.go depends on this scrub running
	// AFTER the snapshot is taken there, never before daemon start.)
	for _, k := range credentialEnvVars {
		_ = os.Unsetenv(k)
	}
	// Adopting the vendor logger costs every record a ctx-merge/sampling/
	// schema/PII-redaction pass — real cost that must not be paid when there's
	// no collector to send to, and its default PII redaction mangles
	// litevirt's deliberately-non-secret token= capability lines (finding 4).
	// So local logging (no endpoint) only ever gets a plain stdlib handler,
	// and ONLY when the operator explicitly asked for one via log_format/
	// log_level — otherwise slog.Default() is left completely untouched,
	// byte-for-byte parity with the pre-telemetry daemon (which never called
	// slog.SetDefault at all).
	var log *slog.Logger
	switch {
	case active:
		// Even on error the library leaves a usable fallback logger; adopt it as
		// the slog default so the whole tree logs through one pipeline. Guard
		// nil: a nil return would make slog.SetDefault panic, turning fail-open
		// into fail-closed at boot.
		log = adoptLogger(telemetry.GetLogger(ctx, svc))
		slog.SetDefault(log)
	case explicitLogFormat || explicitLogLevel:
		// Build from the resolved vendor env, not the cfg fields: the format/
		// level can arrive via LITEVIRT_LOG_*/PROVIDE_LOG_* (mapped above) with
		// the cfg fields empty, and reading cfg alone would silently drop an
		// operator's env-set level/format back to INFO/text. PROVIDE_LOG_FORMAT
		// is always set (console default above); PROVIDE_LOG_LEVEL only when an
		// operator/config asked, and empty → INFO, matching prior behavior.
		log = slog.New(newStdlibHandler(os.Stderr, os.Getenv("PROVIDE_LOG_FORMAT"), os.Getenv("PROVIDE_LOG_LEVEL")))
		slog.SetDefault(log)
	default:
		// SetupTelemetry (above) already called slog.SetDefault internally via
		// the vendor's own _configureLogger — undo it so the net effect is
		// truly untouched, byte-for-byte parity with the pre-telemetry daemon.
		slog.SetDefault(preSetupDefault)
		log = preSetupDefault
	}
	// One-line startup visibility so an operator can tell export state at a glance
	// (a silent fail-open otherwise looks identical to "not configured"). Prints
	// the actually-applied rate (what the injected sampler uses), not an env echo.
	if active {
		log.Info("telemetry: OTLP export enabled",
			"endpoint", SafeEndpointForLog(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
			"traces_sample_rate", strconv.FormatFloat(appliedRate, 'f', -1, 64))
	} else {
		log.Info("telemetry: OTLP export disabled — local structured logging only")
	}
	return telemetry.ShutdownTelemetry, err
}

// Logger returns a named structured logger bound to ctx (carrying any active
// trace/span IDs). Prefer this over slog.Default() where a stable component
// name aids filtering; existing slog.* calls also work after Setup.
func Logger(ctx context.Context, name string) *slog.Logger {
	return telemetry.GetLogger(ctx, name)
}

// Trace runs fn inside a span named name and returns fn's error. Use for a
// self-contained unit of work.
func Trace(ctx context.Context, name string, fn func(context.Context) error) error {
	return telemetry.Trace(ctx, name, fn)
}

// Span starts a manual span for a multi-step operation that can't be wrapped in
// a single closure (e.g. a migration/failover that spans several helper calls).
// The caller MUST call span.End() — defer it. The span is a no-op when tracing
// is not active, so this is always safe to call.
func Span(ctx context.Context, name string) (context.Context, telemetry.Span) {
	return telemetry.GetTracer(scopeName).Start(ctx, name)
}

// ServerOptions returns the gRPC server options that create a server span per
// RPC and extract inbound W3C trace context. It returns nil when tracing is not
// active, so with telemetry off there is no otel handler in the serve path at
// all. Spread into grpc.NewServer(existing, obs.ServerOptions()...).
func ServerOptions() []grpc.ServerOption {
	if !tracingActive.Load() {
		return nil
	}
	return []grpc.ServerOption{grpc.StatsHandler(
		otelgrpc.NewServerHandler(otelgrpc.WithFilter(traceFilter)))}
}

// ClientDialOptions returns the gRPC dial options that create a client span and
// inject trace context on outbound peer calls. It returns nil when tracing is
// not active, so a peer dial carries no otel handler unless export is on. The
// daemon wires this into every pki.PeerDial caller at boot via
// pki.SetTraceDialOptions(obs.ClientDialOptions) — callers don't spread it
// into the dial by hand.
func ClientDialOptions() []grpc.DialOption {
	if !tracingActive.Load() {
		return nil
	}
	return []grpc.DialOption{grpc.WithStatsHandler(
		otelgrpc.NewClientHandler(otelgrpc.WithFilter(traceFilter)))}
}

// credentialEnvVars carry the OTLP collector auth secret. They are scrubbed from
// the process environment after SetupTelemetry consumes them so daemon-forked
// child processes never inherit the credential. Covers the litevirt-native source
// var and every vendor-facing header var (generic + per-signal).
var credentialEnvVars = []string{
	"LITEVIRT_OTEL_HEADERS",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
	"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
}

// adoptLogger returns l, or the current slog default if l is nil. The vendor is
// documented to always return a usable logger, but a nil would make
// slog.SetDefault panic (fail-open → fail-closed); this keeps boot safe.
func adoptLogger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

// validEndpoint reports whether raw is a usable OTLP HTTP endpoint: an http(s)
// URL with a host and no URL userinfo. Credentials belong in
// LITEVIRT_OTEL_HEADERS / OTEL_EXPORTER_OTLP_HEADERS (scrubbed after Setup),
// not in the endpoint URL — userinfo would otherwise land in the boot log and
// any other place that echoes the endpoint. Mirrors daemon.normalizeTelemetry's
// config-file guard; obs cannot import internal/daemon (cycle) and is the
// runtime authority for env-sourced values too.
func validEndpoint(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false // reject user:pass@host — use header env for auth
	}
	return u.Host != ""
}

// SafeEndpointForLog returns raw with any URL userinfo redacted, so a
// misconfigured endpoint never prints credentials into journald even on the
// rejection path (warn before unset). Non-URL strings pass through unchanged.
// The masked form uses a literal "REDACTED" placeholder (not "***") so
// url.URL.String() does not percent-encode the mask. Exported so the daemon's
// config-file validation shares this single redaction implementation rather
// than keeping a second copy that could drift and leak.
func SafeEndpointForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("REDACTED")
	return u.String()
}

// validSampleRate parses raw as a trace sample rate in [0.0, 1.0]. Mirrors
// daemon.normalizeTelemetry's NaN/range guard, which only covers the
// config-file source — LITEVIRT_TRACES_SAMPLE_RATE bypasses it entirely,
// landing straight in PROVIDE_SAMPLING_TRACES_RATE.
func validSampleRate(raw string) (float64, bool) {
	r, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(r) || r < 0 || r > 1 {
		return 0, false
	}
	return r, true
}

// buildTracerProvider builds an obs-owned *sdktrace.TracerProvider with a
// real sampler, so obs.Span and otelgrpc (which read the OTel global
// provider) actually honor rate — unlike the vendor's own default provider,
// which is built with no sampler at all (see finding 3). otlptracehttp.New
// autoconfigures endpoint + headers from the OTEL_EXPORTER_OTLP_* env obs has
// already set, matching the vendor's own HTTP transport. Caller MUST call
// this before Setup's credential-env scrub — see the ordering comment at the
// call site.
func buildTracerProvider(ctx context.Context, svc string, cfg Config, rate float64) (*sdktrace.TracerProvider, error) {
	opts := []otlptracehttp.Option{}
	if secs := os.Getenv("PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS"); secs != "" {
		if v, err := strconv.ParseFloat(secs, 64); err == nil && v > 0 {
			opts = append(opts, otlptracehttp.WithTimeout(time.Duration(v*float64(time.Second))))
		}
	}
	if retries := os.Getenv("PROVIDE_EXPORTER_TRACES_RETRIES"); retries != "" {
		if n, err := strconv.Atoi(retries); err == nil {
			backoff := 5 * time.Second
			if secs := os.Getenv("PROVIDE_EXPORTER_TRACES_BACKOFF_SECONDS"); secs != "" {
				if v, err := strconv.ParseFloat(secs, 64); err == nil && v > 0 {
					backoff = time.Duration(v * float64(time.Second))
				}
			}
			opts = append(opts, otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
				Enabled:         n > 0,
				InitialInterval: backoff,
				MaxInterval:     4 * backoff,
				MaxElapsedTime:  time.Duration(n) * backoff,
			}))
		}
	}

	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	attrs := []attribute.KeyValue{attribute.String("service.name", svc)}
	if cfg.Version != "" {
		attrs = append(attrs, attribute.String("service.version", cfg.Version))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, attribute.String("deployment.environment", cfg.Environment))
	}
	if cfg.HostName != "" {
		attrs = append(attrs, attribute.String("host.name", cfg.HostName), attribute.String("service.instance.id", cfg.HostName))
	}
	res, resErr := sdkresource.New(ctx, sdkresource.WithFromEnv(), sdkresource.WithAttributes(attrs...))
	if resErr != nil || res == nil {
		res = sdkresource.NewSchemaless(attrs...)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(rate))),
	), nil
}

// newStdlibHandler builds a plain standard-library slog handler for local
// (no-OTLP-endpoint) structured/leveled logging — used only when an operator
// explicitly asks for it via log_format/log_level (finding 4). No vendor
// per-record cost, no PII redaction.
func newStdlibHandler(w io.Writer, format, level string) slog.Handler {
	opts := &slog.HandlerOptions{Level: parseStdlibLevel(level)}
	if strings.EqualFold(format, "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// parseStdlibLevel maps litevirt's TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
// scale onto slog's four built-in levels, extending below Debug / above Error
// for the two the stdlib doesn't have. Unknown/empty falls back to Info.
func parseStdlibLevel(level string) slog.Level {
	switch strings.ToUpper(level) {
	case "TRACE":
		return slog.LevelDebug - 4
	case "DEBUG":
		return slog.LevelDebug
	case "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	case "CRITICAL":
		return slog.LevelError + 4
	default:
		return slog.LevelInfo
	}
}

func setEnvDefault(key, val string) {
	if _, ok := os.LookupEnv(key); !ok {
		_ = os.Setenv(key, val)
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
