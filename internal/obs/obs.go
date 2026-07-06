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
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	telemetry "github.com/provide-io/provide-telemetry/go"
	_ "github.com/provide-io/provide-telemetry/go/otel" // activates OTLP env wiring for SetupTelemetry

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
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

// tracingActive gates the gRPC otel instrumentation. It flips true only when an
// OTLP endpoint is configured, so with tracing off there is ZERO otel in the
// RPC dial/serve path — the stats handlers are never attached. Logging still
// routes through provide-telemetry regardless (that path degrades gracefully to
// local structured output and needs no collector).
var tracingActive atomic.Bool

// TracingActive reports whether OTLP tracing/metrics export is on.
func TracingActive() bool { return tracingActive.Load() }

// exportErrors counts OTLP export failures (spans/logs dropped, fail-open). A
// nonzero, growing value means the collector is unreachable or rejecting data.
// Surfaced to Prometheus by internal/metrics.
var exportErrors atomic.Int64

// ExportErrors returns the cumulative OTLP export-failure count.
func ExportErrors() int64 { return exportErrors.Load() }

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
	OTLPEndpoint string  // OTLP gRPC endpoint, e.g. "otel-collector:4317"; empty = no export
	SampleRate   float64 // trace sample rate 0.0–1.0; 0 falls back to the library default
	LogLevel     string  // TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL (default INFO)
	LogFormat    string  // json|console|pretty (default json)
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
	// Highest precedence: litevirt-native LITEVIRT_* operator overrides, mapped
	// onto the vendor env contract. Applied first so the config-derived defaults
	// below (setEnvDefault) will not clobber them.
	for src, dst := range litevirtEnvMap {
		if v, ok := os.LookupEnv(src); ok {
			_ = os.Setenv(dst, v)
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
	if cfg.LogLevel != "" {
		setEnvDefault("PROVIDE_LOG_LEVEL", cfg.LogLevel)
	}
	setEnvDefault("PROVIDE_LOG_FORMAT", orDefault(cfg.LogFormat, "json"))
	if cfg.SampleRate > 0 {
		setEnvDefault("PROVIDE_SAMPLING_TRACES_RATE", strconv.FormatFloat(cfg.SampleRate, 'f', -1, 64))
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
		// env. obs exports LOGS + TRACES only — metrics remain owned by
		// internal/metrics (Prometheus pull, /metrics). provide-telemetry has no
		// Prometheus exporter, so keeping metrics there avoids a split, duplicate
		// metrics system. PROVIDE_METRICS_ENABLED is deliberately left unset.
		setEnvDefault("OTEL_EXPORTER_OTLP_ENDPOINT", cfg.OTLPEndpoint)
		setEnvDefault("PROVIDE_LOG_OTLP_ENABLED", "true")
	}

	// Tracing is active only when a non-empty endpoint is resolvable (config or
	// operator env). This gates the gRPC otel handlers — no endpoint, no otel in
	// the RPC path. Stored unconditionally so Setup is idempotent (a later call
	// with no endpoint correctly turns instrumentation back off).
	active := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
	tracingActive.Store(active)
	if active {
		// W3C tracecontext + baggage so otelgrpc injects on dial and extracts on
		// serve — this is what carries a trace across the peer mesh.
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))
		// Count + surface OTLP export failures instead of dropping them silently.
		// Throttled logging (first, then every 100th) so a down collector can't
		// flood the log while still making "no traces" diagnosable.
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			if n := exportErrors.Add(1); n == 1 || n%100 == 0 {
				slog.Warn("telemetry: OTLP export error (data dropped, fail-open)",
					"error", err, "export_errors_total", n)
			}
		}))
	}

	_, err := telemetry.SetupTelemetry()
	// Even on error the library leaves a usable fallback logger; adopt it as the
	// slog default so the whole tree logs through one pipeline.
	log := telemetry.GetLogger(ctx, svc)
	slog.SetDefault(log)
	// One-line startup visibility so an operator can tell export state at a glance
	// (a silent fail-open otherwise looks identical to "not configured").
	if active {
		log.Info("telemetry: OTLP export enabled",
			"endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
			"traces_sample_rate", orDefault(os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"), "1.0"))
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
// not active, so a peer dial carries no otel handler unless export is on.
// Spread into the dial: pki.PeerDial(dir, target, obs.ClientDialOptions()...).
func ClientDialOptions() []grpc.DialOption {
	if !tracingActive.Load() {
		return nil
	}
	return []grpc.DialOption{grpc.WithStatsHandler(
		otelgrpc.NewClientHandler(otelgrpc.WithFilter(traceFilter)))}
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
