package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/otel"

	"github.com/litevirt/litevirt/internal/obs"
)

// Live /metrics scrape with tracing ON and a dead (503) collector.
//
// Spins an HTTP /metrics endpoint the same way the daemon does (promhttp +
// telemetryCollector), drives obs.Setup against a failing OTLP endpoint,
// emits spans until export failures are observed, then scrapes and asserts:
//
//   - litevirt_telemetry_circuit_state{signal="traces"} == -1 (unknown; not a fake healthy 0)
//   - litevirt_telemetry_export_errors_total has grown (traces error handler is live)
//   - litevirt_telemetry_dropped_total has no signal label (logs-only counter)
//
// Runnable on macOS — no libvirt, no cluster.
func TestLiveMetrics_TracingOnDeadCollector_Scrape(t *testing.T) {
	if testing.Short() {
		t.Skip("drives real batch export against a 503 collector")
	}
	cleanObsEnv(t)

	// Dead collector: accept HTTP, always 503.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(dead.Close)

	// Bound export so the test finishes promptly.
	t.Setenv("LITEVIRT_OTEL_TIMEOUT", "1")
	t.Setenv("LITEVIRT_OTEL_RETRIES", "0")
	t.Setenv("LITEVIRT_OTEL_SHUTDOWN_TIMEOUT", "1")

	// /metrics on a private registry (don't touch the process-global default
	// registry used by other metrics tests / daemon wiring).
	reg := prometheus.NewRegistry()
	if err := reg.Register(newTelemetryCollector()); err != nil {
		t.Fatalf("register telemetry collector: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsSrv := httptest.NewServer(mux)
	t.Cleanup(metricsSrv.Close)

	beforeBody := scrape(t, metricsSrv.URL+"/metrics")
	beforeErrs := metricValue(t, beforeBody, `litevirt_telemetry_export_errors_total`)
	// Traces circuit must already scrape as -1 even before Setup (Health default).
	if v := metricLabeled(t, beforeBody, `litevirt_telemetry_circuit_state`, `signal`, `traces`); v != -1 {
		t.Fatalf("pre-Setup circuit_state{signal=traces}=%v; want -1 (unknown)", v)
	}

	shutdown, err := obs.Setup(context.Background(), obs.Config{
		ServiceName:  "metrics-live",
		OTLPEndpoint: dead.URL,
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
		t.Fatal("TracingActive()=false; need tracing on for this scrape test")
	}

	// Drive spans until the obs-owned error handler has counted at least one
	// export failure (batch processor → 503). ForceFlush accelerates the batch.
	// Baseline is the process counter at Setup time (scrape uses the same source).
	errBaseline := obs.ExportErrors()
	deadline := time.Now().Add(20 * time.Second)
	var grew bool
	for time.Now().Before(deadline) {
		for i := 0; i < 20; i++ {
			_, span := obs.Span(context.Background(), "metrics.live")
			span.End()
		}
		if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = tp.ForceFlush(ctx)
			cancel()
		}
		if obs.ExportErrors() > errBaseline {
			grew = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !grew {
		t.Fatalf("ExportErrors did not grow against 503 collector (still %d; baseline %d)",
			obs.ExportErrors(), errBaseline)
	}

	body := scrape(t, metricsSrv.URL+"/metrics")
	t.Logf("scraped /metrics (%d bytes) after dead-collector export failures", len(body))

	// 1. traces circuit always unknown (-1), never a fake closed(0).
	if v := metricLabeled(t, body, `litevirt_telemetry_circuit_state`, `signal`, `traces`); v != -1 {
		t.Errorf("circuit_state{signal=traces}=%v; want -1 (unknown) with obs-owned traces provider", v)
	}
	// logs circuit is whatever the vendor reports (closed/half-open/open) — just present.
	if _, ok := findLabeled(body, `litevirt_telemetry_circuit_state`, `signal`, `logs`); !ok {
		t.Error("circuit_state{signal=logs} missing from scrape")
	}

	// 2. export_errors_total on the wire reflects the dead collector.
	afterErrs := metricValue(t, body, `litevirt_telemetry_export_errors_total`)
	if afterErrs <= beforeErrs {
		t.Errorf("export_errors_total=%v after failures; want > pre-Setup scrape %v", afterErrs, beforeErrs)
	}


	// 3. dropped_total is unlabeled (logs only — no signal="traces" series).
	if strings.Contains(body, `litevirt_telemetry_dropped_total{`) {
		t.Error("dropped_total must be unlabeled (logs only); found labeled series")
	}
	if !strings.Contains(body, "litevirt_telemetry_dropped_total") {
		t.Error("dropped_total family missing from scrape")
	}
}

func f64p(v float64) *float64 { return &v }

func scrape(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d body %s", url, resp.StatusCode, b)
	}
	return string(b)
}

// metricValue returns the value of an unlabeled counter/gauge family.
func metricValue(t *testing.T, body, name string) float64 {
	t.Helper()
	// Match "name <value>" lines; skip HELP/TYPE.
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + ` ([0-9.eE+-]+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("metric %s not found in scrape:\n%s", name, body)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parse %s: %v", m[1], err)
	}
	return v
}

func metricLabeled(t *testing.T, body, name, label, value string) float64 {
	t.Helper()
	v, ok := findLabeled(body, name, label, value)
	if !ok {
		t.Fatalf("metric %s{%s=%q} not found in scrape", name, label, value)
	}
	return v
}

func findLabeled(body, name, label, value string) (float64, bool) {
	// Prometheus text: name{label="value",...} 1
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\{[^}]*` +
		regexp.QuoteMeta(label) + `="` + regexp.QuoteMeta(value) + `"[^}]*\} ([0-9.eE+-]+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func cleanObsEnv(t *testing.T) {
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
		"PROVIDE_EXPORTER_LOGS_TIMEOUT_SECONDS", "PROVIDE_EXPORTER_TRACES_TIMEOUT_SECONDS",
		"PROVIDE_EXPORTER_LOGS_RETRIES", "PROVIDE_EXPORTER_TRACES_RETRIES",
		"PROVIDE_EXPORTER_LOGS_BACKOFF_SECONDS", "PROVIDE_EXPORTER_TRACES_BACKOFF_SECONDS",
		"PROVIDE_EXPORTER_LOGS_FAIL_OPEN", "PROVIDE_EXPORTER_TRACES_FAIL_OPEN",
		"PROVIDE_EXPORTER_LOGS_SHUTDOWN_TIMEOUT_SECONDS",
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
