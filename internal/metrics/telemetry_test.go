package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// The telemetry collector emits every health metric (registered via a fresh
// registry so the test doesn't touch the default one), including per-signal
// circuit-breaker gauges.
func TestTelemetryCollector_EmitsAllMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(newTelemetryCollector()); err != nil {
		t.Fatalf("register: %v", err)
	}

	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string]*dto.MetricFamily{}
	for _, f := range fams {
		got[f.GetName()] = f
	}

	for _, name := range []string{
		"litevirt_telemetry_export_errors_total",
		"litevirt_telemetry_dropped_total",
		"litevirt_telemetry_export_retries_total",
		"litevirt_telemetry_circuit_state",
	} {
		if got[name] == nil {
			t.Errorf("metric %q not emitted", name)
		}
	}

	// circuit_state must carry one series per signal (logs, traces).
	cs := got["litevirt_telemetry_circuit_state"]
	if cs == nil {
		t.Fatal("circuit_state family missing")
	}
	signals := map[string]bool{}
	for _, m := range cs.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == "signal" {
				signals[l.GetValue()] = true
			}
		}
	}
	if !signals["logs"] || !signals["traces"] {
		t.Errorf("circuit_state signals = %v; want both logs and traces", signals)
	}
}

func TestCircuitStateValue(t *testing.T) {
	cases := map[string]float64{"closed": 0, "half-open": 1, "open": 2, "": -1, "bogus": -1}
	for in, want := range cases {
		if got := circuitStateValue(in); got != want {
			t.Errorf("circuitStateValue(%q) = %v; want %v", in, got, want)
		}
	}
}

// Guards the encoding / signal semantics described in metric Help so docs and
// code can't drift apart (finding 3 fallout: traces circuit is unknown; dropped
// is logs-only).
func TestTelemetryCollector_HelpDocumentsEncoding(t *testing.T) {
	c := newTelemetryCollector()
	if !strings.Contains(c.circuitState.String(), "0=closed") {
		t.Error("circuit_state Help must document the numeric encoding")
	}
	if !strings.Contains(c.circuitState.String(), "-1=unknown") {
		t.Error("circuit_state Help must document unknown=-1")
	}
	if !strings.Contains(c.circuitState.String(), "traces") {
		t.Error("circuit_state Help must note that signal=traces is unobservable")
	}
	if !strings.Contains(c.dropped.String(), "logs only") {
		t.Error("dropped Help must state logs-only (trace drops unobservable)")
	}
	if strings.Contains(c.dropped.String(), "logs+traces") {
		t.Error("dropped Help must not claim logs+traces — only logs are counted")
	}
}

// Traces circuit must scrape as -1 (unknown), never a fake healthy 0=closed.
// Dropped has no signal label and is logs-sourced only.
func TestTelemetryCollector_TracesCircuitUnknown_AndDroppedUnlabeled(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(newTelemetryCollector()); err != nil {
		t.Fatalf("register: %v", err)
	}
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		switch f.GetName() {
		case "litevirt_telemetry_circuit_state":
			for _, m := range f.GetMetric() {
				var signal string
				for _, l := range m.GetLabel() {
					if l.GetName() == "signal" {
						signal = l.GetValue()
					}
				}
				if signal == "traces" && m.GetGauge().GetValue() != -1 {
					t.Errorf("circuit_state{signal=traces}=%v; want -1 (unknown)", m.GetGauge().GetValue())
				}
			}
		case "litevirt_telemetry_dropped_total":
			if len(f.GetMetric()) != 1 {
				t.Errorf("dropped_total series count = %d; want 1 unlabeled counter (logs only)", len(f.GetMetric()))
			}
			for _, m := range f.GetMetric() {
				if len(m.GetLabel()) != 0 {
					t.Errorf("dropped_total must have no labels; got %v", m.GetLabel())
				}
			}
		}
	}
}
