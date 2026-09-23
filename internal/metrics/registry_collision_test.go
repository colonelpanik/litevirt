package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestPackageCollectorsShareOneRegistryWithoutCollision is the production-fidelity
// check that giving Server an injectable registry took away.
//
// In the daemon every collector in this package lands on ONE registry —
// prometheus.DefaultRegisterer — and Prometheus refuses two Descs with the same
// fully-qualified name, or the same name with a different help string or label
// set. That refusal is a panic on every path here: Start uses MustRegister, and
// daemon.go launches it as a bare `go d.metrics.Start()`, so nothing can recover
// it and the node dies at boot.
//
// Server.reg exists so a test can drive the real Start twice in one process, but
// it also isolates Start's collector from every collector it shares the default
// registry with in production — so a name collision introduced here became
// invisible to the suite while staying fatal in the daemon. Registering the whole
// set into one fresh registry restores the check without touching global state.
//
// Register, not Gather: registration is what calls Describe and does the name
// and consistency checks, and it is the step that panics. Collect needs a live
// corrosion client and a libvirt connection, and reaching for those would buy no
// extra coverage of this failure mode.
func TestPackageCollectorsShareOneRegistryWithoutCollision(t *testing.T) {
	reg := prometheus.NewRegistry()

	// The two Start registers back to back (server.go: MustRegister(collector)
	// then registerTelemetryMetrics). nil db/virt/ctStat is fine — Describe
	// reads neither.
	for _, c := range []prometheus.Collector{
		newCollector(nil, nil, nil, "host-a"),
		newTelemetryCollector(),
	} {
		if err := reg.Register(c); err != nil {
			t.Fatalf("%T cannot share a registry with the collectors already on it: %v\n\n"+
				"In the daemon this is prometheus.MustRegister on the default registry inside a "+
				"bare `go d.metrics.Start()`, so it is an unrecoverable panic at boot, not a "+
				"degraded metric.", c, err)
		}
	}

	// Every constructor in the package that accepts a Registerer. These reach
	// the default registry through their exported New* wrappers, so a Desc
	// added to the collector above can collide with any of them.
	for _, register := range []struct {
		name string
		fn   func(prometheus.Registerer)
	}{
		{"dualrun", func(r prometheus.Registerer) { newDualRunMetrics(r) }},
		{"failover", func(r prometheus.Registerer) { newFailoverMetrics(r) }},
		{"ha_health", func(r prometheus.Registerer) { newHAHealthMetrics(r) }},
		{"runtime_repair", func(r prometheus.Registerer) { newRuntimeRepairMetrics(r) }},
		{"runtime_gate", func(r prometheus.Registerer) { newRuntimeGateMetrics(r) }},
		{"state_write", func(r prometheus.Registerer) { newStateWriteMetrics(r) }},
		{"gc", func(r prometheus.Registerer) { newGCMetrics(r) }},
		{"sriov", func(r prometheus.Registerer) { newSRIOVMetrics(r) }},
		{"antientropy", func(r prometheus.Registerer) { newAntiEntropyMetrics(r) }},
	} {
		t.Run(register.name, func(t *testing.T) {
			// These use MustRegister internally, so a collision arrives as a
			// panic rather than an error. Turn it into a legible failure.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("the %s metrics cannot share a registry with the collectors already "+
						"on it: %v\n\nIn the daemon these all land on "+
						"prometheus.DefaultRegisterer, so this is a startup panic.", register.name, r)
				}
			}()
			register.fn(reg)
		})
	}

	// A collision is the failure this guards, so prove the guard can see one:
	// re-registering anything already present must be refused.
	if err := reg.Register(newTelemetryCollector()); err == nil {
		t.Fatal("the registry accepted a duplicate collector, so this test cannot detect a " +
			"name collision and proves nothing")
	} else if !strings.Contains(err.Error(), "duplicate") &&
		!strings.Contains(err.Error(), "already") {
		t.Errorf("duplicate registration failed for an unexpected reason: %v", err)
	}
}
