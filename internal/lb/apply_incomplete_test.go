package lb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func incompleteTestCfg() Config {
	return Config{
		Name: "web-lb", VIP: "10.0.1.100", VIPPrefix: 24, Interface: "eth0",
		VRID: 10, Priority: 100, Algorithm: "roundrobin",
		Backends: []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:    []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
}

// TestApply_LeavesAnIncompleteMarkerWhenItFails is the #190 regression.
//
// Apply writes both configs and only then runs `haproxy -c`. A failure there —
// or in any later step — returns with the new config already on disk while the
// OLD keepalived process is still running the OLD VIP.
//
// The retry is then a no-op by construction: configChanged compares the render
// against the file it just wrote, so it is false, and pidAlive is true because
// the stale keepalived never died. The reload is skipped entirely. HAProxy
// binds the new VIP regardless (ip_nonlocal_bind=1 is set a few lines above),
// so the LB reports healthy while the VIP is advertised from nowhere.
//
// The file cannot be the record of what was APPLIED, because it is written
// before the apply can fail — it is only the record of what was last RENDERED.
// A marker written before the first durable write and cleared only on a
// complete pass is the missing piece.
//
// `haproxy` is not on PATH in CI, so Apply genuinely fails at validation here.
func TestApply_LeavesAnIncompleteMarkerWhenItFails(t *testing.T) {
	m := testManager(t)
	cfg := incompleteTestCfg()

	if err := m.Apply(context.Background(), cfg); err == nil {
		t.Skip("haproxy validation unexpectedly succeeded; this test needs it to fail")
	}
	if _, err := os.Stat(m.applyMarkerPath(cfg.Name)); err != nil {
		t.Fatalf("no incomplete-apply marker after a failed Apply: %v — the next "+
			"Apply will see an unchanged config and a live keepalived, and skip "+
			"the reload forever", err)
	}
	// The config files are still written: Remove and stats discovery read them,
	// and TestApply_WritesAllConfigs pins that.
	if _, err := os.Stat(filepath.Join(m.configDir, "web-lb-haproxy.cfg")); err != nil {
		t.Errorf("haproxy config missing: %v", err)
	}
}

// With the marker present, an IDENTICAL config must still be treated as
// changed — that is the whole point. Without it the retry does nothing.
func TestReloadDecision_IncompleteApplyForcesReload(t *testing.T) {
	m := testManager(t)
	cfg := incompleteTestCfg()
	_ = m.Apply(context.Background(), cfg) // fails at validation, leaves the marker

	haproxyCfg, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy: %v", err)
	}
	keepalivedCfg, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}

	hChanged, kChanged := m.reloadDecision(cfg.Name, haproxyCfg, keepalivedCfg)
	if !hChanged || !kChanged {
		t.Fatalf("after an incomplete apply, identical configs read as unchanged "+
			"(haproxy=%v keepalived=%v); the retry would skip the reload and leave "+
			"the old VIP advertised", hChanged, kChanged)
	}

	// Once the marker is cleared, an identical config is unchanged again — the
	// burst-of-identical-applies churn guard must survive this fix.
	if err := os.Remove(m.applyMarkerPath(cfg.Name)); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	hChanged, kChanged = m.reloadDecision(cfg.Name, haproxyCfg, keepalivedCfg)
	if hChanged || kChanged {
		t.Errorf("identical configs after a COMPLETE apply must not reload "+
			"(haproxy=%v keepalived=%v); that churn is what spawned reload-race "+
			"orphan processes", hChanged, kChanged)
	}
}

// A genuinely different config is changed whether or not a marker exists.
func TestReloadDecision_DifferentConfigAlwaysReloads(t *testing.T) {
	m := testManager(t)
	cfg := incompleteTestCfg()
	_ = m.Apply(context.Background(), cfg)
	_ = os.Remove(m.applyMarkerPath(cfg.Name)) // pretend it completed

	changed := cfg
	changed.Backends = append(changed.Backends, Backend{Name: "b2", IP: "10.0.1.11", Port: 8080})
	haproxyCfg, _ := RenderHAProxy(changed)
	keepalivedCfg, _ := RenderKeepalived(changed)

	if h, _ := m.reloadDecision(cfg.Name, haproxyCfg, keepalivedCfg); !h {
		t.Error("an added backend must reload haproxy")
	}
	_ = keepalivedCfg
}

// Removing an LB takes its marker with it; a leftover would force a redundant
// reload if the name were reused.
func TestRemove_ClearsTheApplyMarker(t *testing.T) {
	m := testManager(t)
	cfg := incompleteTestCfg()
	_ = m.Apply(context.Background(), cfg)
	if _, err := os.Stat(m.applyMarkerPath(cfg.Name)); err != nil {
		t.Skipf("no marker to clear (Apply succeeded?): %v", err)
	}
	_ = m.Remove(context.Background(), cfg.Name)
	if _, err := os.Stat(m.applyMarkerPath(cfg.Name)); !os.IsNotExist(err) {
		t.Errorf("apply marker survived Remove: %v", err)
	}
}
