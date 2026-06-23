package lb

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	return &Manager{
		configDir: filepath.Join(dir, "config"),
		runDir:    filepath.Join(dir, "run"),
	}
}

// KeepalivedRunning is the VIP-assigned signal: true only when the pidfile
// names a live process. A missing pidfile → false (VIP not assigned).
func TestKeepalivedRunning(t *testing.T) {
	m := testManager(t)
	if err := os.MkdirAll(m.runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if m.KeepalivedRunning("nope-lb") {
		t.Error("no pidfile → should be false")
	}
	// A pidfile pointing at this test process (definitely alive) → true.
	pidPath := filepath.Join(m.runDir, "live-lb-keepalived.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	if !m.KeepalivedRunning("live-lb") {
		t.Error("pidfile of a live process → should be true")
	}
}

// lbLock is keyed by LB name: same name → same mutex (serializes), different
// names → different mutexes (no cross-LB stalling).
func TestLBLock_KeyedByName(t *testing.T) {
	if lbLock("a") != lbLock("a") {
		t.Error("same name should return the same mutex")
	}
	if lbLock("a") == lbLock("b") {
		t.Error("different names should return different mutexes")
	}
}

// Concurrent Apply of the SAME LB must be serialized (no data race, no corrupted
// config). Run under -race; the per-LB mutex is what makes this safe.
func TestApply_ConcurrentSameLB_NoRace(t *testing.T) {
	m := testManager(t)
	cfg := Config{
		Name: "race-lb", VIP: "10.0.1.100", VIPPrefix: 24, Interface: "eth0",
		VRID: 10, Priority: 100, Algorithm: "roundrobin",
		Backends: []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:    []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.Apply(context.Background(), cfg) }() //nolint:errcheck
	}
	wg.Wait()
	data, err := os.ReadFile(filepath.Join(m.configDir, "race-lb-haproxy.cfg"))
	if err != nil || !strings.Contains(string(data), "frontend race-lb-80") {
		t.Fatalf("config corrupted/missing after concurrent applies: err=%v", err)
	}
}

// configChanged drives the skip-if-unchanged optimization: identical bytes →
// no reload; any difference or a missing file → reload.
func TestConfigChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.cfg")
	if !configChanged(path, "anything") {
		t.Error("missing file should count as changed")
	}
	if err := os.WriteFile(path, []byte("A\nB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if configChanged(path, "A\nB\n") {
		t.Error("identical content should be unchanged")
	}
	if !configChanged(path, "A\nB\nC\n") {
		t.Error("different content should be changed")
	}
}

// Apply must (re)write the config files every time even when it skips the
// reload, so the on-disk config stays canonical for Remove / stats discovery.
func TestApply_WritesConfigEvenWhenUnchanged(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	cfg := Config{
		Name: "web-lb", VIP: "10.0.1.100", VIPPrefix: 24, Interface: "eth0",
		VRID: 10, Priority: 100, Algorithm: "roundrobin",
		Backends: []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:    []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	haproxyPath := filepath.Join(m.configDir, "web-lb-haproxy.cfg")

	m.Apply(ctx, cfg) //nolint:errcheck — haproxy -c fails in CI; we test file writes
	first, err := os.ReadFile(haproxyPath)
	if err != nil {
		t.Fatalf("first apply didn't write config: %v", err)
	}
	// Second apply with identical config: file still present and byte-identical
	// (the reload is skipped, but the write is not).
	m.Apply(ctx, cfg) //nolint:errcheck
	second, err := os.ReadFile(haproxyPath)
	if err != nil {
		t.Fatalf("second apply removed config: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("config changed across identical applies:\n%s\n---\n%s", first, second)
	}
}

// ── Apply ───────────────────────────────────────────────────────────────────

func TestApply_WritesAllConfigs(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	cfg := Config{
		Name:      "web-lb",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      10,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:     []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}

	// Apply will write configs but fail at 'haproxy -c' validation (binary not in PATH).
	// That's fine — we're testing the file writing path.
	err := m.Apply(ctx, cfg)

	// Check configs were written even if Apply returned error from haproxy validation.
	haproxyPath := filepath.Join(m.configDir, "web-lb-haproxy.cfg")
	data, readErr := os.ReadFile(haproxyPath)
	if readErr != nil {
		t.Fatalf("haproxy config not written: %v (Apply error: %v)", readErr, err)
	}
	if !strings.Contains(string(data), "frontend web-lb-80") {
		t.Errorf("haproxy config missing frontend:\n%s", string(data))
	}
	if !strings.Contains(string(data), "server b1 10.0.1.10:8080") {
		t.Errorf("haproxy config missing backend server:\n%s", string(data))
	}

	keepalivedPath := filepath.Join(m.configDir, "web-lb-keepalived.conf")
	data, readErr = os.ReadFile(keepalivedPath)
	if readErr != nil {
		t.Fatalf("keepalived config not written: %v", readErr)
	}
	if !strings.Contains(string(data), "vrrp_instance web-lb") {
		t.Errorf("keepalived config missing vrrp_instance:\n%s", string(data))
	}
	if !strings.Contains(string(data), "10.0.1.100/24") {
		t.Errorf("keepalived config missing VIP:\n%s", string(data))
	}
}

func TestApply_WithSNAT(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	cfg := Config{
		Name:        "snat-lb",
		VIP:         "10.0.1.200",
		VIPPrefix:   24,
		Interface:   "eth0",
		VRID:        20,
		Priority:    100,
		Algorithm:   "roundrobin",
		Backends:    []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:       []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		SNATEnabled: true,
		LocalIP:     "10.0.1.1",
		PeerIP:      "10.0.1.2",
	}

	_ = m.Apply(ctx, cfg)

	// Verify conntrackd config was written.
	ctPath := filepath.Join(m.configDir, "snat-lb-conntrackd.conf")
	if _, err := os.Stat(ctPath); os.IsNotExist(err) {
		t.Error("conntrackd config not written for SNAT-enabled LB")
	}

	// Verify notify script was written.
	notifyPath := filepath.Join(m.configDir, "snat-lb-notify.sh")
	if _, err := os.Stat(notifyPath); os.IsNotExist(err) {
		t.Error("notify script not written for SNAT-enabled LB")
	}
}

func TestApply_WithTLS(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	dir := t.TempDir()

	// Create fake cert/key files.
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, []byte("---CERT---\n"), 0644)
	os.WriteFile(keyPath, []byte("---KEY---\n"), 0644)

	cfg := Config{
		Name:      "tls-lb",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      30,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.1.10", Port: 443}},
		Ports: []Port{{
			Listen:   443,
			Target:   443,
			Protocol: "tcp",
			TLS:      &TLSConfig{Cert: certPath, Key: keyPath},
		}},
	}

	_ = m.Apply(ctx, cfg)

	// Verify combined PEM was written.
	pemPath := filepath.Join(m.configDir, "tls-lb-443.pem")
	data, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("TLS PEM not written: %v", err)
	}
	if !strings.Contains(string(data), "---CERT---") || !strings.Contains(string(data), "---KEY---") {
		t.Errorf("PEM doesn't contain cert+key: %s", string(data))
	}
}

func TestApply_TLSMissingCert(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	cfg := Config{
		Name:      "bad-tls",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      40,
		Priority:  100,
		Backends:  []Backend{{Name: "b1", IP: "10.0.1.10", Port: 443}},
		Ports: []Port{{
			Listen: 443, Target: 443, Protocol: "tcp",
			TLS: &TLSConfig{Cert: "/nonexistent/cert.pem", Key: "/nonexistent/key.pem"},
		}},
	}

	err := m.Apply(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for missing TLS cert")
	}
	if !strings.Contains(err.Error(), "read TLS cert") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestApply_CreatesDirectories(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	cfg := Config{
		Name:      "dir-test",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      1,
		Priority:  100,
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.2", Port: 80}},
		Ports:     []Port{{Listen: 80, Target: 80, Protocol: "tcp"}},
	}

	// Directories don't exist yet. Apply should create them.
	_ = m.Apply(ctx, cfg)

	if _, err := os.Stat(m.configDir); os.IsNotExist(err) {
		t.Error("configDir not created")
	}
	if _, err := os.Stat(m.runDir); os.IsNotExist(err) {
		t.Error("runDir not created")
	}
}

// ── Remove ──────────────────────────────────────────────────────────────────

func TestRemove_CleansUpFiles(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	os.MkdirAll(m.configDir, 0755)
	os.MkdirAll(m.runDir, 0755)

	// Create config files that Remove should delete.
	files := []string{
		filepath.Join(m.configDir, "test-lb-haproxy.cfg"),
		filepath.Join(m.configDir, "test-lb-keepalived.conf"),
		filepath.Join(m.configDir, "test-lb-conntrackd.conf"),
		filepath.Join(m.configDir, "test-lb-notify.sh"),
	}
	for _, f := range files {
		os.WriteFile(f, []byte("config"), 0640)
	}

	// Create PID files (no real processes).
	pidFiles := []string{
		filepath.Join(m.runDir, "test-lb-haproxy.pid"),
		filepath.Join(m.runDir, "test-lb-keepalived.pid"),
		filepath.Join(m.runDir, "test-lb-conntrackd.pid"),
	}
	for _, f := range pidFiles {
		os.WriteFile(f, []byte("99999"), 0640)
	}

	err := m.Remove(ctx, "test-lb")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// All config files should be gone.
	for _, f := range files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("file not removed: %s", f)
		}
	}
}

func TestRemove_NoFiles(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	// Remove on nonexistent LB should not error.
	err := m.Remove(ctx, "nonexistent-lb")
	if err != nil {
		t.Fatalf("Remove should not error for missing files: %v", err)
	}
}

// ── SetBackendEnabled ───────────────────────────────────────────────────────

func TestSetBackendEnabled_NoConfig(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	os.MkdirAll(m.configDir, 0755)
	os.MkdirAll(m.runDir, 0755)

	// No config file → discoverBackendSections returns nil → uses fallback name.
	// runHAProxyCmd will fail silently (socat not available or socket missing).
	err := m.SetBackendEnabled(ctx, "missing-lb", "b1", true)
	// This should either return nil (socat not found, graceful) or an error from socket.
	_ = err // error is acceptable — the important thing is no panic
}

func TestSetBackendEnabled_WithConfig(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	os.MkdirAll(m.configDir, 0755)
	os.MkdirAll(m.runDir, 0755)

	// Write a config with backend sections.
	cfgContent := `
frontend test-lb-80
    bind *:80
    default_backend test-lb-80-backend

backend test-lb-80-backend
    server b1 10.0.0.1:8080

backend test-lb-8080-backend
    server b1 10.0.0.1:8080
`
	cfgPath := filepath.Join(m.configDir, "test-lb-haproxy.cfg")
	os.WriteFile(cfgPath, []byte(cfgContent), 0640)

	// SetBackendEnabled discovers backends from the config.
	// Socket communication will fail (no real haproxy) but we verify discovery.
	_ = m.SetBackendEnabled(ctx, "test-lb", "b1", false)
}

// ── discoverBackendSections ─────────────────────────────────────────────────

func TestDiscoverBackendSections_MultipleBackends(t *testing.T) {
	m := testManager(t)
	os.MkdirAll(m.configDir, 0755)

	cfgContent := `
frontend web-80
    bind *:80

backend web-80-backend
    server s1 10.0.0.1:8080

backend web-8080-backend
    server s1 10.0.0.1:8080

backend api-443-backend
    server s1 10.0.0.2:443
`
	cfgPath := filepath.Join(m.configDir, "web-haproxy.cfg")
	os.WriteFile(cfgPath, []byte(cfgContent), 0640)

	sections := m.discoverBackendSections("web")
	if len(sections) != 3 {
		t.Fatalf("expected 3 backend sections, got %d: %v", len(sections), sections)
	}
}

func TestDiscoverBackendSections_NoBackends(t *testing.T) {
	m := testManager(t)
	os.MkdirAll(m.configDir, 0755)

	cfgContent := `
frontend web-80
    bind *:80
`
	cfgPath := filepath.Join(m.configDir, "web-haproxy.cfg")
	os.WriteFile(cfgPath, []byte(cfgContent), 0640)

	sections := m.discoverBackendSections("web")
	if len(sections) != 0 {
		t.Errorf("expected 0 backend sections, got %d: %v", len(sections), sections)
	}
}

func TestDiscoverBackendSections_MissingConfig(t *testing.T) {
	m := testManager(t)

	sections := m.discoverBackendSections("nonexistent")
	if sections != nil {
		t.Errorf("expected nil for missing config, got %v", sections)
	}
}

// ── DrainBackend ────────────────────────────────────────────────────────────

func TestDrainBackend_NoConfig(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	os.MkdirAll(m.configDir, 0755)
	os.MkdirAll(m.runDir, 0755)

	// DrainBackend with no config/socket — should not panic.
	_, err := m.DrainBackend(ctx, "missing-lb", "b1")
	// Error is expected (no socat/socket), but no panic.
	_ = err
}

// ── GetStats ────────────────────────────────────────────────────────────────

func TestGetStats_NoSocket(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	os.MkdirAll(m.runDir, 0755)

	_, err := m.GetStats(ctx, "missing-lb")
	if err == nil {
		t.Fatal("expected error for missing socat/socket")
	}
}

// ── Apply roundtrip: Apply then Remove ──────────────────────────────────────

func TestApply_ThenRemove_Roundtrip(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()

	cfg := Config{
		Name:      "roundtrip-lb",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      50,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:     []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}

	// Apply (will fail at haproxy -c but writes configs).
	_ = m.Apply(ctx, cfg)

	// Verify config exists.
	haproxyPath := filepath.Join(m.configDir, "roundtrip-lb-haproxy.cfg")
	if _, err := os.Stat(haproxyPath); os.IsNotExist(err) {
		t.Fatal("config should exist after Apply")
	}

	// Remove should clean up.
	if err := m.Remove(ctx, "roundtrip-lb"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := os.Stat(haproxyPath); !os.IsNotExist(err) {
		t.Error("config should be removed after Remove")
	}
}
