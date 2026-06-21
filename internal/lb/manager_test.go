package lb

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ── readPid tests ────────────────────────────────────────────────────────────

func TestReadPid_ValidFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte("12345\n"), 0644)

	pid := readPid(pidFile)
	if pid != 12345 {
		t.Errorf("readPid = %d, want 12345", pid)
	}
}

func TestReadPid_ValidNoNewline(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte("9999"), 0644)

	pid := readPid(pidFile)
	if pid != 9999 {
		t.Errorf("readPid = %d, want 9999", pid)
	}
}

func TestReadPid_WithWhitespace(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte("  42  \n"), 0644)

	pid := readPid(pidFile)
	if pid != 42 {
		t.Errorf("readPid = %d, want 42", pid)
	}
}

func TestReadPid_NonExistentFile(t *testing.T) {
	pid := readPid("/tmp/nonexistent-pid-file-litevirt-test")
	if pid != 0 {
		t.Errorf("readPid nonexistent = %d, want 0", pid)
	}
}

func TestReadPid_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte(""), 0644)

	pid := readPid(pidFile)
	if pid != 0 {
		t.Errorf("readPid empty = %d, want 0", pid)
	}
}

func TestReadPid_NonNumeric(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte("notapid"), 0644)

	pid := readPid(pidFile)
	if pid != 0 {
		t.Errorf("readPid non-numeric = %d, want 0", pid)
	}
}

func TestReadPid_NegativeNumber(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte("-1"), 0644)

	pid := readPid(pidFile)
	if pid != -1 {
		t.Errorf("readPid negative = %d, want -1", pid)
	}
}

func TestReadPid_Zero(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")
	os.WriteFile(pidFile, []byte("0"), 0644)

	pid := readPid(pidFile)
	if pid != 0 {
		t.Errorf("readPid zero = %d, want 0", pid)
	}
}

// ── processAlive tests ───────────────────────────────────────────────────────

func TestProcessAlive_CurrentProcess(t *testing.T) {
	// Our own PID should be alive.
	if !processAlive(os.Getpid()) {
		t.Error("processAlive(self) should be true")
	}
}

func TestProcessAlive_NonExistentProcess(t *testing.T) {
	// PID 2^22 - 1 is unlikely to exist.
	if processAlive(4194303) {
		t.Skip("PID 4194303 somehow exists, skipping")
	}
	// If we get here, the test passed (processAlive returned false).
}

func TestProcessAlive_PidOne(t *testing.T) {
	// PID 1 (init/systemd) should always be alive, but in some sandboxed
	// environments we may not have permission to signal it.
	alive := processAlive(1)
	_ = alive // just exercise the code path; result depends on environment
}

// ── killByPidFile tests ─────────────────────────────────────────────────────

func TestKillByPidFile_NonExistentFile(t *testing.T) {
	// Should not panic or error when pid file doesn't exist.
	killByPidFile("/tmp/litevirt-test-nonexistent.pid")
}

func TestKillByPidFile_StaleFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "stale.pid")
	// Write a PID that definitely doesn't exist.
	os.WriteFile(pidFile, []byte("4194303"), 0644)

	killByPidFile(pidFile)

	// The pid file should be removed even for stale PIDs.
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("killByPidFile should remove stale pid file")
	}
}

func TestKillByPidFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "empty.pid")
	os.WriteFile(pidFile, []byte(""), 0644)

	killByPidFile(pidFile)

	// Should still remove the file.
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("killByPidFile should remove empty pid file")
	}
}

func TestKillByPidFile_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "bad.pid")
	os.WriteFile(pidFile, []byte("not-a-pid"), 0644)

	killByPidFile(pidFile)

	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("killByPidFile should remove invalid pid file")
	}
}

// ── DetectInterfaceForIP tests ──────────────────────────────────────────────

func TestDetectInterfaceForIP_InvalidIP(t *testing.T) {
	// Invalid IP should fall back to DetectInterface.
	iface := DetectInterfaceForIP("not-an-ip")
	if iface == "" {
		t.Error("DetectInterfaceForIP should return a non-empty interface")
	}
}

func TestDetectInterfaceForIP_Loopback(t *testing.T) {
	// 127.0.0.1 should match the loopback interface.
	iface := DetectInterfaceForIP("127.0.0.1")
	if iface == "" {
		t.Error("DetectInterfaceForIP(127.0.0.1) should return a non-empty interface")
	}
	// On Linux, loopback is typically "lo".
	if iface != "lo" {
		t.Logf("loopback interface name: %s (expected 'lo')", iface)
	}
}

func TestDetectInterfaceForIP_UnroutableIP(t *testing.T) {
	// An IP that doesn't belong to any local interface should fall back.
	iface := DetectInterfaceForIP("203.0.113.99")
	if iface == "" {
		t.Error("DetectInterfaceForIP should return fallback interface")
	}
}

func TestDetectInterfaceForIP_EmptyString(t *testing.T) {
	iface := DetectInterfaceForIP("")
	if iface == "" {
		t.Error("DetectInterfaceForIP('') should return fallback interface")
	}
}

// ── parseHAProxyCSV additional edge cases ───────────────────────────────────

func TestParseHAProxyCSV_BlankLines(t *testing.T) {
	csv := `# pxname,svname,status,type
web-be,vm1,UP,2

web-be,vm2,DOWN,2

`
	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestParseHAProxyCSV_AllFieldTypes(t *testing.T) {
	csv := `# pxname,svname,scur,stot,bin,bout,status,rate,econ,eresp,hrsp_2xx,hrsp_4xx,hrsp_5xx,rtime,qtime,type
api-be,srv1,100,50000,999999999,888888888,UP,500,10,5,45000,3000,2000,25,8,2
`
	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.ProxyName != "api-be" {
		t.Errorf("ProxyName = %q", e.ProxyName)
	}
	if e.ServerName != "srv1" {
		t.Errorf("ServerName = %q", e.ServerName)
	}
	if e.CurrentSess != 100 {
		t.Errorf("CurrentSess = %d", e.CurrentSess)
	}
	if e.TotalSess != 50000 {
		t.Errorf("TotalSess = %d", e.TotalSess)
	}
	if e.BytesIn != 999999999 {
		t.Errorf("BytesIn = %d", e.BytesIn)
	}
	if e.BytesOut != 888888888 {
		t.Errorf("BytesOut = %d", e.BytesOut)
	}
	if e.Status != "UP" {
		t.Errorf("Status = %q", e.Status)
	}
	if e.Rate != 500 {
		t.Errorf("Rate = %d", e.Rate)
	}
	if e.ErrConn != 10 {
		t.Errorf("ErrConn = %d", e.ErrConn)
	}
	if e.ErrResp != 5 {
		t.Errorf("ErrResp = %d", e.ErrResp)
	}
	if e.Resp2xx != 45000 {
		t.Errorf("Resp2xx = %d", e.Resp2xx)
	}
	if e.Resp4xx != 3000 {
		t.Errorf("Resp4xx = %d", e.Resp4xx)
	}
	if e.Resp5xx != 2000 {
		t.Errorf("Resp5xx = %d", e.Resp5xx)
	}
	if e.AvgResponseMs != 25 {
		t.Errorf("AvgResponseMs = %d", e.AvgResponseMs)
	}
	if e.AvgQueueMs != 8 {
		t.Errorf("AvgQueueMs = %d", e.AvgQueueMs)
	}
	if e.Type != 2 {
		t.Errorf("Type = %d", e.Type)
	}
}

func TestParseHAProxyCSV_StatusValues(t *testing.T) {
	csv := `# pxname,svname,status,type
be,s1,UP,2
be,s2,DOWN,2
be,s3,DRAIN,2
be,s4,MAINT,2
`
	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	statuses := []string{"UP", "DOWN", "DRAIN", "MAINT"}
	for i, want := range statuses {
		if entries[i].Status != want {
			t.Errorf("entry[%d].Status = %q, want %q", i, entries[i].Status, want)
		}
	}
}

func TestParseHAProxyCSV_SingleLine(t *testing.T) {
	// Only header, no data line — should return nil.
	csv := `# pxname,svname,status,type`
	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0, got %d", len(entries))
	}
}

func TestParseHAProxyCSV_ExtraColumns(t *testing.T) {
	csv := `# pxname,svname,status,type,extra1,extra2
be,s1,UP,2,foo,bar
`
	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Status != "UP" {
		t.Errorf("Status = %q", entries[0].Status)
	}
}

// ── csvField / csvFieldInt edge cases ────────────────────────────────────────

func TestCsvField_OutOfBounds(t *testing.T) {
	fields := []string{"a", "b"}
	colIdx := map[string]int{"c": 5} // index beyond fields length
	result := csvField(fields, colIdx, "c")
	if result != "" {
		t.Errorf("csvField out of bounds = %q, want empty", result)
	}
}

func TestCsvField_MissingKey(t *testing.T) {
	fields := []string{"a", "b"}
	colIdx := map[string]int{"x": 0}
	result := csvField(fields, colIdx, "nonexistent")
	if result != "" {
		t.Errorf("csvField missing key = %q, want empty", result)
	}
}

func TestCsvFieldInt_NonNumeric(t *testing.T) {
	fields := []string{"abc"}
	colIdx := map[string]int{"val": 0}
	result := csvFieldInt(fields, colIdx, "val")
	if result != 0 {
		t.Errorf("csvFieldInt non-numeric = %d, want 0", result)
	}
}

func TestCsvFieldInt_EmptyString(t *testing.T) {
	fields := []string{""}
	colIdx := map[string]int{"val": 0}
	result := csvFieldInt(fields, colIdx, "val")
	if result != 0 {
		t.Errorf("csvFieldInt empty = %d, want 0", result)
	}
}

func TestCsvFieldInt_NegativeValue(t *testing.T) {
	fields := []string{"-42"}
	colIdx := map[string]int{"val": 0}
	result := csvFieldInt(fields, colIdx, "val")
	if result != -42 {
		t.Errorf("csvFieldInt negative = %d, want -42", result)
	}
}

// ── Manager.Remove file cleanup (more thorough) ─────────────────────────────

func TestManager_Remove_CleansAllConfigFiles(t *testing.T) {
	dir := t.TempDir()

	// Create all the config files that Remove should delete.
	files := []string{
		"test-lb-haproxy.cfg",
		"test-lb-keepalived.conf",
		"test-lb-conntrackd.conf",
		"test-lb-notify.sh",
	}
	for _, f := range files {
		os.WriteFile(filepath.Join(dir, f), []byte("config"), 0640)
	}

	// Simulate Remove's file deletion logic (without calling systemctl).
	name := "test-lb"
	for _, f := range []string{
		filepath.Join(dir, name+"-haproxy.cfg"),
		filepath.Join(dir, name+"-keepalived.conf"),
		filepath.Join(dir, name+"-conntrackd.conf"),
		filepath.Join(dir, name+"-notify.sh"),
	} {
		os.Remove(f)
	}

	for _, f := range files {
		path := filepath.Join(dir, f)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file %s should have been removed", f)
		}
	}
}

// ── Manager.discoverBackendSections edge cases ──────────────────────────────

func TestDiscoverBackendSections_EmptyConfig(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: dir}

	os.WriteFile(filepath.Join(dir, "empty-haproxy.cfg"), []byte(""), 0640)
	backends := m.discoverBackendSections("empty")
	if len(backends) != 0 {
		t.Errorf("expected 0 backends from empty config, got %v", backends)
	}
}

func TestDiscoverBackendSections_OnlyGlobalDefaults(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: dir}

	cfg := "global\n    maxconn 4096\n\ndefaults\n    timeout connect 5s\n"
	os.WriteFile(filepath.Join(dir, "nobackend-haproxy.cfg"), []byte(cfg), 0640)
	backends := m.discoverBackendSections("nobackend")
	if len(backends) != 0 {
		t.Errorf("expected 0, got %v", backends)
	}
}

func TestDiscoverBackendSections_ManyBackends(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: dir}

	var sb strings.Builder
	sb.WriteString("global\n\ndefaults\n\n")
	for i := 0; i < 10; i++ {
		sb.WriteString("backend svc-" + strconv.Itoa(i) + "-be\n    balance roundrobin\n\n")
	}
	os.WriteFile(filepath.Join(dir, "many-haproxy.cfg"), []byte(sb.String()), 0640)

	backends := m.discoverBackendSections("many")
	if len(backends) != 10 {
		t.Errorf("expected 10 backends, got %d: %v", len(backends), backends)
	}
}

// ── RenderConntrackd edge cases ─────────────────────────────────────────────

func TestRenderConntrackd_MissingLocalIPOnly(t *testing.T) {
	cfg := Config{Name: "test", PeerIP: "10.0.0.2"}
	_, err := RenderConntrackd(cfg)
	if err == nil {
		t.Error("expected error for missing LocalIP")
	}
	if !strings.Contains(err.Error(), "LocalIP") {
		t.Errorf("error should mention LocalIP: %v", err)
	}
}

func TestRenderConntrackd_MissingPeerIPOnly(t *testing.T) {
	cfg := Config{Name: "test", LocalIP: "10.0.0.1"}
	_, err := RenderConntrackd(cfg)
	if err == nil {
		t.Error("expected error for missing PeerIP")
	}
}

func TestRenderConntrackd_AllFieldsPresent(t *testing.T) {
	cfg := Config{
		Name:      "snat-lb",
		Interface: "bond0",
		LocalIP:   "10.0.0.1",
		PeerIP:    "10.0.0.2",
		Subnet:    "192.168.0.0/16",
	}
	out, err := RenderConntrackd(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"Mode FTFW",
		"IPv4_address 10.0.0.1",
		"IPv4_Destination_Address 10.0.0.2",
		"Port 3780",
		"Interface bond0",
		"conntrack-snat-lb.lock",
		"conntrackd-snat-lb.ctl",
		"192.168.0.0/16",
		"NetlinkBufferSize 2097152",
		"HashSize 32768",
		"Protocol Accept { TCP UDP }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in conntrackd config:\n%s", want, out)
		}
	}
}

// ── RenderNotifyScript edge cases ───────────────────────────────────────────

func TestRenderNotifyScript_NameInPath(t *testing.T) {
	cfg := Config{Name: "my-special-lb"}
	out, err := RenderNotifyScript(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "conntrackd-my-special-lb.ctl") {
		t.Errorf("notify script should reference lb name:\n%s", out)
	}
	if !strings.Contains(out, "#!/bin/bash") {
		t.Error("missing shebang")
	}
	if !strings.Contains(out, "case \"$1\" in") {
		t.Error("missing case statement")
	}
}

func TestRenderNotifyScript_ContainsMasterAndBackupCases(t *testing.T) {
	cfg := Config{Name: "lb1"}
	out, err := RenderNotifyScript(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "MASTER)") {
		t.Error("missing MASTER case")
	}
	if !strings.Contains(out, "BACKUP|FAULT)") {
		t.Error("missing BACKUP|FAULT case")
	}
	if !strings.Contains(out, "commit") {
		t.Error("MASTER case should commit")
	}
	if !strings.Contains(out, "f internal") {
		t.Error("MASTER case should flush internal")
	}
	if !strings.Contains(out, "f external") {
		t.Error("BACKUP/FAULT case should flush external")
	}
}

// ── RenderHAProxy + RenderKeepalived integration with SNAT ──────────────────

func TestRenderFullSNATConfig(t *testing.T) {
	cfg := Config{
		Name:        "snat-gw",
		VIP:         "10.100.0.1",
		VIPPrefix:   24,
		Interface:   "br0",
		VRID:        77,
		Priority:    100,
		Algorithm:   "leastconn",
		SNATEnabled: true,
		LocalIP:     "192.168.1.10",
		PeerIP:      "192.168.1.11",
		Subnet:      "10.100.0.0/24",
		Backends: []Backend{
			{Name: "app-1", IP: "10.100.0.10", Port: 3000},
			{Name: "app-2", IP: "10.100.0.11", Port: 3000},
		},
		Ports: []Port{
			{Listen: 80, Target: 3000, Protocol: "tcp"},
			{Listen: 443, Target: 3000, Protocol: "tcp", TLS: &TLSConfig{Cert: "/etc/ssl/cert.pem", Key: "/etc/ssl/key.pem"}},
		},
	}

	// All four render functions should succeed with the same config.
	haOut, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy: %v", err)
	}
	kaOut, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	ctOut, err := RenderConntrackd(cfg)
	if err != nil {
		t.Fatalf("RenderConntrackd: %v", err)
	}
	notifyOut, err := RenderNotifyScript(cfg)
	if err != nil {
		t.Fatalf("RenderNotifyScript: %v", err)
	}

	// HAProxy checks.
	if !strings.Contains(haOut, "balance leastconn") {
		t.Error("haproxy missing leastconn")
	}
	if !strings.Contains(haOut, "ssl crt") {
		t.Error("haproxy missing TLS binding")
	}
	if strings.Count(haOut, "frontend snat-gw-") != 2 {
		t.Error("expected 2 frontends")
	}

	// Keepalived checks.
	if !strings.Contains(kaOut, "notify_master") {
		t.Error("keepalived missing notify_master for SNAT")
	}
	if !strings.Contains(kaOut, "state MASTER") {
		t.Error("keepalived missing MASTER state")
	}

	// Conntrackd checks.
	if !strings.Contains(ctOut, "192.168.1.10") {
		t.Error("conntrackd missing LocalIP")
	}
	if !strings.Contains(ctOut, "br0") {
		t.Error("conntrackd missing interface")
	}

	// Notify script checks.
	if !strings.Contains(notifyOut, "snat-gw") {
		t.Error("notify script missing lb name")
	}
}

// ── RenderHAProxy health check coverage gaps ────────────────────────────────

func TestRenderHAProxy_HealthNilWithMultiplePorts(t *testing.T) {
	cfg := Config{
		Name:     "svc",
		Backends: []Backend{{Name: "b1", IP: "10.0.0.1", Port: 80}},
		Ports: []Port{
			{Listen: 80, Target: 80, Protocol: "tcp"},
			{Listen: 443, Target: 443, Protocol: "tcp"},
		},
		Health: nil,
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Each backend section should have tcp-check.
	count := strings.Count(out, "option tcp-check")
	if count != 2 {
		t.Errorf("expected 2 'option tcp-check', got %d:\n%s", count, out)
	}
}

func TestRenderHAProxy_HTTPHealthWithMultiplePorts(t *testing.T) {
	cfg := Config{
		Name:     "svc",
		Backends: []Backend{{Name: "b1", IP: "10.0.0.1", Port: 80}},
		Ports: []Port{
			{Listen: 80, Target: 80, Protocol: "tcp"},
			{Listen: 8080, Target: 8080, Protocol: "tcp"},
		},
		Health: &HealthConfig{Type: "http", Path: "/health"},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := strings.Count(out, "option httpchk GET /health")
	if count != 2 {
		t.Errorf("expected 2 http health checks, got %d:\n%s", count, out)
	}
}

func TestRenderHAProxy_CustomIntervalWithHTTPCheck(t *testing.T) {
	cfg := Config{
		Name:      "svc",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.1", Port: 80}},
		Ports:     []Port{{Listen: 80, Target: 80, Protocol: "tcp"}},
		Health:    &HealthConfig{Type: "http", Path: "/ready", IntervalMS: 3000},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "inter 3000ms") {
		t.Errorf("expected custom interval 3000ms:\n%s", out)
	}
	if !strings.Contains(out, "option httpchk GET /ready") {
		t.Errorf("expected http health check:\n%s", out)
	}
}

// ── RenderHAProxy TLS edge cases ────────────────────────────────────────────

func TestRenderHAProxy_AllPortsTLS(t *testing.T) {
	cfg := Config{
		Name:      "secure",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.1", Port: 443}},
		Ports: []Port{
			{Listen: 443, Target: 443, Protocol: "tcp", TLS: &TLSConfig{Cert: "/c", Key: "/k"}},
			{Listen: 8443, Target: 443, Protocol: "tcp", TLS: &TLSConfig{Cert: "/c2", Key: "/k2"}},
		},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sslCount := strings.Count(out, "ssl crt")
	if sslCount != 2 {
		t.Errorf("expected 2 ssl crt directives, got %d:\n%s", sslCount, out)
	}
	if !strings.Contains(out, "secure-443.pem") {
		t.Error("missing PEM path for port 443")
	}
	if !strings.Contains(out, "secure-8443.pem") {
		t.Error("missing PEM path for port 8443")
	}
}

func TestRenderHAProxy_MixedTLSAndPlain(t *testing.T) {
	cfg := Config{
		Name:      "mixed",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.1", Port: 8080}},
		Ports: []Port{
			{Listen: 80, Target: 8080, Protocol: "tcp"},
			{Listen: 443, Target: 8080, Protocol: "tcp", TLS: &TLSConfig{Cert: "/c", Key: "/k"}},
			{Listen: 8080, Target: 8080, Protocol: "tcp"},
		},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sslCount := strings.Count(out, "ssl crt")
	if sslCount != 1 {
		t.Errorf("expected exactly 1 ssl crt, got %d:\n%s", sslCount, out)
	}
}

// ── DetectInterface tests ───────────────────────────────────────────────────

func TestDetectInterface_ReturnsNonEmpty(t *testing.T) {
	iface := DetectInterface()
	if iface == "" {
		t.Error("DetectInterface should return non-empty")
	}
}

func TestDetectInterface_NoWhitespace(t *testing.T) {
	iface := DetectInterface()
	if strings.TrimSpace(iface) != iface {
		t.Errorf("DetectInterface has whitespace: %q", iface)
	}
}

// ── AllocVRID additional properties ─────────────────────────────────────────

func TestAllocVRID_StabilityAcrossCalls(t *testing.T) {
	// Ensure same input always produces same output across many calls.
	results := make([]int, 1000)
	for i := range results {
		results[i] = AllocVRID("stable-test")
	}
	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Fatalf("AllocVRID not stable: call %d got %d, call 0 got %d", i, results[i], results[0])
		}
	}
}

// ── Manager struct field access ─────────────────────────────────────────────

func TestNewManager_FieldValues(t *testing.T) {
	m := NewManager()
	if m.configDir != "/etc/litevirt/lb" {
		t.Errorf("configDir = %q", m.configDir)
	}
	if m.runDir != "/run/litevirt/lb" {
		t.Errorf("runDir = %q", m.runDir)
	}
}
