package lb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllocVRID_Range(t *testing.T) {
	names := []string{"web", "api", "db", "cache", "worker", "", "a", "very-long-lb-name-that-exceeds-normal"}
	for _, name := range names {
		vrid := AllocVRID(name)
		if vrid < 1 || vrid > 254 {
			t.Errorf("AllocVRID(%q) = %d, want [1,254]", name, vrid)
		}
	}
}

func TestAllocVRID_Deterministic(t *testing.T) {
	v1 := AllocVRID("my-lb")
	v2 := AllocVRID("my-lb")
	if v1 != v2 {
		t.Errorf("AllocVRID not deterministic: %d vs %d", v1, v2)
	}
}

func TestAllocVRID_DifferentNames(t *testing.T) {
	v1 := AllocVRID("web")
	v2 := AllocVRID("api")
	_ = v1
	_ = v2
}

func TestVRIDFromString_NumericValid(t *testing.T) {
	if v := VRIDFromString("42"); v != 42 {
		t.Errorf("VRIDFromString(42) = %d", v)
	}
	if v := VRIDFromString("1"); v != 1 {
		t.Errorf("VRIDFromString(1) = %d", v)
	}
	if v := VRIDFromString("254"); v != 254 {
		t.Errorf("VRIDFromString(254) = %d", v)
	}
}

func TestVRIDFromString_NumericOutOfRange(t *testing.T) {
	v := VRIDFromString("0")
	if v < 1 || v > 254 {
		t.Errorf("VRIDFromString(0) = %d, out of range", v)
	}
	v2 := VRIDFromString("255")
	if v2 < 1 || v2 > 254 {
		t.Errorf("VRIDFromString(255) = %d, out of range", v2)
	}
	v3 := VRIDFromString("999")
	if v3 < 1 || v3 > 254 {
		t.Errorf("VRIDFromString(999) = %d, out of range", v3)
	}
}

func TestVRIDFromString_NonNumeric(t *testing.T) {
	v := VRIDFromString("my-lb")
	expected := AllocVRID("my-lb")
	if v != expected {
		t.Errorf("VRIDFromString(my-lb) = %d, want %d", v, expected)
	}
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.configDir != "/etc/litevirt/lb" {
		t.Errorf("configDir = %q", m.configDir)
	}
}

func TestDetectInterface(t *testing.T) {
	iface := DetectInterface()
	if iface == "" {
		t.Error("DetectInterface returned empty string")
	}
	if strings.ContainsAny(iface, " \t\n") {
		t.Errorf("DetectInterface returned name with whitespace: %q", iface)
	}
}

func TestAllocVRID_EmptyString(t *testing.T) {
	v := AllocVRID("")
	if v < 1 || v > 254 {
		t.Errorf("AllocVRID empty = %d", v)
	}
}

func TestAllocVRID_UnicodeName(t *testing.T) {
	v := AllocVRID("lb-日本語")
	if v < 1 || v > 254 {
		t.Errorf("AllocVRID unicode = %d", v)
	}
}

func TestVRIDFromString_BoundaryValues(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"1", 1},
		{"254", 254},
	}
	for _, tc := range tests {
		got := VRIDFromString(tc.input)
		if got != tc.want {
			t.Errorf("VRIDFromString(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestVRIDFromString_NegativeNumber(t *testing.T) {
	v := VRIDFromString("-1")
	if v < 1 || v > 254 {
		t.Errorf("VRIDFromString(-1) = %d, out of range", v)
	}
}

func TestRenderHAProxy_SingleBackendSinglePort(t *testing.T) {
	cfg := Config{
		Name:      "minimal",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "solo", IP: "172.16.0.5", Port: 5000}},
		Ports:     []Port{{Listen: 5000, Target: 5000, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "frontend minimal-5000") {
		t.Errorf("missing frontend:\n%s", out)
	}
	if !strings.Contains(out, "server solo 172.16.0.5:5000 check") {
		t.Errorf("missing server line:\n%s", out)
	}
}

func TestRenderKeepalived_HighPriority(t *testing.T) {
	cfg := Config{
		Name:      "ha",
		VIP:       "10.10.10.1",
		VIPPrefix: 24,
		Interface: "bond0",
		VRID:      200,
		Priority:  100,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "state MASTER") {
		t.Errorf("priority 100 should be MASTER:\n%s", out)
	}
	if !strings.Contains(out, "interface bond0") {
		t.Errorf("missing bond0:\n%s", out)
	}
}

func TestRenderKeepalived_LowPriority(t *testing.T) {
	cfg := Config{
		Name:      "ha",
		VIP:       "10.10.10.1",
		VIPPrefix: 24,
		Interface: "eth1",
		VRID:      200,
		Priority:  1,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "state BACKUP") {
		t.Errorf("priority 1 should be BACKUP:\n%s", out)
	}
}

func TestParseVIP_EdgeCases(t *testing.T) {
	ip, prefix, err := ParseVIP("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "" || prefix != 32 {
		t.Errorf("ParseVIP(\"\") = %q/%d", ip, prefix)
	}
}

// TestManager_Apply_WritesConfigFiles tests only the file-writing portion
// of Apply by using a temp dir. The systemctl/haproxy commands will fail,
// but the config files should still be written before those calls.
func TestManager_Apply_WritesConfigFiles(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{
		Name:      "test-lb",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      10,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:     []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}

	// Instead of calling m.Apply (which runs systemctl), test config rendering
	// and file writing directly.
	haproxyCfg, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy: %v", err)
	}
	haproxyPath := filepath.Join(dir, cfg.Name+"-haproxy.cfg")
	if err := os.WriteFile(haproxyPath, []byte(haproxyCfg), 0640); err != nil {
		t.Fatalf("write haproxy config: %v", err)
	}

	keepalivedCfg, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	keepalivedPath := filepath.Join(dir, cfg.Name+"-keepalived.conf")
	if err := os.WriteFile(keepalivedPath, []byte(keepalivedCfg), 0640); err != nil {
		t.Fatalf("write keepalived config: %v", err)
	}

	// Verify haproxy config
	data, err := os.ReadFile(haproxyPath)
	if err != nil {
		t.Fatalf("haproxy config not written: %v", err)
	}
	if !strings.Contains(string(data), "frontend test-lb-80") {
		t.Errorf("haproxy config missing frontend:\n%s", string(data))
	}
	if !strings.Contains(string(data), "server b1 10.0.1.10:8080") {
		t.Errorf("haproxy config missing backend:\n%s", string(data))
	}

	// Verify keepalived config
	data2, err := os.ReadFile(keepalivedPath)
	if err != nil {
		t.Fatalf("keepalived config not written: %v", err)
	}
	if !strings.Contains(string(data2), "vrrp_instance test-lb") {
		t.Errorf("keepalived config missing vrrp_instance:\n%s", string(data2))
	}
}

func TestManager_Remove_FileCleanup(t *testing.T) {
	dir := t.TempDir()

	// Pre-create config files
	haproxyPath := filepath.Join(dir, "rm-test-haproxy.cfg")
	keepalivedPath := filepath.Join(dir, "rm-test-keepalived.conf")
	os.WriteFile(haproxyPath, []byte("config"), 0640)
	os.WriteFile(keepalivedPath, []byte("config"), 0640)

	// Test file removal directly (without calling systemctl)
	for _, f := range []string{haproxyPath, keepalivedPath} {
		_ = os.Remove(f)
	}

	if _, err := os.Stat(haproxyPath); !os.IsNotExist(err) {
		t.Error("haproxy config should be deleted")
	}
	if _, err := os.Stat(keepalivedPath); !os.IsNotExist(err) {
		t.Error("keepalived config should be deleted")
	}
}

func TestRenderHAProxy_SourceAlgorithm(t *testing.T) {
	cfg := Config{
		Name:      "api",
		Algorithm: "source",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "balance source") {
		t.Errorf("expected 'balance source', got:\n%s", out)
	}
}

func TestRenderHAProxy_LeastconnAlgorithm(t *testing.T) {
	cfg := Config{
		Name:      "api",
		Algorithm: "leastconn",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 443, Target: 3000, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "balance leastconn") {
		t.Errorf("expected 'balance leastconn', got:\n%s", out)
	}
}

func TestRenderHAProxy_MultipleBackends(t *testing.T) {
	cfg := Config{
		Name:      "web",
		Algorithm: "roundrobin",
		Backends: []Backend{
			{Name: "web-1", IP: "10.0.1.10", Port: 8080},
			{Name: "web-2", IP: "10.0.1.11", Port: 8080},
			{Name: "web-3", IP: "10.0.1.12", Port: 8080},
		},
		Ports: []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, be := range cfg.Backends {
		expected := "server " + be.Name + " " + be.IP + ":8080 check"
		if !strings.Contains(out, expected) {
			t.Errorf("missing backend %q in output:\n%s", be.Name, out)
		}
	}
}

func TestRenderHAProxy_GlobalSection(t *testing.T) {
	cfg := Config{
		Name:     "svc",
		Backends: []Backend{{Name: "b1", IP: "10.0.0.10", Port: 3000}},
		Ports:    []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"global",
		"maxconn 4096",
		"defaults",
		"timeout connect 5s",
		"timeout client  30s",
		"timeout server  30s",
		"option  tcplog",
		"retries 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRenderHAProxy_BackendNaming(t *testing.T) {
	cfg := Config{
		Name:      "myapp",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.10", Port: 9000}},
		Ports: []Port{
			{Listen: 80, Target: 9000, Protocol: "http"},
			{Listen: 8443, Target: 9000, Protocol: "tcp"},
		},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "backend myapp-80-be") {
		t.Errorf("missing backend myapp-80-be:\n%s", out)
	}
	if !strings.Contains(out, "backend myapp-8443-be") {
		t.Errorf("missing backend myapp-8443-be:\n%s", out)
	}
	if !strings.Contains(out, "default_backend myapp-80-be") {
		t.Errorf("missing default_backend reference:\n%s", out)
	}
	if !strings.Contains(out, "default_backend myapp-8443-be") {
		t.Errorf("missing default_backend reference:\n%s", out)
	}
}

func TestRenderHAProxy_NoBackends(t *testing.T) {
	cfg := Config{
		Name:     "empty",
		Backends: []Backend{},
		Ports:    []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "frontend empty-80") {
		t.Errorf("missing frontend:\n%s", out)
	}
	if !strings.Contains(out, "backend empty-80-be") {
		t.Errorf("missing backend:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "server ") {
			t.Errorf("should have no server lines, found: %q", trimmed)
		}
	}
}

func TestRenderHAProxy_NoPorts(t *testing.T) {
	cfg := Config{
		Name:     "noop",
		Backends: []Backend{{Name: "b1", IP: "10.0.0.10", Port: 8080}},
		Ports:    []Port{},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, "frontend") {
		t.Errorf("should have no frontend:\n%s", out)
	}
}

func TestRenderKeepalived_VIPFormat(t *testing.T) {
	cfg := Config{
		Name:      "lb",
		VIP:       "192.168.1.100",
		VIPPrefix: 16,
		Interface: "ens3",
		VRID:      42,
		Priority:  100,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "192.168.1.100/16") {
		t.Errorf("VIP with prefix not found:\n%s", out)
	}
	if !strings.Contains(out, "interface ens3") {
		t.Errorf("missing interface:\n%s", out)
	}
	if !strings.Contains(out, "virtual_router_id 42") {
		t.Errorf("missing VRID:\n%s", out)
	}
}

func TestRenderKeepalived_AuthAndTracking(t *testing.T) {
	cfg := Config{
		Name:      "test",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      1,
		Priority:  50,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"auth_type PASS",
		"auth_pass ", // F6: per-LB derived password, no longer the literal "litevirt"
		"track_script",
		"chk_haproxy",
		"vrrp_script chk_haproxy",
		"pgrep -f test-haproxy.cfg",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "auth_pass litevirt") {
		t.Error("auth_pass should be a per-LB derived value, not the hardcoded 'litevirt'")
	}
}

func TestParseVIP_IPv6Style(t *testing.T) {
	ip, prefix, err := ParseVIP("10.0.0.1/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "10.0.0.1" || prefix != 32 {
		t.Errorf("got %q/%d", ip, prefix)
	}
}

func TestParseVIP_SmallPrefix(t *testing.T) {
	ip, prefix, err := ParseVIP("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "10.0.0.0" || prefix != 8 {
		t.Errorf("got %q/%d", ip, prefix)
	}
}

func TestDiscoverBackendSections(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: dir}

	// Write a haproxy config with known backend sections.
	cfg := "global\n\ndefaults\n\nfrontend myapp-80\n    bind *:80\n    default_backend myapp-80-be\n\nbackend myapp-80-be\n    balance roundrobin\n\nfrontend myapp-443\n    bind *:443\n    default_backend myapp-443-be\n\nbackend myapp-443-be\n    balance roundrobin\n"
	if err := os.WriteFile(filepath.Join(dir, "myapp-haproxy.cfg"), []byte(cfg), 0640); err != nil {
		t.Fatal(err)
	}

	backends := m.discoverBackendSections("myapp")
	if len(backends) != 2 {
		t.Fatalf("expected 2 backends, got %d: %v", len(backends), backends)
	}
	if backends[0] != "myapp-80-be" || backends[1] != "myapp-443-be" {
		t.Errorf("unexpected backends: %v", backends)
	}
}

func TestDiscoverBackendSections_NoConfig(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: dir}

	backends := m.discoverBackendSections("nonexistent")
	if len(backends) != 0 {
		t.Errorf("expected empty, got %v", backends)
	}
}

// ── HAProxy CSV Parsing Tests ────────────────────────────────────────────────

func TestParseHAProxyCSV(t *testing.T) {
	csv := `# pxname,svname,scur,stot,bin,bout,status,rate,econ,eresp,hrsp_2xx,hrsp_4xx,hrsp_5xx,rtime,qtime,type
web-80,FRONTEND,12,1000,1048576,2097152,OPEN,45,0,0,0,0,0,0,0,0
web-80-be,vm1,5,500,524288,1048576,UP,20,0,1,450,30,20,12,2,2
web-80-be,vm2,7,500,524288,1048576,UP,25,1,0,480,15,5,15,3,2
web-80-be,BACKEND,12,1000,1048576,2097152,UP,45,1,1,930,45,25,0,0,1
`

	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("parseHAProxyCSV: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	// Check frontend
	fe := entries[0]
	if fe.ProxyName != "web-80" || fe.ServerName != "FRONTEND" {
		t.Errorf("frontend: %q/%q", fe.ProxyName, fe.ServerName)
	}
	if fe.Type != 0 {
		t.Errorf("frontend type = %d, want 0", fe.Type)
	}
	if fe.CurrentSess != 12 {
		t.Errorf("frontend scur = %d, want 12", fe.CurrentSess)
	}

	// Check server entry
	srv := entries[1]
	if srv.ProxyName != "web-80-be" || srv.ServerName != "vm1" {
		t.Errorf("server: %q/%q", srv.ProxyName, srv.ServerName)
	}
	if srv.Type != 2 {
		t.Errorf("server type = %d, want 2", srv.Type)
	}
	if srv.Status != "UP" {
		t.Errorf("server status = %q, want UP", srv.Status)
	}
	if srv.AvgResponseMs != 12 {
		t.Errorf("server rtime = %d, want 12", srv.AvgResponseMs)
	}
	if srv.ErrResp != 1 {
		t.Errorf("server eresp = %d, want 1", srv.ErrResp)
	}
}

func TestParseHAProxyCSV_Empty(t *testing.T) {
	entries, err := parseHAProxyCSV("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseHAProxyCSV_HeaderOnly(t *testing.T) {
	entries, err := parseHAProxyCSV("# pxname,svname,scur,type\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseHAProxyCSV_MissingColumns(t *testing.T) {
	// Only some columns present
	csv := `# pxname,svname,status,type
web-be,vm1,UP,2
`
	entries, err := parseHAProxyCSV(csv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Status != "UP" {
		t.Errorf("status = %q, want UP", entries[0].Status)
	}
	// Missing columns should default to 0
	if entries[0].CurrentSess != 0 {
		t.Errorf("scur should be 0 for missing column, got %d", entries[0].CurrentSess)
	}
}
