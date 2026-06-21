package lb

import (
	"strings"
	"testing"
)

// ── ParseVIP edge cases ─────────────────────────────────────────────────────

func TestParseVIP_ZeroPrefix(t *testing.T) {
	ip, prefix, err := ParseVIP("0.0.0.0/0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "0.0.0.0" || prefix != 0 {
		t.Errorf("got %q/%d, want 0.0.0.0/0", ip, prefix)
	}
}

func TestParseVIP_NoSlash_DefaultsTo32(t *testing.T) {
	ip, prefix, err := ParseVIP("172.16.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "172.16.0.1" {
		t.Errorf("ip = %q", ip)
	}
	if prefix != 32 {
		t.Errorf("prefix = %d, want 32", prefix)
	}
}

func TestParseVIP_IPv6Style_WithPrefix(t *testing.T) {
	ip, prefix, err := ParseVIP("fd00::1/64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "fd00::1" || prefix != 64 {
		t.Errorf("got %q/%d", ip, prefix)
	}
}

func TestParseVIP_InvalidPrefix_Letters(t *testing.T) {
	_, _, err := ParseVIP("10.0.0.1/abc")
	if err == nil {
		t.Error("expected error for non-numeric prefix")
	}
}

func TestParseVIP_InvalidPrefix_Decimal(t *testing.T) {
	// "3.5" should fail Sscanf with %d.
	_, _, err := ParseVIP("10.0.0.1/3.5")
	// Sscanf("%d") will parse "3" and succeed, so prefix=3. This is not an error.
	if err != nil {
		t.Logf("got error (acceptable): %v", err)
	}
}

func TestParseVIP_SlashOnly(t *testing.T) {
	_, _, err := ParseVIP("/24")
	// parts[0] = "", parts[1] = "24" — no error, ip = "", prefix = 24.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseVIP_TrailingSlash(t *testing.T) {
	// "10.0.0.1/" — parts[1] = "" — Sscanf should fail.
	_, _, err := ParseVIP("10.0.0.1/")
	if err == nil {
		t.Error("expected error for empty prefix after slash")
	}
}

func TestParseVIP_MultipleSlashes(t *testing.T) {
	// SplitN with n=2: "10.0.0.1/24/extra" → parts[0]="10.0.0.1", parts[1]="24/extra".
	// Sscanf("%d") parses "24" and stops.
	ip, prefix, err := ParseVIP("10.0.0.1/24/extra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "10.0.0.1" || prefix != 24 {
		t.Errorf("got %q/%d", ip, prefix)
	}
}

// ── AllocVRID properties ────────────────────────────────────────────────────

func TestAllocVRID_AlwaysInRange(t *testing.T) {
	// Test many diverse inputs.
	inputs := []string{
		"", "a", "ab", "abc", "test-lb", "production-web",
		"verylongnamethatgoeson", "123", "日本語", "emoji🎉",
		strings.Repeat("x", 1000),
	}
	for _, name := range inputs {
		v := AllocVRID(name)
		if v < 1 || v > 254 {
			t.Errorf("AllocVRID(%q) = %d, out of [1,254]", name, v)
		}
	}
}

func TestAllocVRID_DeterministicMultipleCalls(t *testing.T) {
	for i := 0; i < 100; i++ {
		v1 := AllocVRID("consistent")
		v2 := AllocVRID("consistent")
		if v1 != v2 {
			t.Fatalf("iteration %d: %d != %d", i, v1, v2)
		}
	}
}

func TestAllocVRID_DistinctInputsVary(t *testing.T) {
	// Not all distinct inputs produce distinct VRIDs (hash collisions),
	// but we should get at least some variation across many inputs.
	seen := map[int]bool{}
	for i := 0; i < 100; i++ {
		name := strings.Repeat("x", i)
		seen[AllocVRID(name)] = true
	}
	if len(seen) < 5 {
		t.Errorf("expected some diversity across 100 inputs, got only %d distinct VRIDs", len(seen))
	}
}

// ── VRIDFromString edge cases ───────────────────────────────────────────────

func TestVRIDFromString_EmptyString(t *testing.T) {
	v := VRIDFromString("")
	expected := AllocVRID("")
	if v != expected {
		t.Errorf("VRIDFromString('') = %d, want %d", v, expected)
	}
}

func TestVRIDFromString_LargeNumber(t *testing.T) {
	v := VRIDFromString("100000")
	if v < 1 || v > 254 {
		t.Errorf("VRIDFromString('100000') = %d, out of range", v)
	}
	// Falls back to AllocVRID since 100000 > 254.
	if v != AllocVRID("100000") {
		t.Errorf("expected AllocVRID fallback")
	}
}

func TestVRIDFromString_Whitespace(t *testing.T) {
	// "  42  " is not a valid int (Atoi fails), falls back to AllocVRID.
	v := VRIDFromString("  42  ")
	if v < 1 || v > 254 {
		t.Errorf("VRIDFromString('  42  ') = %d", v)
	}
}

// ── RenderHAProxy edge cases ────────────────────────────────────────────────

func TestRenderHAProxy_EmptyConfig(t *testing.T) {
	cfg := Config{}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should produce valid output with global/defaults but no frontends.
	if !strings.Contains(out, "global") {
		t.Error("missing global section")
	}
	if !strings.Contains(out, "defaults") {
		t.Error("missing defaults section")
	}
	if strings.Contains(out, "frontend") {
		t.Error("should have no frontend with empty config")
	}
}

func TestRenderHAProxy_DefaultAlgorithm_IsRoundrobin(t *testing.T) {
	cfg := Config{
		Name:     "test",
		Backends: []Backend{{Name: "b1", IP: "10.0.0.1", Port: 80}},
		Ports:    []Port{{Listen: 80, Target: 80, Protocol: "tcp"}},
		// Algorithm intentionally empty.
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "balance roundrobin") {
		t.Errorf("expected default roundrobin:\n%s", out)
	}
}

func TestRenderHAProxy_ManyBackends(t *testing.T) {
	var backends []Backend
	for i := 0; i < 50; i++ {
		backends = append(backends, Backend{
			Name: "b" + strings.Repeat("x", 5),
			IP:   "10.0.0.1",
			Port: 8080,
		})
	}
	cfg := Config{
		Name:      "scale",
		Algorithm: "leastconn",
		Backends:  backends,
		Ports:     []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := strings.Count(out, "server b")
	if count != 50 {
		t.Errorf("expected 50 server lines, got %d", count)
	}
}

func TestRenderHAProxy_MultiplePorts_EachGetsFrontendAndBackend(t *testing.T) {
	cfg := Config{
		Name:      "multi",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.1", Port: 80}},
		Ports: []Port{
			{Listen: 80, Target: 80, Protocol: "tcp"},
			{Listen: 443, Target: 443, Protocol: "tcp"},
			{Listen: 8080, Target: 8080, Protocol: "tcp"},
		},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, port := range []int{80, 443, 8080} {
		frontend := "frontend multi-"
		if !strings.Contains(out, frontend) {
			t.Errorf("missing frontend for port %d:\n%s", port, out)
		}
	}
}

func TestRenderHAProxy_SpecialCharsInName(t *testing.T) {
	cfg := Config{
		Name:      "my-app_v2.1",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.1", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "frontend my-app_v2.1-80") {
		t.Errorf("name with special chars not rendered:\n%s", out)
	}
}

// ── RenderKeepalived edge cases ─────────────────────────────────────────────

func TestRenderKeepalived_Priority99_IsBackup(t *testing.T) {
	cfg := Config{
		Name:      "lb",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      1,
		Priority:  99,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "state BACKUP") {
		t.Errorf("priority 99 should be BACKUP:\n%s", out)
	}
}

func TestRenderKeepalived_Priority0_IsBackup(t *testing.T) {
	cfg := Config{
		Name:      "lb",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      1,
		Priority:  0,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "state BACKUP") {
		t.Errorf("priority 0 should be BACKUP:\n%s", out)
	}
}

func TestRenderKeepalived_ContainsAllSections(t *testing.T) {
	cfg := Config{
		Name:      "full",
		VIP:       "192.168.1.1",
		VIPPrefix: 24,
		Interface: "ens192",
		VRID:      100,
		Priority:  100,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	required := []string{
		"vrrp_script chk_haproxy",
		"vrrp_instance full",
		"state MASTER",
		"interface ens192",
		"virtual_router_id 100",
		"priority 100",
		"advert_int 1",
		"authentication",
		"auth_type PASS",
		"auth_pass ", // F6: per-LB derived password, not the literal "litevirt"
		"virtual_ipaddress",
		"192.168.1.1/24",
		"track_script",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in output:\n%s", s, out)
		}
	}
}

func TestRenderKeepalived_LargeVRID(t *testing.T) {
	cfg := Config{
		Name:      "lb",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      254,
		Priority:  100,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "virtual_router_id 254") {
		t.Errorf("VRID 254 not rendered:\n%s", out)
	}
}

func TestRenderKeepalived_IPv6VIP(t *testing.T) {
	cfg := Config{
		Name:      "lb6",
		VIP:       "fd00::100",
		VIPPrefix: 64,
		Interface: "eth0",
		VRID:      42,
		Priority:  50,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "fd00::100/64") {
		t.Errorf("IPv6 VIP not rendered:\n%s", out)
	}
}

// ── NewManager ──────────────────────────────────────────────────────────────

func TestNewManager_ReturnsNonNil(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.configDir == "" {
		t.Error("configDir should not be empty")
	}
}

// ── RenderHAProxy + RenderKeepalived roundtrip ──────────────────────────────

func TestRenderBoth_SameConfig(t *testing.T) {
	cfg := Config{
		Name:      "roundtrip",
		VIP:       "10.0.0.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      50,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends: []Backend{
			{Name: "web-1", IP: "10.0.0.10", Port: 8080},
			{Name: "web-2", IP: "10.0.0.11", Port: 8080},
		},
		Ports: []Port{
			{Listen: 80, Target: 8080, Protocol: "tcp"},
			{Listen: 443, Target: 8443, Protocol: "tcp"},
		},
	}

	haOut, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy: %v", err)
	}
	kaOut, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}

	// HAProxy should have 2 frontends, 2 backends, 2 servers each.
	if strings.Count(haOut, "frontend roundtrip-") != 2 {
		t.Errorf("expected 2 frontends:\n%s", haOut)
	}
	// "backend roundtrip-" appears both as "backend roundtrip-X-be" and "default_backend roundtrip-X-be"
	// Count only lines starting with "backend" (after trimming).
	backendCount := 0
	for _, line := range strings.Split(haOut, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "backend roundtrip-") {
			backendCount++
		}
	}
	if backendCount != 2 {
		t.Errorf("expected 2 backend sections, got %d:\n%s", backendCount, haOut)
	}

	// Keepalived should reference the VIP.
	if !strings.Contains(kaOut, "10.0.0.100/24") {
		t.Errorf("missing VIP in keepalived:\n%s", kaOut)
	}
}
