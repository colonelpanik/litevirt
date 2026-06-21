package lb

import (
	"strings"
	"testing"
)

func TestRenderHAProxy_Basic(t *testing.T) {
	cfg := Config{
		Name:      "web",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      10,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends: []Backend{
			{Name: "vm1", IP: "10.0.1.10", Port: 8080},
			{Name: "vm2", IP: "10.0.1.11", Port: 8080},
		},
		Ports: []Port{
			{Listen: 80, Target: 8080, Protocol: "tcp"},
		},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	for _, want := range []string{
		"frontend web-80",
		"bind 10.0.1.100:80",
		"backend web-80-be",
		"balance roundrobin",
		"server vm1 10.0.1.10:8080 check",
		"server vm2 10.0.1.11:8080 check",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q\ngot:\n%s", want, out)
		}
	}
}

func TestRenderHAProxy_StatsSocket(t *testing.T) {
	cfg := Config{
		Name:      "myapp",
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.10", Port: 8080}},
		Ports:     []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "stats socket /run/litevirt/lb/myapp-haproxy.sock mode 660 level admin") {
		t.Errorf("missing stats socket in rendered config:\n%s", out)
	}
	if !strings.Contains(out, "stats timeout 30s") {
		t.Errorf("missing stats timeout in rendered config:\n%s", out)
	}
}

func TestRenderHAProxy_DefaultAlgorithm(t *testing.T) {
	cfg := Config{
		Name:      "app",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Backends:  []Backend{{Name: "b1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 443, Target: 3000, Protocol: "tcp"}},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "balance roundrobin") {
		t.Errorf("expected default algorithm roundrobin, got:\n%s", out)
	}
}

func TestRenderHAProxy_MultipleListeners(t *testing.T) {
	cfg := Config{
		Name:      "svc",
		Algorithm: "leastconn",
		Backends:  []Backend{{Name: "b1", IP: "192.168.1.10", Port: 9000}},
		Ports: []Port{
			{Listen: 80, Target: 9000, Protocol: "http"},
			{Listen: 443, Target: 9000, Protocol: "tcp"},
		},
	}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "frontend svc-80") {
		t.Errorf("missing frontend svc-80\n%s", out)
	}
	if !strings.Contains(out, "frontend svc-443") {
		t.Errorf("missing frontend svc-443\n%s", out)
	}
}

func TestRenderKeepalived_Master(t *testing.T) {
	cfg := Config{
		Name:      "web",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      10,
		Priority:  100,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived error: %v", err)
	}
	for _, want := range []string{
		"vrrp_instance web",
		"state MASTER",
		"interface eth0",
		"virtual_router_id 10",
		"priority 100",
		"10.0.1.100/24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in keepalived config\ngot:\n%s", want, out)
		}
	}
}

func TestRenderKeepalived_Backup(t *testing.T) {
	cfg := Config{
		Name:      "web",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      10,
		Priority:  50,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "state BACKUP") {
		t.Errorf("expected BACKUP state\n%s", out)
	}
}

func TestParseVIP(t *testing.T) {
	tests := []struct {
		input      string
		wantIP     string
		wantPrefix int
		wantErr    bool
	}{
		{"10.0.1.100/24", "10.0.1.100", 24, false},
		{"192.168.0.1/16", "192.168.0.1", 16, false},
		{"10.0.0.1", "10.0.0.1", 32, false}, // no prefix → /32
		{"bad/notanint", "", 0, true},
	}
	for _, tc := range tests {
		ip, prefix, err := ParseVIP(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseVIP(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVIP(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if ip != tc.wantIP || prefix != tc.wantPrefix {
			t.Errorf("ParseVIP(%q) = %q/%d, want %q/%d", tc.input, ip, prefix, tc.wantIP, tc.wantPrefix)
		}
	}
}

func TestRenderConntrackd(t *testing.T) {
	cfg := Config{
		Name:      "web-lb",
		Interface: "ens18",
		LocalIP:   "192.168.1.10",
		PeerIP:    "192.168.1.11",
		Subnet:    "10.100.0.0/24",
	}
	out, err := RenderConntrackd(cfg)
	if err != nil {
		t.Fatalf("RenderConntrackd: %v", err)
	}

	checks := []string{
		"192.168.1.10",
		"192.168.1.11",
		"3780",
		"ens18",
		"conntrackd-web-lb",
		"10.100.0.0/24",
		"Mode FTFW",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("conntrackd config missing %q", c)
		}
	}
}

func TestRenderConntrackd_MissingIPs(t *testing.T) {
	cfg := Config{Name: "test"}
	_, err := RenderConntrackd(cfg)
	if err == nil {
		t.Fatal("expected error for missing LocalIP/PeerIP")
	}
}

func TestRenderNotifyScript(t *testing.T) {
	cfg := Config{Name: "web-lb"}
	out, err := RenderNotifyScript(cfg)
	if err != nil {
		t.Fatalf("RenderNotifyScript: %v", err)
	}

	checks := []string{
		"#!/bin/bash",
		"conntrackd-web-lb",
		"MASTER",
		"BACKUP|FAULT",
		"commit",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("notify script missing %q", c)
		}
	}
}

func TestRenderKeepalived_WithSNAT(t *testing.T) {
	cfg := Config{
		Name:        "web-lb",
		VIP:         "10.0.1.100",
		VIPPrefix:   24,
		Interface:   "eth0",
		VRID:        10,
		Priority:    100,
		SNATEnabled: true,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}

	if !strings.Contains(out, "notify_master") {
		t.Error("SNAT-enabled keepalived should have notify_master")
	}
	if !strings.Contains(out, "notify_backup") {
		t.Error("SNAT-enabled keepalived should have notify_backup")
	}
	if !strings.Contains(out, "notify_fault") {
		t.Error("SNAT-enabled keepalived should have notify_fault")
	}
	if !strings.Contains(out, "web-lb-notify.sh") {
		t.Error("notify script path should reference LB name")
	}
}

func TestRenderKeepalived_WithoutSNAT(t *testing.T) {
	cfg := Config{
		Name:        "web-lb",
		VIP:         "10.0.1.100",
		VIPPrefix:   24,
		Interface:   "eth0",
		VRID:        10,
		Priority:    100,
		SNATEnabled: false,
	}
	out, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}

	if strings.Contains(out, "notify_master") {
		t.Error("non-SNAT keepalived should NOT have notify_master")
	}
}

func TestRenderHAProxy_TLS(t *testing.T) {
	cfg := Config{
		Name:      "web",
		VIP:       "10.0.1.100",
		VIPPrefix: 24,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "vm1", IP: "10.0.1.10", Port: 8080}},
		Ports: []Port{
			{Listen: 443, Target: 8080, Protocol: "tcp", TLS: &TLSConfig{Cert: "/etc/ssl/cert.pem", Key: "/etc/ssl/key.pem"}},
			{Listen: 80, Target: 8080, Protocol: "tcp"},
		},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	if !strings.Contains(out, "ssl crt /etc/litevirt/lb/") {
		t.Errorf("expected TLS port to contain 'ssl crt /etc/litevirt/lb/', got:\n%s", out)
	}
	if !strings.Contains(out, "web-443.pem") {
		t.Errorf("expected TLS PEM path to contain 'web-443.pem', got:\n%s", out)
	}

	// Find the frontend for port 80 and verify it does NOT contain ssl.
	// Split output by "frontend" to isolate sections.
	sections := strings.Split(out, "frontend")
	for _, sec := range sections {
		if strings.Contains(sec, "web-80") && strings.Contains(sec, "ssl") {
			t.Errorf("non-TLS port 80 frontend should NOT contain 'ssl', got:\n%s", sec)
		}
	}
}

func TestRenderHAProxy_HTTPHealthCheck(t *testing.T) {
	cfg := Config{
		Name:      "app",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "vm1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
		Health:    &HealthConfig{Type: "http", Path: "/healthz", IntervalMS: 0},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	if !strings.Contains(out, "option httpchk GET /healthz") {
		t.Errorf("expected 'option httpchk GET /healthz', got:\n%s", out)
	}
	if !strings.Contains(out, "http-check expect status 200") {
		t.Errorf("expected 'http-check expect status 200', got:\n%s", out)
	}
	if strings.Contains(out, "option tcp-check") {
		t.Errorf("HTTP health check should NOT contain 'option tcp-check', got:\n%s", out)
	}
}

func TestRenderHAProxy_HTTPHealthCheck_DefaultPath(t *testing.T) {
	cfg := Config{
		Name:      "app",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "vm1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
		Health:    &HealthConfig{Type: "http", Path: "", IntervalMS: 0},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	if !strings.Contains(out, "option httpchk GET /") {
		t.Errorf("expected 'option httpchk GET /' for default path, got:\n%s", out)
	}
}

func TestRenderHAProxy_TCPHealthCheck(t *testing.T) {
	cfg := Config{
		Name:      "app",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "vm1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
		Health:    &HealthConfig{Type: "tcp"},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	if !strings.Contains(out, "option tcp-check") {
		t.Errorf("expected 'option tcp-check' for TCP health check, got:\n%s", out)
	}
	if strings.Contains(out, "httpchk") {
		t.Errorf("TCP health check should NOT contain 'httpchk', got:\n%s", out)
	}

	// Also test nil Health (should default to tcp-check).
	cfg.Health = nil
	out, err = RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error with nil Health: %v", err)
	}
	if !strings.Contains(out, "option tcp-check") {
		t.Errorf("nil Health should produce 'option tcp-check', got:\n%s", out)
	}
	if strings.Contains(out, "httpchk") {
		t.Errorf("nil Health should NOT contain 'httpchk', got:\n%s", out)
	}
}

func TestRenderHAProxy_CustomInterval(t *testing.T) {
	cfg := Config{
		Name:      "app",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "vm1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
		Health:    &HealthConfig{Type: "tcp", IntervalMS: 5000},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	if !strings.Contains(out, "inter 5000ms") {
		t.Errorf("expected 'inter 5000ms' for custom interval, got:\n%s", out)
	}
}

func TestRenderHAProxy_DefaultInterval(t *testing.T) {
	cfg := Config{
		Name:      "app",
		VIP:       "10.0.0.1",
		VIPPrefix: 24,
		Algorithm: "roundrobin",
		Backends:  []Backend{{Name: "vm1", IP: "10.0.0.10", Port: 3000}},
		Ports:     []Port{{Listen: 80, Target: 3000, Protocol: "tcp"}},
	}

	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatalf("RenderHAProxy error: %v", err)
	}

	if !strings.Contains(out, "inter 2s") {
		t.Errorf("expected 'inter 2s' for default interval, got:\n%s", out)
	}
}
