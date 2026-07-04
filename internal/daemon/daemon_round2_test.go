package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_TabIndented(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := "host_name: \"tab-host\"\ngrpc_port:\t9443\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.GRPCPort != 9443 {
		t.Errorf("GRPCPort = %d, want 9443", cfg.GRPCPort)
	}
}

// The Phase-2 VIP self-demote timings must both be positive (majority reclaim is
// proof-gated, so there is no demote-vs-takeover invariant — just sane durations).
func TestLoadConfig_VIPTimingInvariant(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	// A zero keepalived-stop timeout is nonsensical (DemoteAll would give up instantly).
	yaml := "host_name: \"h\"\nquorum_loss_demote_after_sec: 12\nkeepalived_stop_timeout_sec: 0\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected LoadConfig to reject a non-positive VIP self-demote timing")
	} else if !strings.Contains(err.Error(), "VIP self-demote timing") {
		t.Errorf("error = %q, want it to mention the VIP self-demote timing", err.Error())
	}
}

// The defaults are positive and load cleanly.
func TestLoadConfig_VIPTimingDefaultsValid(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("host_name: \"h\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with defaults: %v", err)
	}
	if cfg.QuorumLossDemoteAfterSec != 12 || cfg.KeepalivedStopTimeoutSec != 3 {
		t.Errorf("unexpected VIP timing defaults: %+v", cfg)
	}
}

func TestLoadConfig_WhitespaceHostName(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// YAML value with surrounding whitespace -- yaml.Unmarshal trims it
	yaml := "host_name: \"  spaced-host  \"\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "  spaced-host  " {
		t.Errorf("HostName = %q", cfg.HostName)
	}
}

func TestLoadConfig_OnlyComments(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := "# This is a comment\n# Another comment\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for config with only comments (no host_name)")
	}
	if !strings.Contains(err.Error(), "host_name is required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestLoadConfig_BinaryGarbage(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte{0x00, 0xFF, 0xFE, 0x01}, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for binary garbage")
	}
}

func TestLoadConfig_UnknownFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "unknown-fields-host"
unknown_field: "should be ignored"
another_unknown: 42
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "unknown-fields-host" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
}

func TestLoadConfig_NegativePort(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "neg-port-host"
grpc_port: -1
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// No validation on port range currently, so it just stores -1
	if cfg.GRPCPort != -1 {
		t.Errorf("GRPCPort = %d, want -1", cfg.GRPCPort)
	}
}

func TestLoadConfig_LargePort(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "big-port-host"
grpc_port: 99999
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.GRPCPort != 99999 {
		t.Errorf("GRPCPort = %d, want 99999", cfg.GRPCPort)
	}
}

func TestLoadConfig_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("host_name: test"), 0000); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Errorf("error = %q, expected to mention 'read config'", err.Error())
	}
}

func TestLoadConfig_SpecialCharsHostName(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "node-01.dc1.example.com"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "node-01.dc1.example.com" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
}

func TestParsePCIRescanInterval_ZeroString(t *testing.T) {
	d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: "0"}}}
	got := d.parsePCIRescanInterval()
	if got != 0 {
		t.Errorf("parsePCIRescanInterval('0') = %v, want 0", got)
	}
}

func TestParsePCIRescanInterval_EmptyConfig(t *testing.T) {
	d := &Daemon{cfg: &Config{}}
	got := d.parsePCIRescanInterval()
	if got != 0 {
		t.Errorf("parsePCIRescanInterval(empty) = %v, want 0", got)
	}
}

func TestParsePCIRescanInterval_SubSecond(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"500ms", 500 * time.Millisecond},
		{"1us", 1 * time.Microsecond},
		{"100ns", 100 * time.Nanosecond},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: tt.value}}}
			got := d.parsePCIRescanInterval()
			if got != tt.want {
				t.Errorf("parsePCIRescanInterval(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestParsePCIRescanInterval_LargeDuration(t *testing.T) {
	d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: "24h"}}}
	got := d.parsePCIRescanInterval()
	if got != 24*time.Hour {
		t.Errorf("parsePCIRescanInterval('24h') = %v, want 24h", got)
	}
}

func TestParsePCIRescanInterval_CompoundDuration(t *testing.T) {
	d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: "1h30m"}}}
	got := d.parsePCIRescanInterval()
	if got != time.Hour+30*time.Minute {
		t.Errorf("parsePCIRescanInterval('1h30m') = %v, want 1h30m", got)
	}
}

func TestParsePCIRescanInterval_Whitespace(t *testing.T) {
	// Go's ParseDuration does not handle leading/trailing whitespace
	d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: " 5m "}}}
	got := d.parsePCIRescanInterval()
	// Should fail to parse and return 0
	if got != 0 {
		t.Errorf("parsePCIRescanInterval(' 5m ') = %v, want 0 (parse failure)", got)
	}
}

func TestConfigDefaults_AreAppliedBeforeUnmarshal(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Config that only overrides host_name. All defaults should survive.
	yaml := `host_name: "defaults-test"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	defaults := map[string]interface{}{
		"GRPCPort":    7443,
		"MetricsPort": 7444,
		"GossipPort":  7946,
		"DNSPort":     5354,
		"RESTPort":    7446,
	}
	if cfg.GRPCPort != defaults["GRPCPort"] {
		t.Errorf("GRPCPort = %d, want %d", cfg.GRPCPort, defaults["GRPCPort"])
	}
	if cfg.MetricsPort != defaults["MetricsPort"] {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, defaults["MetricsPort"])
	}
	if cfg.GossipPort != defaults["GossipPort"] {
		t.Errorf("GossipPort = %d, want %d", cfg.GossipPort, defaults["GossipPort"])
	}
	if cfg.DNSPort != defaults["DNSPort"] {
		t.Errorf("DNSPort = %d, want %d", cfg.DNSPort, defaults["DNSPort"])
	}
	if cfg.RESTPort != defaults["RESTPort"] {
		t.Errorf("RESTPort = %d, want %d", cfg.RESTPort, defaults["RESTPort"])
	}
	if cfg.PKIDir != "/etc/litevirt/pki" {
		t.Errorf("PKIDir = %q", cfg.PKIDir)
	}
	if cfg.DataDir != "/var/lib/litevirt" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.DNSDomain != "litevirt.local" {
		t.Errorf("DNSDomain = %q", cfg.DNSDomain)
	}
}

func TestLoadConfig_OverrideAllDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "override-all"
grpc_port: 1111
metrics_port: 2222
pki_dir: /custom/pki
data_dir: /custom/data
gossip_port: 3333
dns_port: 4444
dns_domain: "custom.domain"
rest_port: 5555
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.GRPCPort != 1111 {
		t.Errorf("GRPCPort = %d", cfg.GRPCPort)
	}
	if cfg.MetricsPort != 2222 {
		t.Errorf("MetricsPort = %d", cfg.MetricsPort)
	}
	if cfg.PKIDir != "/custom/pki" {
		t.Errorf("PKIDir = %q", cfg.PKIDir)
	}
	if cfg.DataDir != "/custom/data" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.GossipPort != 3333 {
		t.Errorf("GossipPort = %d", cfg.GossipPort)
	}
	if cfg.DNSPort != 4444 {
		t.Errorf("DNSPort = %d", cfg.DNSPort)
	}
	if cfg.DNSDomain != "custom.domain" {
		t.Errorf("DNSDomain = %q", cfg.DNSDomain)
	}
	if cfg.RESTPort != 5555 {
		t.Errorf("RESTPort = %d", cfg.RESTPort)
	}
}

func TestLoadConfig_DirectoryAsConfigPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LITEVIRT_CONFIG", dir)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error when config path is a directory")
	}
}

func TestLoadConfig_JSONContent(t *testing.T) {
	// YAML is a superset of JSON, so valid JSON should parse
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	jsonContent := `{"host_name": "json-host", "grpc_port": 8443}`
	if err := os.WriteFile(configPath, []byte(jsonContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "json-host" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
	if cfg.GRPCPort != 8443 {
		t.Errorf("GRPCPort = %d", cfg.GRPCPort)
	}
}

func TestLoadConfig_PCIRescanIntervalZero(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "pci-zero-host"
pci:
  rescan_interval: "0"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.PCI.RescanInterval != "0" {
		t.Errorf("PCI.RescanInterval = %q, want '0'", cfg.PCI.RescanInterval)
	}

	d := &Daemon{cfg: cfg}
	dur := d.parsePCIRescanInterval()
	if dur != 0 {
		t.Errorf("parsePCIRescanInterval = %v, want 0", dur)
	}
}

func TestPCIConfig_ZeroValue(t *testing.T) {
	cfg := PCIConfig{}
	if cfg.RescanInterval != "" {
		t.Errorf("zero RescanInterval = %q", cfg.RescanInterval)
	}
	if cfg.UdevHook {
		t.Error("zero UdevHook should be false")
	}
}

func TestSRIOVConfig_ZeroValue(t *testing.T) {
	cfg := SRIOVConfig{}
	if cfg.Managed {
		t.Error("zero Managed should be false")
	}
	if cfg.MaxVFsPerPF != 0 {
		t.Errorf("zero MaxVFsPerPF = %d", cfg.MaxVFsPerPF)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	if defaultConfigPath != "/etc/litevirt/config.yaml" {
		t.Errorf("defaultConfigPath = %q", defaultConfigPath)
	}
}

func TestLoadConfig_SymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.yaml")
	linkPath := filepath.Join(dir, "link.yaml")

	yaml := `host_name: "symlink-host"
`
	if err := os.WriteFile(realPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", linkPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "symlink-host" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
}

func TestGetOutboundIP_ReturnsValidIP(t *testing.T) {
	ip := getOutboundIP()
	if ip == "" {
		t.Error("getOutboundIP returned empty string")
	}
	// Should be either a real IP or the fallback 127.0.0.1
	if ip != "127.0.0.1" {
		// Validate it looks like an IP address
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			t.Errorf("getOutboundIP = %q, doesn't look like an IPv4 address", ip)
		}
	}
}

func TestLoadConfig_UnicodeHostName(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := "host_name: \"node-\u00e9l\u00e8ve\"\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "node-\u00e9l\u00e8ve" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
}
