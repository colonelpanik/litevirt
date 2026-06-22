package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_DNSFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "dns-host"
dns_port: 9053
dns_domain: "mycloud.internal"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.DNSPort != 9053 {
		t.Errorf("DNSPort = %d, want 9053", cfg.DNSPort)
	}
	if cfg.DNSDomain != "mycloud.internal" {
		t.Errorf("DNSDomain = %q, want mycloud.internal", cfg.DNSDomain)
	}
}

func TestLoadConfig_DNSDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "default-dns-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.DNSPort != 5354 {
		t.Errorf("default DNSPort = %d, want 5354", cfg.DNSPort)
	}
	if cfg.DNSDomain != "litevirt.local" {
		t.Errorf("default DNSDomain = %q, want litevirt.local", cfg.DNSDomain)
	}
}

func TestLoadConfig_RESTPort(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "rest-host"
rest_port: 8080
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RESTPort != 8080 {
		t.Errorf("RESTPort = %d, want 8080", cfg.RESTPort)
	}
}

// P2-2: the anti-entropy interval is operator-configurable.
func TestLoadConfig_AntiEntropyInterval(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	yaml := `host_name: "ae-host"
anti_entropy_interval_sec: 10
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.AntiEntropyIntervalSec != 10 {
		t.Errorf("AntiEntropyIntervalSec = %d, want 10", cfg.AntiEntropyIntervalSec)
	}
	// Unset stays 0 (NewAntiEntropy maps 0 → 60s default).
	dir2 := t.TempDir()
	p2 := filepath.Join(dir2, "config.yaml")
	if err := os.WriteFile(p2, []byte(`host_name: "ae-default"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", p2)
	cfg2, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg2.AntiEntropyIntervalSec != 0 {
		t.Errorf("default AntiEntropyIntervalSec = %d, want 0", cfg2.AntiEntropyIntervalSec)
	}
}

func TestLoadConfig_RESTPortDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "rest-default-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RESTPort != 7446 {
		t.Errorf("default RESTPort = %d, want 7446", cfg.RESTPort)
	}
}

func TestLoadConfig_RESTPortDisabled(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "rest-disabled-host"
rest_port: 0
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RESTPort != 0 {
		t.Errorf("RESTPort = %d, want 0 (disabled)", cfg.RESTPort)
	}
}

func TestLoadConfig_WatchdogDev(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "watchdog-host"
watchdog_dev: "/dev/watchdog"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.WatchdogDev != "/dev/watchdog" {
		t.Errorf("WatchdogDev = %q, want /dev/watchdog", cfg.WatchdogDev)
	}
}

func TestLoadConfig_WatchdogDevDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "no-watchdog-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.WatchdogDev != "" {
		t.Errorf("default WatchdogDev = %q, want empty", cfg.WatchdogDev)
	}
}

func TestLoadConfig_UIPort(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "ui-host"
ui_port: 9090
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.UIPort != 9090 {
		t.Errorf("UIPort = %d, want 9090", cfg.UIPort)
	}
}

func TestLoadConfig_UIPortDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "ui-default-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// UIPort defaults to 7445 in LoadConfig (centralized port defaults).
	if cfg.UIPort != 7445 {
		t.Errorf("default UIPort = %d, want 7445", cfg.UIPort)
	}
}

func TestLoadConfig_FullConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "full-host"
grpc_port: 9443
metrics_port: 9444
pki_dir: /opt/litevirt/pki
data_dir: /opt/litevirt/data
gossip_port: 8946
ui_port: 8080
dns_port: 5353
dns_domain: "cluster.local"
watchdog_dev: "/dev/watchdog0"
rest_port: 9446
join_peers:
  - "10.0.0.1:8946"
  - "10.0.0.2:8946"
pci:
  rescan_interval: "10m"
  udev_hook: true
  sriov:
    managed: true
    max_vfs_per_pf: 32
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.HostName != "full-host" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
	if cfg.GRPCPort != 9443 {
		t.Errorf("GRPCPort = %d", cfg.GRPCPort)
	}
	if cfg.MetricsPort != 9444 {
		t.Errorf("MetricsPort = %d", cfg.MetricsPort)
	}
	if cfg.PKIDir != "/opt/litevirt/pki" {
		t.Errorf("PKIDir = %q", cfg.PKIDir)
	}
	if cfg.DataDir != "/opt/litevirt/data" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.GossipPort != 8946 {
		t.Errorf("GossipPort = %d", cfg.GossipPort)
	}
	if cfg.UIPort != 8080 {
		t.Errorf("UIPort = %d", cfg.UIPort)
	}
	if cfg.DNSPort != 5353 {
		t.Errorf("DNSPort = %d", cfg.DNSPort)
	}
	if cfg.DNSDomain != "cluster.local" {
		t.Errorf("DNSDomain = %q", cfg.DNSDomain)
	}
	if cfg.WatchdogDev != "/dev/watchdog0" {
		t.Errorf("WatchdogDev = %q", cfg.WatchdogDev)
	}
	if cfg.RESTPort != 9446 {
		t.Errorf("RESTPort = %d", cfg.RESTPort)
	}
	if len(cfg.JoinPeers) != 2 {
		t.Errorf("JoinPeers count = %d, want 2", len(cfg.JoinPeers))
	}
	if cfg.PCI.RescanInterval != "10m" {
		t.Errorf("PCI.RescanInterval = %q", cfg.PCI.RescanInterval)
	}
	if !cfg.PCI.UdevHook {
		t.Error("PCI.UdevHook should be true")
	}
	if !cfg.PCI.SRIOV.Managed {
		t.Error("PCI.SRIOV.Managed should be true")
	}
	if cfg.PCI.SRIOV.MaxVFsPerPF != 32 {
		t.Errorf("PCI.SRIOV.MaxVFsPerPF = %d", cfg.PCI.SRIOV.MaxVFsPerPF)
	}
}

func TestLoadConfig_EmptyHostName(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: ""
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for empty host_name")
	}
	if !strings.Contains(err.Error(), "host_name is required") {
		t.Errorf("error = %q, should mention host_name", err.Error())
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for empty config file (no host_name)")
	}
	if !strings.Contains(err.Error(), "host_name is required") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestLoadConfig_JoinPeersEmpty(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "lonely-host"
join_peers: []
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.JoinPeers) != 0 {
		t.Errorf("JoinPeers = %v, want empty", cfg.JoinPeers)
	}
}

func TestLoadConfig_EnvOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.yaml")

	yaml := `host_name: "env-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HostName != "env-host" {
		t.Errorf("HostName = %q", cfg.HostName)
	}
}

func TestLoadConfig_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Only override some fields, rest should keep defaults
	yaml := `host_name: "partial-host"
grpc_port: 12345
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.GRPCPort != 12345 {
		t.Errorf("GRPCPort = %d, want 12345", cfg.GRPCPort)
	}
	// Non-overridden fields should have defaults
	if cfg.MetricsPort != 7444 {
		t.Errorf("MetricsPort = %d, want 7444 (default)", cfg.MetricsPort)
	}
	if cfg.GossipPort != 7946 {
		t.Errorf("GossipPort = %d, want 7946 (default)", cfg.GossipPort)
	}
	if cfg.PKIDir != "/etc/litevirt/pki" {
		t.Errorf("PKIDir = %q, want default", cfg.PKIDir)
	}
	if cfg.DataDir != "/var/lib/litevirt" {
		t.Errorf("DataDir = %q, want default", cfg.DataDir)
	}
	if cfg.DNSPort != 5354 {
		t.Errorf("DNSPort = %d, want 5354 (default)", cfg.DNSPort)
	}
	if cfg.DNSDomain != "litevirt.local" {
		t.Errorf("DNSDomain = %q, want default", cfg.DNSDomain)
	}
	if cfg.RESTPort != 7446 {
		t.Errorf("RESTPort = %d, want 7446 (default)", cfg.RESTPort)
	}
}

func TestLoadConfig_SRIOVDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "sriov-default-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.PCI.RescanInterval != "" {
		t.Errorf("PCI.RescanInterval = %q, want empty", cfg.PCI.RescanInterval)
	}
	if cfg.PCI.UdevHook {
		t.Error("PCI.UdevHook should default to false")
	}
	if cfg.PCI.SRIOV.Managed {
		t.Error("PCI.SRIOV.Managed should default to false")
	}
	if cfg.PCI.SRIOV.MaxVFsPerPF != 0 {
		t.Errorf("PCI.SRIOV.MaxVFsPerPF = %d, want 0", cfg.PCI.SRIOV.MaxVFsPerPF)
	}
}

func TestParsePCIRescanInterval_VariousDurations(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"10m", 10 * time.Minute},
		{"2h", 2 * time.Hour},
		{"100ms", 100 * time.Millisecond},
		{"1s", time.Second},
		{"500us", 500 * time.Microsecond},
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

func TestParsePCIRescanInterval_InvalidFormats(t *testing.T) {
	invalids := []string{
		"five minutes",
		"5minutes",
		"abc",
		"5",   // no unit
		"-5m", // negative
	}
	for _, val := range invalids {
		t.Run(val, func(t *testing.T) {
			d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: val}}}
			got := d.parsePCIRescanInterval()
			// Invalid formats (except "-5m" which Go parses as negative) should return 0
			// Note: Go's ParseDuration accepts negative durations and bare numbers with units
			if val == "-5m" {
				// Go parses this as -5*time.Minute, which is valid
				if got != -5*time.Minute {
					t.Errorf("parsePCIRescanInterval(%q) = %v", val, got)
				}
			} else {
				if got != 0 {
					t.Errorf("parsePCIRescanInterval(%q) = %v, want 0", val, got)
				}
			}
		})
	}
}

func TestConfigStruct_ZeroValue(t *testing.T) {
	cfg := Config{}
	if cfg.HostName != "" {
		t.Errorf("zero HostName = %q", cfg.HostName)
	}
	if cfg.GRPCPort != 0 {
		t.Errorf("zero GRPCPort = %d", cfg.GRPCPort)
	}
	if cfg.MetricsPort != 0 {
		t.Errorf("zero MetricsPort = %d", cfg.MetricsPort)
	}
	if len(cfg.JoinPeers) != 0 {
		t.Errorf("zero JoinPeers = %v", cfg.JoinPeers)
	}
	if cfg.PCI.UdevHook {
		t.Error("zero UdevHook should be false")
	}
	if cfg.PCI.SRIOV.Managed {
		t.Error("zero SRIOV.Managed should be false")
	}
}

func TestLoadConfig_MultipleJoinPeers(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "multi-peer-host"
join_peers:
  - "10.0.0.1:7946"
  - "10.0.0.2:7946"
  - "10.0.0.3:7946"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.JoinPeers) != 3 {
		t.Fatalf("JoinPeers count = %d, want 3", len(cfg.JoinPeers))
	}
	expected := []string{"10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.3:7946"}
	for i, peer := range cfg.JoinPeers {
		if peer != expected[i] {
			t.Errorf("JoinPeers[%d] = %q, want %q", i, peer, expected[i])
		}
	}
}

func TestLoadConfig_ErrorMessageContainsPath(t *testing.T) {
	t.Setenv("LITEVIRT_CONFIG", "/nonexistent/path/config.yaml")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "/nonexistent/path/config.yaml") {
		t.Errorf("error should mention file path: %v", err)
	}
}

func TestLoadConfig_InvalidYAMLErrorMessage(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("{{{{"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("error should mention 'parse config': %v", err)
	}
}

func TestDaemonStruct_FieldAssignment(t *testing.T) {
	cfg := &Config{HostName: "test"}
	d := &Daemon{cfg: cfg}
	if d.cfg.HostName != "test" {
		t.Errorf("cfg.HostName = %q", d.cfg.HostName)
	}
}
