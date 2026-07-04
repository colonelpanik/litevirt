package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig_ImagePullDenyPolicy(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.yaml")
	t.Setenv("LITEVIRT_CONFIG", cp)

	// An invalid CIDR must FAIL load (never silently drop a security policy).
	if err := os.WriteFile(cp, []byte("host_name: h\nimage_pull_blocked_cidrs: [\"not-a-cidr\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted an invalid image_pull_blocked_cidrs")
	}

	// A valid policy loads and resolves to a non-empty, deduped prefix set.
	if err := os.WriteFile(cp, []byte("host_name: h\nimage_pull_block_metadata: true\nimage_pull_blocked_cidrs: [\"10.0.0.0/8\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig (valid policy): %v", err)
	}
	prefixes, err := cfg.ImagePullBlockedPrefixes()
	if err != nil {
		t.Fatalf("ImagePullBlockedPrefixes: %v", err)
	}
	if len(prefixes) < 2 { // at least 10.0.0.0/8 + the metadata set
		t.Errorf("expected resolved prefixes, got %v", prefixes)
	}

	// Default (no policy) → no prefixes (no network guard).
	if err := os.WriteFile(cp, []byte("host_name: h\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := cfg.ImagePullBlockedPrefixes(); len(p) != 0 {
		t.Errorf("default config produced a deny policy: %v", p)
	}
}

func TestLoadConfig_NoQuorumVIPPolicy(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.yaml")
	t.Setenv("LITEVIRT_CONFIG", cp)

	// Absent → defaults to "safe".
	if err := os.WriteFile(cp, []byte("host_name: h\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig (default): %v", err)
	}
	if cfg.NoQuorumVIPPolicy != "safe" {
		t.Errorf("default no_quorum_vip_policy = %q; want safe", cfg.NoQuorumVIPPolicy)
	}

	// Explicit empty string → normalized to "safe".
	if err := os.WriteFile(cp, []byte("host_name: h\nno_quorum_vip_policy: \"\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if cfg, err = LoadConfig(); err != nil || cfg.NoQuorumVIPPolicy != "safe" {
		t.Fatalf("empty policy: cfg=%q err=%v; want safe/nil", cfg.NoQuorumVIPPolicy, err)
	}

	// "safe" accepted.
	if err := os.WriteFile(cp, []byte("host_name: h\nno_quorum_vip_policy: safe\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("safe policy rejected: %v", err)
	}

	// The weaker tier is deliberately NOT implemented → LoadConfig must reject it loudly.
	if err := os.WriteFile(cp, []byte("host_name: h\nno_quorum_vip_policy: best-effort\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted no_quorum_vip_policy: best-effort (must reject — not implemented)")
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "test-host"
grpc_port: 9443
metrics_port: 9444
pki_dir: /tmp/pki
data_dir: /tmp/data
gossip_port: 8946
join_peers:
  - "10.0.50.10:8946"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.HostName != "test-host" {
		t.Errorf("HostName = %s, want test-host", cfg.HostName)
	}
	if cfg.GRPCPort != 9443 {
		t.Errorf("GRPCPort = %d, want 9443", cfg.GRPCPort)
	}
	if cfg.MetricsPort != 9444 {
		t.Errorf("MetricsPort = %d, want 9444", cfg.MetricsPort)
	}
	if cfg.PKIDir != "/tmp/pki" {
		t.Errorf("PKIDir = %s, want /tmp/pki", cfg.PKIDir)
	}
	if cfg.DataDir != "/tmp/data" {
		t.Errorf("DataDir = %s, want /tmp/data", cfg.DataDir)
	}
	if cfg.GossipPort != 8946 {
		t.Errorf("GossipPort = %d, want 8946", cfg.GossipPort)
	}
	if len(cfg.JoinPeers) != 1 || cfg.JoinPeers[0] != "10.0.50.10:8946" {
		t.Errorf("JoinPeers = %v", cfg.JoinPeers)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Only set required field
	yaml := `host_name: "minimal-host"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.GRPCPort != 7443 {
		t.Errorf("default GRPCPort = %d, want 7443", cfg.GRPCPort)
	}
	if cfg.MetricsPort != 7444 {
		t.Errorf("default MetricsPort = %d, want 7444", cfg.MetricsPort)
	}
	if cfg.PKIDir != "/etc/litevirt/pki" {
		t.Errorf("default PKIDir = %s", cfg.PKIDir)
	}
	if cfg.DataDir != "/var/lib/litevirt" {
		t.Errorf("default DataDir = %s", cfg.DataDir)
	}
	if cfg.GossipPort != 7946 {
		t.Errorf("default GossipPort = %d, want 7946", cfg.GossipPort)
	}
}

func TestLoadConfig_MissingHostName(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `grpc_port: 7443
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing host_name")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	t.Setenv("LITEVIRT_CONFIG", "/nonexistent/config.yaml")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("LITEVIRT_CONFIG", configPath)

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParsePCIRescanInterval_Disabled(t *testing.T) {
	for _, val := range []string{"", "0"} {
		d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: val}}}
		got := d.parsePCIRescanInterval()
		if got != 0 {
			t.Errorf("parsePCIRescanInterval(%q) = %v, want 0", val, got)
		}
	}
}

func TestParsePCIRescanInterval_Valid(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"1h", time.Hour},
	}
	for _, tt := range tests {
		d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: tt.value}}}
		got := d.parsePCIRescanInterval()
		if got != tt.want {
			t.Errorf("parsePCIRescanInterval(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestParsePCIRescanInterval_Invalid(t *testing.T) {
	d := &Daemon{cfg: &Config{PCI: PCIConfig{RescanInterval: "notaduration"}}}
	got := d.parsePCIRescanInterval()
	if got != 0 {
		t.Errorf("parsePCIRescanInterval(invalid) = %v, want 0", got)
	}
}

func TestLoadConfig_PCIConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yaml := `host_name: "pci-host"
pci:
  rescan_interval: "5m"
  udev_hook: true
  sriov:
    managed: true
    max_vfs_per_pf: 16
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", configPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.PCI.RescanInterval != "5m" {
		t.Errorf("RescanInterval = %q, want 5m", cfg.PCI.RescanInterval)
	}
	if !cfg.PCI.UdevHook {
		t.Error("UdevHook should be true")
	}
	if !cfg.PCI.SRIOV.Managed {
		t.Error("SRIOV.Managed should be true")
	}
	if cfg.PCI.SRIOV.MaxVFsPerPF != 16 {
		t.Errorf("MaxVFsPerPF = %d, want 16", cfg.PCI.SRIOV.MaxVFsPerPF)
	}
}
