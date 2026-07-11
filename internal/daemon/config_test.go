package daemon

import (
	"math"
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

// normalizeTelemetry never errors — it is fail-open. Valid values are
// canonicalized; invalid values are degraded to their safe default (empty
// level/format, 0 sample rate, cleared endpoint) so a typo can never block boot.
func TestNormalizeTelemetry(t *testing.T) {
	cases := []struct {
		name string
		in   TelemetryConfig
		want TelemetryConfig // expected state after normalize
	}{
		{name: "empty ok", in: TelemetryConfig{}, want: TelemetryConfig{}},
		{
			name: "valid full canonicalized",
			in:   TelemetryConfig{OTLPEndpoint: "http://c:4318", LogLevel: "info", LogFormat: "JSON"},
			want: TelemetryConfig{OTLPEndpoint: "http://c:4318", LogLevel: "INFO", LogFormat: "json"},
		},
		{name: "WARN degraded (must be WARNING)", in: TelemetryConfig{LogLevel: "WARN"}, want: TelemetryConfig{LogLevel: ""}},
		{name: "warning canonicalized", in: TelemetryConfig{LogLevel: "warning"}, want: TelemetryConfig{LogLevel: "WARNING"}},
		{name: "bad format degraded", in: TelemetryConfig{LogFormat: "yaml"}, want: TelemetryConfig{LogFormat: ""}},
		{name: "pretty canonicalized", in: TelemetryConfig{LogFormat: "pretty"}, want: TelemetryConfig{LogFormat: "pretty"}},
		{name: "gRPC scheme endpoint disabled", in: TelemetryConfig{OTLPEndpoint: "grpc://c:4317"}, want: TelemetryConfig{OTLPEndpoint: ""}},
		{name: "no-scheme endpoint disabled", in: TelemetryConfig{OTLPEndpoint: "otel-collector:4317"}, want: TelemetryConfig{OTLPEndpoint: ""}},
		{name: "no-host endpoint disabled", in: TelemetryConfig{OTLPEndpoint: "http://"}, want: TelemetryConfig{OTLPEndpoint: ""}},
		{name: "userinfo endpoint disabled", in: TelemetryConfig{OTLPEndpoint: "http://u:p@c:4318"}, want: TelemetryConfig{OTLPEndpoint: ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			normalizeTelemetry(&got)
			if got != c.want {
				t.Errorf("normalizeTelemetry(%+v) = %+v; want %+v", c.in, got, c.want)
			}
		})
	}
}

func f64(v float64) *float64 { return &v }

// sample_rate is a tristate: nil (unset) = library default (100%); a valid value
// INCLUDING 0 (disable sampling) is honored; an out-of-range/NaN value degrades to
// nil (library default), never to 0 — 0 is a legitimate "off" request.
func TestNormalizeTelemetry_SampleRate(t *testing.T) {
	cases := []struct {
		name    string
		in      *float64
		wantNil bool
		wantVal float64
	}{
		{"nil = library default", nil, true, 0},
		{"valid 0.5 kept", f64(0.5), false, 0.5},
		{"zero kept (disabled, not treated as unset)", f64(0), false, 0},
		{"one kept", f64(1), false, 1},
		{"too high -> default", f64(1.5), true, 0},
		{"negative -> default", f64(-0.1), true, 0},
		{"NaN -> default", f64(math.NaN()), true, 0},
		{"+Inf -> default", f64(math.Inf(1)), true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := TelemetryConfig{SampleRate: c.in}
			normalizeTelemetry(&tc)
			if c.wantNil {
				if tc.SampleRate != nil {
					t.Errorf("SampleRate = %v; want nil (degraded to library default)", *tc.SampleRate)
				}
				return
			}
			if tc.SampleRate == nil {
				t.Fatalf("SampleRate = nil; want %v", c.wantVal)
			}
			if *tc.SampleRate != c.wantVal {
				t.Errorf("SampleRate = %v; want %v", *tc.SampleRate, c.wantVal)
			}
		})
	}
}
