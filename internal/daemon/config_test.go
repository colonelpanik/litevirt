package daemon

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
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

// TestLoadConfig_AdvertiseAddress: the key parses, and its absence leaves the
// field empty so the daemon falls back to auto-detection (the pre-existing
// single-homed behaviour).
func TestLoadConfig_AdvertiseAddress(t *testing.T) {
	write := func(t *testing.T, yaml string) Config {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("LITEVIRT_CONFIG", path)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		return *cfg
	}

	cfg := write(t, "host_name: \"h\"\nadvertise_address: \"10.77.0.11\"\n")
	if cfg.AdvertiseAddress != "10.77.0.11" {
		t.Errorf("AdvertiseAddress = %q, want 10.77.0.11", cfg.AdvertiseAddress)
	}

	// Omitted ⇒ empty ⇒ auto-detect. A non-empty default would silently pin
	// every existing single-homed deployment to one heuristic.
	cfg = write(t, "host_name: \"h\"\n")
	if cfg.AdvertiseAddress != "" {
		t.Errorf("AdvertiseAddress = %q with the key omitted, want empty (auto-detect)", cfg.AdvertiseAddress)
	}
}

// TestLoadConfig_AdvertiseAddressRejectsUndialable: advertise_address is the
// address peers dial AND the address gossip announces, so a value the transport
// cannot carry does not degrade gracefully — it makes every peer probe fail and
// the failure detector fences a host that was never down. Refuse to boot instead.
//
// IPv6 is the specific trap: memberlist ACCEPTS a v6 advertise address while
// gossip and gRPC stay bound to 0.0.0.0, so the daemon comes up looking fine and
// then gets fenced. It must be rejected here, not discovered in production.
func TestLoadConfig_AdvertiseAddressRejectsUndialable(t *testing.T) {
	load := func(t *testing.T, value string) (*Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		body := "host_name: \"h\"\nadvertise_address: " + strconv.Quote(value) + "\n"
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("LITEVIRT_CONFIG", path)
		return LoadConfig()
	}

	for _, c := range []struct {
		name, value, wantErrSubstr string
	}{
		{"ipv6 global", "2001:db8::1", "IPv6 is not supported"},
		{"ipv6 ula", "fd00::1", "IPv6 is not supported"},
		{"ipv6 loopback", "::1", "IPv6 is not supported"},
		{"ipv6 link-local with zone", "fe80::1%eth0", "IPv6 is not supported"},
		{"bracketed ipv6", "[2001:db8::1]", "bare IPv4 literal"},
		{"ipv4 with port", "10.77.0.11:7443", "bare IPv4 literal"},
		{"hostname", "node-b.example.com", "bare IPv4 literal"},
		{"cidr", "10.77.0.11/24", "bare IPv4 literal"},
		{"garbage", "not-an-address", "bare IPv4 literal"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, c.value)
			if err == nil {
				t.Fatalf("LoadConfig accepted advertise_address %q; want a load error — "+
					"an undialable advertise address fences healthy hosts", c.value)
			}
			if !strings.Contains(err.Error(), c.wantErrSubstr) {
				t.Errorf("error = %q, want it to contain %q so the operator knows what to write",
					err, c.wantErrSubstr)
			}
		})
	}

	for _, c := range []struct{ name, value, want string }{
		{"plain ipv4", "10.77.0.11", "10.77.0.11"},
		// Canonicalized: hosts.address, the gossip advertise address and the cert
		// SAN must all agree on one spelling or every dial fails SAN verification.
		{"v4-mapped v6 is canonicalized to dotted quad", "::ffff:10.77.0.11", "10.77.0.11"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := load(t, c.value)
			if err != nil {
				t.Fatalf("LoadConfig(%q): %v", c.value, err)
			}
			if cfg.AdvertiseAddress != c.want {
				t.Errorf("AdvertiseAddress = %q, want %q", cfg.AdvertiseAddress, c.want)
			}
		})
	}
}

// TestHostAddress_PrefersAdvertiseAddress: the host record a daemon
// self-registers must use the configured advertise address, because that is the
// address peers dial AND the same value gossip advertises. If this fell back to
// getOutboundIP while gossip used the configured value (or vice versa), peers
// would dial an address the host certificate does not cover.
func TestHostAddress_PrefersAdvertiseAddress(t *testing.T) {
	d := &Daemon{cfg: &Config{AdvertiseAddress: "10.77.0.11"}}
	if got := d.hostAddress(); got != "10.77.0.11" {
		t.Fatalf("hostAddress() = %q, want the configured advertise address 10.77.0.11", got)
	}

	// Unset ⇒ fall back to auto-detection. Assert only that it does NOT return
	// the configured-address sentinel and is non-empty: the detected value
	// depends on the host's routing table.
	d = &Daemon{cfg: &Config{}}
	got := d.hostAddress()
	if got == "" {
		t.Fatal("hostAddress() is empty with no advertise address; auto-detect must still yield something")
	}
	if got == "10.77.0.11" {
		t.Fatalf("hostAddress() = %q with no advertise address configured — value leaked from config", got)
	}
}

// A partially set capacity block must inherit built-in defaults for every
// unset field — not silently zero the host reserves (which would offer guests
// 100% of RAM, the exact outage the capacity subsystem exists to prevent).
func TestCapacityConfigPolicy_PartialBlockKeepsReserveDefaults(t *testing.T) {
	want := corrosion.DefaultCapacityPolicy()
	want.CPUOvercommit = 5.0
	if got := (CapacityConfig{CPUOvercommitRatio: 5.0}).Policy(); got != want {
		t.Errorf("Policy() = %+v, want %+v (defaults for every unset field)", got, want)
	}
}

// A fully unset capacity block yields exactly the built-in defaults.
func TestCapacityConfigPolicy_EmptyBlockIsDefaults(t *testing.T) {
	if got, want := (CapacityConfig{}).Policy(), corrosion.DefaultCapacityPolicy(); got != want {
		t.Errorf("Policy() = %+v, want %+v", got, want)
	}
}
