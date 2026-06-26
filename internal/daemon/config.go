package daemon

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/auth"
)

const defaultConfigPath = "/etc/litevirt/config.yaml"

// Config holds litevirtd configuration.
type Config struct {
	HostName         string   `yaml:"host_name"`
	GRPCPort         int      `yaml:"grpc_port"`
	MetricsPort      int      `yaml:"metrics_port"`
	MetricsBind      string   `yaml:"metrics_bind"` // listen address for /metrics (default "" = all interfaces; set "127.0.0.1" to restrict)
	PKIDir           string   `yaml:"pki_dir"`
	DataDir          string   `yaml:"data_dir"`
	GossipPort       int      `yaml:"gossip_port"`
	JoinPeers        []string `yaml:"join_peers"`
	UIPort           int      `yaml:"ui_port"`
	UIBind           string   `yaml:"ui_bind"`            // listen address for web UI (default "127.0.0.1")
	UIAllowedOrigins []string `yaml:"ui_allowed_origins"` // WebSocket Origin allowlist (host patterns); empty = strict same-origin
	DNSPort          int      `yaml:"dns_port"`           // UDP port for embedded DNS (default 5354)
	DNSDomain        string   `yaml:"dns_domain"`         // base domain, e.g. "litevirt.local"
	WatchdogDev      string   `yaml:"watchdog_dev"`       // e.g. "/dev/watchdog"; empty = disabled
	RESTPort         int      `yaml:"rest_port"`          // HTTP REST gateway port (default 7446; 0 = disabled)

	// AntiEntropyIntervalSec is how often the anti-entropy loop compares state
	// digests with peers and full-syncs on drift. 0 = default (60s). Lower it
	// (e.g. 10) on backup-critical clusters where faster drift detection is
	// worth the extra digest traffic. (P2-2)
	AntiEntropyIntervalSec int `yaml:"anti_entropy_interval_sec"`

	// PCI device management
	PCI PCIConfig `yaml:"pci"`

	// Storage pools to ensure exist in libvirt on startup.
	// If empty, a default "litevirt" dir pool at {DataDir}/disks is created.
	StoragePools []StoragePoolConfig `yaml:"storage_pools"`

	// Auth holds multi-realm authentication config: which OIDC / LDAP
	// providers the daemon should accept Login requests against. The
	// "local" realm is always present and need not be listed.
	Auth AuthConfig `yaml:"auth"`

	// BackupRepos maps a logical repo name (referenced from compose
	// `vms.<name>.backup.repo:`) to an on-disk path the snapshot
	// scheduler opens via pbsstore.Open. Daemons not configured to
	// host backup data leave this empty; the scheduler then quietly
	// skips any VM whose backup.repo cannot be resolved locally.
	BackupRepos map[string]string `yaml:"backup_repos,omitempty"`

	// MaxImageBytes caps a single image pull/import (disk-fill guard);
	// ImagePullTimeoutSec bounds a pull's total wall time (SSRF/slowloris
	// guard). Zero on either falls back to the image package's defaults
	// (64 GiB / 30 min).
	MaxImageBytes       int64 `yaml:"max_image_bytes,omitempty"`
	ImagePullTimeoutSec int   `yaml:"image_pull_timeout_sec,omitempty"`

	// BillingWebhookURL receives JSON-formatted metered events from
	// internal/billing on every VM lifecycle transition. Empty
	// disables the emitter (NopEmitter).
	BillingWebhookURL string `yaml:"billing_webhook_url,omitempty"`

	// Per-VM event store (vm_events) retention, enforced by a daily prune.
	// Info/success events are kept VMEventRetentionDays; errors (rarer +
	// higher-value) are kept VMEventErrorRetentionDays; each VM is capped at
	// VMEventMaxPerVM rows. 0 disables that sweep. Defaults: 30 / 90 / 1000,
	// pruned every VMEventPruneHours (default 24).
	VMEventRetentionDays      int `yaml:"vm_event_retention_days"`
	VMEventErrorRetentionDays int `yaml:"vm_event_error_retention_days"`
	VMEventMaxPerVM           int `yaml:"vm_event_max_per_vm"`
	VMEventPruneHours         int `yaml:"vm_event_prune_hours"`

	// WebAuthn configures the second-factor enrolment dance. Required
	// fields: rp_id (the bare host operators reach via the UI, e.g.
	// "litevirt.corp") and rp_origins (full origins, e.g.
	// "https://litevirt.corp"). Empty rp_id disables WebAuthn entirely;
	// the gRPC RPCs return Unimplemented.
	WebAuthn WebAuthnConfig `yaml:"webauthn,omitempty"`

	// AutoUpgrade lets a lagging daemon pull a newer binary from a healthy peer
	// and self-upgrade — auto-catch-up for a host that was down during a cluster
	// upgrade and came back on its old binary. See docs/self-upgrade-from-peer.md.
	AutoUpgrade AutoUpgradeConfig `yaml:"auto_upgrade,omitempty"`

	// ACME auto-provisions a public TLS cert for the web UI (#13). When set, the
	// daemon terminates UI TLS itself via autocert; when unset the UI stays plain
	// HTTP (today's behavior, e.g. behind a fronting proxy).
	ACME ACMEConfig `yaml:"acme,omitempty"`

	// Notifications: operator alerting targets/routes (#5). The optional
	// DefaultWebhook seeds a catch-all webhook target without UI/CLI.
	Notifications NotificationsConfig `yaml:"notifications,omitempty"`

	// Version is set at startup from build-time ldflags (not from config file).
	Version string `yaml:"-"`
}

// ACMEConfig configures autocert for the web UI (#13). directory_url points at
// an ACME directory — internal step-ca (e.g.
// "https://ca.internal/acme/acme/directory") or Let's Encrypt. Empty
// directory_url or domains disables ACME (UI stays plain HTTP). HTTP-01 only
// (needs inbound :80 reachable from the CA).
type ACMEConfig struct {
	DirectoryURL string   `yaml:"directory_url,omitempty"`
	Email        string   `yaml:"email,omitempty"`
	Domains      []string `yaml:"domains,omitempty"`
	CacheDir     string   `yaml:"cache_dir,omitempty"` // default {DataDir}/acme
}

// Enabled reports whether ACME should run.
func (a ACMEConfig) Enabled() bool { return a.DirectoryURL != "" && len(a.Domains) > 0 }

// NotificationsConfig holds the optional default-webhook shortcut (#5).
type NotificationsConfig struct {
	DefaultWebhook string `yaml:"default_webhook,omitempty"`
}

// AutoUpgradeConfig controls peer self-upgrade. FromPeer is a pointer so an
// unset config defaults to ENABLED (nil = on); set `from_peer: false` to require
// manual `lv host upgrade`.
type AutoUpgradeConfig struct {
	FromPeer        *bool `yaml:"from_peer,omitempty"`
	IntervalMinutes int   `yaml:"interval_minutes,omitempty"` // 0 = default (5)
}

// FromPeerEnabled reports whether peer self-upgrade is on (default: yes).
func (a AutoUpgradeConfig) FromPeerEnabled() bool {
	return a.FromPeer == nil || *a.FromPeer
}

// Interval returns the self-upgrade check interval (default 5m).
func (a AutoUpgradeConfig) Interval() time.Duration {
	if a.IntervalMinutes <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(a.IntervalMinutes) * time.Minute
}

// AuthConfig is the YAML wrapper around auth.RealmConfig. We delegate
// to the auth package's typed struct so the YAML tags live next to
// the constructor logic.
type AuthConfig struct {
	Realms []auth.RealmConfig `yaml:"realms,omitempty"`
	// Session lifetimes as Go durations (e.g. "8h", "168h"). Empty = built-in
	// default (idle 8h / hard 7d). SessionHardExpiry is the absolute cap;
	// SessionIdleTimeout is the inactivity window, refreshed on each request.
	SessionIdleTimeout string `yaml:"session_idle_timeout,omitempty"`
	SessionHardExpiry  string `yaml:"session_hard_expiry,omitempty"`
}

// StoragePoolConfig defines a libvirt storage pool to create on daemon startup.
type StoragePoolConfig struct {
	Name    string            `yaml:"name"`
	Driver  string            `yaml:"driver"`  // local | nfs | ceph | iscsi
	Source  string            `yaml:"source"`  // driver-specific (NFS export, Ceph pool name, iSCSI IQN)
	Target  string            `yaml:"target"`  // local directory path (for local/nfs)
	Options map[string]string `yaml:"options"` // driver-specific options
}

// WebAuthnConfig is the YAML shape mirrored onto auth.WebAuthnConfig.
// Mirrored rather than aliased so config.yaml authors don't need to
// import the auth package's struct tags.
type WebAuthnConfig struct {
	RPDisplayName string   `yaml:"rp_display_name,omitempty"` // shown in the browser prompt
	RPID          string   `yaml:"rp_id,omitempty"`           // bare host (no scheme)
	RPOrigins     []string `yaml:"rp_origins,omitempty"`      // full origins ("https://…")
}

// PCIConfig holds PCI device management settings.
type PCIConfig struct {
	RescanInterval string      `yaml:"rescan_interval"` // "0" = off, "5m" = every 5 min
	UdevHook       bool        `yaml:"udev_hook"`       // install udev rule for real-time events
	SRIOV          SRIOVConfig `yaml:"sriov"`
}

// SRIOVConfig holds SR-IOV settings.
type SRIOVConfig struct {
	Managed     bool `yaml:"managed"`        // false = operator creates VFs; true = litevirtd manages
	MaxVFsPerPF int  `yaml:"max_vfs_per_pf"` // only used when managed=true (default 8)
}

// LoadConfig reads the daemon config from file.
func LoadConfig() (*Config, error) {
	path := defaultConfigPath
	if p := os.Getenv("LITEVIRT_CONFIG"); p != "" {
		path = p
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{
		GRPCPort:    7443,
		MetricsPort: 7444,
		PKIDir:      "/etc/litevirt/pki",
		DataDir:     "/var/lib/litevirt",
		GossipPort:  7946,
		DNSPort:     5354,
		DNSDomain:   "litevirt.local",
		RESTPort:    7446,
		UIPort:      7445,
		UIBind:      "127.0.0.1",

		VMEventRetentionDays:      30,
		VMEventErrorRetentionDays: 90,
		VMEventMaxPerVM:           1000,
		VMEventPruneHours:         24,
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.HostName == "" {
		return nil, fmt.Errorf("host_name is required in config")
	}

	return cfg, nil
}
