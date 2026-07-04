package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/image"
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

	// Image-pull network deny policy (OPT-IN SSRF guard; all default off → no
	// blocking, env proxies honored). A pull's RESOLVED destination IP is rejected
	// at connect time if it falls in any of these ranges (see image.ParseBlockPolicy).
	// Applies to URL pulls only (ImageImport/Push are streamed, byte-ceiling only).
	ImagePullBlockedCIDRs  []string `yaml:"image_pull_blocked_cidrs,omitempty"`
	ImagePullBlockMetadata bool     `yaml:"image_pull_block_metadata,omitempty"` // 169.254/16 + IPv6 link-local + AWS IMDS
	ImagePullBlockPrivate  bool     `yaml:"image_pull_block_private,omitempty"`  // RFC1918 + loopback + CGNAT + ULA + link-local

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

	// Superseded-row GC retention. The core retention applies to provably-inert
	// rows (superseded recovery-code sets / stale LB generations); the longer
	// orphan retention applies to rows whose owning pointer/config is absent
	// (malformed-state cleanup). 0 → defaults (24h / 168h). An hourly local sweep
	// hard-deletes past these cutoffs (see corrosion.GCSupersededRows).
	TombstoneGCRetentionHours       int `yaml:"tombstone_gc_retention_hours"`
	TombstoneGCOrphanRetentionHours int `yaml:"tombstone_gc_orphan_retention_hours"`

	// Post-upgrade health watchdog: after a self-upgrade re-exec, an armed
	// watchdog verifies the NEW binary's local gRPC becomes pingable within
	// UpgradeHealthDeadlineSec; if not, it rolls back to the previous binary
	// (.old) and exits so systemd restarts the restored binary. Only catches
	// binary-INTRINSIC faults (gRPC never serves); systemd's OnFailure still
	// handles crash-loops. Enabled by default; deadline defaults to 120s (wide
	// enough for a slow N-step schema migrate). Override-disable for an
	// environment that swaps binaries out-of-band: LITEVIRT_UNSAFE_NO_UPGRADE_WATCHDOG=1.
	UpgradeWatchdogEnabled   bool `yaml:"upgrade_watchdog_enabled"`
	UpgradeHealthDeadlineSec int  `yaml:"upgrade_health_deadline_sec"`

	// ContainerRestoreTimeoutSec bounds how long the failover coordinator treats a
	// relocate-restore marker as "in flight" before deciding the restore stalled
	// and falling back to image-recreate. Default 600s (10m) — comfortably longer
	// than a real rootfs restore.
	ContainerRestoreTimeoutSec int `yaml:"container_restore_timeout_sec"`

	// Split-brain Phase 2 — minority VIP self-demotion. Both are seconds, consumed as
	// time.Duration. An isolated (quorum-lost) LB host drops its own VIP so keepalived
	// stops answering on the wrong side of a partition:
	//   - QuorumLossDemoteAfterSec: sustained quorum loss before the minority self-demotes.
	//   - KeepalivedStopTimeoutSec: how long DemoteAll waits for keepalived to confirm stopped
	//     (else it self-fences).
	// NOTE: majority-side RECLAIM is PROOF-gated, not timer-gated — the majority only
	// (re)claims a VIP after synchronously standing the removed holder down and proving
	// its keepalived is inert and the address released (see vipMoveRefused). So there is
	// no "wait N seconds then take over" timer in Phase 2, and thus no demote-vs-takeover
	// timing invariant to validate here. Reclaiming an UNREACHABLE holder (which can't
	// prove release) is deliberately deferred to Phase 5 fencing; a timer floor, if one
	// is ever needed, belongs there.
	QuorumLossDemoteAfterSec int `yaml:"quorum_loss_demote_after_sec"`
	KeepalivedStopTimeoutSec int `yaml:"keepalived_stop_timeout_sec"`

	// NoQuorumVIPPolicy selects how the MAJORITY reclaims a VIP whose holder can neither be
	// reached nor proven released. Only "safe" (the default) is accepted today:
	//   - "safe": reclaim ONLY on a release proof (a reachable/relayed VIPAssigned=false, or
	//     an operator manual-fence-confirm attesting the holder is down —
	//     `lv host fence-confirm <host>`). An unreachable, unproven holder leaves the VIP DOWN + HA-degraded —
	//     an outage, never a takeover. This upholds the core invariant (no proof ⇒ no new
	//     ownership; a safe gap beats overlap).
	// A weaker "best-effort" tier (timer-based takeover WITHOUT proof — availability over the
	// split-brain guarantee) is intentionally NOT implemented; it would reintroduce
	// dual-master risk. The supported availability-first recovery is the manual-fence-confirm
	// above, not a weaker policy. Empty → "safe".
	NoQuorumVIPPolicy string `yaml:"no_quorum_vip_policy"`

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

		UpgradeWatchdogEnabled:   true,
		UpgradeHealthDeadlineSec: 120,

		ContainerRestoreTimeoutSec: 600,

		QuorumLossDemoteAfterSec: 12,
		KeepalivedStopTimeoutSec: 3,
		NoQuorumVIPPolicy:        "safe",
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.HostName == "" {
		return nil, fmt.Errorf("host_name is required in config")
	}

	// (No demote-vs-takeover timing invariant: majority reclaim is proof-gated, not
	// timer-gated — see the QuorumLossDemoteAfterSec/KeepalivedStopTimeoutSec doc above.)
	if cfg.QuorumLossDemoteAfterSec <= 0 || cfg.KeepalivedStopTimeoutSec <= 0 {
		return nil, fmt.Errorf("invalid VIP self-demote timing: quorum_loss_demote_after(%ds) and keepalived_stop_timeout(%ds) must both be > 0",
			cfg.QuorumLossDemoteAfterSec, cfg.KeepalivedStopTimeoutSec)
	}

	// VIP no-quorum reclaim policy: only "safe" is supported today (empty → safe). A weaker
	// takeover-without-proof tier is intentionally not implemented (see the field doc), so
	// reject any other value loudly rather than silently ignoring a misconfigured policy.
	if cfg.NoQuorumVIPPolicy == "" {
		cfg.NoQuorumVIPPolicy = "safe"
	}
	if cfg.NoQuorumVIPPolicy != "safe" {
		return nil, fmt.Errorf("invalid no_quorum_vip_policy %q: only \"safe\" is supported "+
			"(a takeover-without-proof tier is intentionally not implemented; to recover an "+
			"unreachable VIP holder, verify it is down and run `lv host fence-confirm <host>`)",
			cfg.NoQuorumVIPPolicy)
	}

	// Validate the image-pull deny policy now so a bad CIDR fails load loudly
	// (never silently drop a configured security policy).
	if _, err := cfg.ImagePullBlockedPrefixes(); err != nil {
		return nil, fmt.Errorf("config image_pull_blocked_cidrs: %w", err)
	}

	return cfg, nil
}

// ImagePullBlockedPrefixes resolves the image-pull deny config (explicit CIDRs +
// the block_metadata/block_private convenience booleans) into a deduped prefix
// list. Empty when nothing is configured (the default → no network guard).
func (c *Config) ImagePullBlockedPrefixes() ([]netip.Prefix, error) {
	return image.ParseBlockPolicy(c.ImagePullBlockedCIDRs, c.ImagePullBlockMetadata, c.ImagePullBlockPrivate)
}
