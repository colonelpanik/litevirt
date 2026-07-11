package daemon

import (
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/obs"
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

	// Enforcement holds the per-node kill-switches for split-brain-family
	// capability tokens. Each is the enforcement AND kill switch: enforcement is
	// this flag AND the token's cluster-wide capability latch, so false disables
	// the behavior regardless of any durable latch marker (flag=false + restart is
	// the only stand-down — never delete marker files). All default false; the
	// build still ADVERTISES the tokens (capabilities.supported) so the cluster can
	// latch, but nothing enforces until the operator opts in. (The strict-mTLS /
	// forwarded-identity switches live under Auth for historical reasons.)
	Enforcement EnforcementConfig `yaml:"enforcement"`

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

	// Telemetry configures structured logging + distributed tracing via
	// provide-telemetry. With no otlp_endpoint the daemon logs locally and traces
	// are no-ops; set otlp_endpoint to export logs + traces to a collector.
	// Metrics stay on Prometheus (/metrics) — obs never exports OTLP metrics.
	// PROVIDE_*/OTEL_* env vars override these fields.
	Telemetry TelemetryConfig `yaml:"telemetry,omitempty"`

	// Version is set at startup from build-time ldflags (not from config file).
	Version string `yaml:"-"`
}

// TelemetryConfig maps litevirt's daemon config onto the provide-telemetry
// environment contract (see internal/obs). Every field is optional; an empty
// OTLPEndpoint leaves OTLP export off (local structured logging only).
type TelemetryConfig struct {
	OTLPEndpoint string  `yaml:"otlp_endpoint,omitempty"` // OTLP HTTP endpoint URL, e.g. "http://otel-collector:4318"; http://|https://, no URL userinfo (use LITEVIRT_OTEL_HEADERS for auth); empty = export disabled
	Environment  string  `yaml:"environment,omitempty"`   // deployment env label, e.g. "prod"/"homelab"
	SampleRate   *float64 `yaml:"sample_rate,omitempty"`  // trace sample rate 0.0–1.0; unset = library default (100%), 0 = disabled (0%)
	LogLevel     string  `yaml:"log_level,omitempty"`     // TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL (default INFO; note WARNING, not WARN)
	LogFormat    string  `yaml:"log_format,omitempty"`    // json|console|pretty (default console — human text; set json for structured export)
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
	// StrictMTLSIdentity, when true, enforces the strict mTLS-identity model on
	// this node: a bearerless "client" certificate (a distributable lv-cli cert,
	// or any cert whose CN is not a live cluster host) is no longer treated as
	// admin and must present a session bearer (run `lv login`). Peer (known-host)
	// and on-node loopback certs are unaffected. Default false; enforcement also
	// requires the StrictMTLSIdentityV1 capability active cluster-wide. This flag
	// is the enforcement + kill switch — set false to disable regardless of latch.
	StrictMTLSIdentity bool `yaml:"strict_mtls_identity,omitempty"`
	// ForwardedIdentity, when true, makes this node (as the owner of a resource)
	// re-authenticate the forwarded user's session bearer relayed by the entry
	// node and run RBAC + audit as the real user, instead of the peer=admin
	// trusted-forward. Send-side propagation is always on; this flag + the
	// ForwardedIdentityV1 capability active cluster-wide gate the owner-side
	// promotion. Default false; the flag is the enforcement + kill switch.
	ForwardedIdentity bool `yaml:"forwarded_identity,omitempty"`
}

// EnforcementConfig holds the per-node kill-switches for the split-brain-family
// capability tokens. Each is `flag && capability` (the strict-mTLS pattern): the
// flag is authoritative for enforcement AND recovery, so false disables the
// behavior regardless of the durable latch. All default false.
type EnforcementConfig struct {
	// SafeFenceDefault: a best-effort (unconfirmable) fence must carry an operator
	// proof-of-power-off before the coordinator reschedules/promotes off the host
	// (capabilities.SafeFenceDefaultV1). Best-effort-fenced hosts then need
	// `lv host fence-confirm` (or the per-host unsafe-auto-failover opt-out label)
	// to auto-recover.
	SafeFenceDefault bool `yaml:"safe_fence_default,omitempty"`
	// LWWSkewGuard: quarantine an incoming LWW row whose updated_at is >5 min into
	// the future when the local copy is not (capabilities.LWWSkewGuardV1). Future-
	// skew only — the backward-clock case is a separate, deferred token. Changes
	// merge behavior, so enable fleet-uniformly.
	LWWSkewGuard bool `yaml:"lww_skew_guard,omitempty"`
	// VIPSelfDemote: on sustained local quorum loss, a minority node stops
	// keepalived + releases its VIPs so it can't serve a VIP the majority may bring
	// up (capabilities.VIPDemoteV1).
	VIPSelfDemote bool `yaml:"vip_self_demote,omitempty"`
	// VIPProofReclaim: the majority refuses a VIP move/claim until the prior holder
	// is proven released (break-before-make), gating majority-side reclaim on a
	// release/fence proof (capabilities.VIPReleaseProbeV1). Named for the behavior
	// it gates, not the release-probe RPC (which still serves when this is off).
	VIPProofReclaim bool `yaml:"vip_proof_reclaim,omitempty"`
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

	// Normalize the telemetry block. A bad value (typo'd log_level, wrong endpoint
	// scheme) must NOT block boot: telemetry is fail-open by contract (see
	// internal/obs), and a live node re-execing an in-place upgrade must not be
	// bricked by an unrelated telemetry typo. So warn loudly and degrade the
	// offending field to its safe default instead of failing load.
	normalizeTelemetry(&cfg.Telemetry)

	return cfg, nil
}

// normalizeTelemetry canonicalizes the telemetry block and neutralizes invalid
// values so a typo never blocks daemon boot (telemetry is fail-open; see
// internal/obs). Accepted sets mirror provide-telemetry's own validators: the
// log level is WARNING (not WARN), and the OTLP endpoint is HTTP and needs an
// http://|https:// scheme. Each rejected value is logged and reset to the
// library default — or, for the endpoint, cleared to disable OTLP export.
func normalizeTelemetry(t *TelemetryConfig) {
	// nil = unset = library default (100%); a set value including 0 (disabled) is
	// honored. NaN must be caught explicitly: NaN<0 and NaN>1 are BOTH false, so a
	// bare range check would let a NaN slip through unwarned. Degrade a bad value to
	// nil (library default), not 0 — 0 is a valid "disable sampling" request.
	if t.SampleRate != nil {
		if r := *t.SampleRate; math.IsNaN(r) || r < 0 || r > 1 {
			slog.Warn("config telemetry: sample_rate out of range — ignoring, using library default",
				"sample_rate", r, "valid_range", "0.0-1.0")
			t.SampleRate = nil
		}
	}
	if t.LogLevel != "" {
		lvl := strings.ToUpper(t.LogLevel)
		switch lvl {
		case "TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL":
			t.LogLevel = lvl
		default:
			slog.Warn("config telemetry: invalid log_level — ignoring, using default INFO",
				"log_level", t.LogLevel, "valid", "TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL (note WARNING, not WARN)")
			t.LogLevel = ""
		}
	}
	if t.LogFormat != "" {
		f := strings.ToLower(t.LogFormat)
		switch f {
		case "json", "console", "pretty":
			t.LogFormat = f
		default:
			slog.Warn("config telemetry: invalid log_format — ignoring, using default",
				"log_format", t.LogFormat, "valid", "json|console|pretty")
			t.LogFormat = ""
		}
	}
	if t.OTLPEndpoint != "" {
		// Redact userinfo in warn logs even when rejecting — a password in the
		// URL must never hit journald. Auth belongs in LITEVIRT_OTEL_HEADERS.
		logEP := obs.SafeEndpointForLog(t.OTLPEndpoint)
		switch u, err := url.Parse(t.OTLPEndpoint); {
		case err != nil:
			slog.Warn("config telemetry: otlp_endpoint is not a valid URL — disabling OTLP export",
				"otlp_endpoint", logEP, "error", err)
			t.OTLPEndpoint = ""
		case u.Scheme != "http" && u.Scheme != "https":
			slog.Warn("config telemetry: otlp_endpoint must use http:// or https:// (OTLP is HTTP, not gRPC) — disabling OTLP export",
				"otlp_endpoint", logEP, "scheme", u.Scheme)
			t.OTLPEndpoint = ""
		case u.Host == "":
			slog.Warn("config telemetry: otlp_endpoint must include a host:port — disabling OTLP export",
				"otlp_endpoint", logEP)
			t.OTLPEndpoint = ""
		case u.User != nil:
			slog.Warn("config telemetry: otlp_endpoint must not embed credentials (userinfo) — use LITEVIRT_OTEL_HEADERS; disabling OTLP export",
				"otlp_endpoint", logEP)
			t.OTLPEndpoint = ""
		}
	}
}

// ImagePullBlockedPrefixes resolves the image-pull deny config (explicit CIDRs +
// the block_metadata/block_private convenience booleans) into a deduped prefix
// list. Empty when nothing is configured (the default → no network guard).
func (c *Config) ImagePullBlockedPrefixes() ([]netip.Prefix, error) {
	return image.ParseBlockPolicy(c.ImagePullBlockedCIDRs, c.ImagePullBlockMetadata, c.ImagePullBlockPrivate)
}
