# Configuration

The daemon reads its config from `/etc/litevirt/config.yaml` (override with `LITEVIRT_CONFIG` env var).

## Full reference

```yaml
# Required: unique name for this host in the cluster.
host_name: "host-a"

# gRPC API port (mTLS). CLI and inter-host communication.
grpc_port: 7443

# Prometheus metrics endpoint (HTTP, no auth).
metrics_port: 7444

# Address the /metrics endpoint listens on. Empty (default) binds all
# interfaces; set "127.0.0.1" to restrict it to localhost (scrape via a
# local exporter / SSH tunnel only).
metrics_bind: ""

# Web UI port (HTTP).
ui_port: 7445

# Address the web UI listens on. Defaults to 127.0.0.1 (localhost only)
# so the UI is unreachable from off-host without a reverse proxy or
# SSH tunnel. Set to 0.0.0.0 to expose directly — only do this behind
# a reverse proxy that terminates TLS.
ui_bind: "127.0.0.1"

# WebSocket Origin allowlist for the UI (host patterns). Empty (default)
# enforces strict same-origin checks on the console WebSocket; add entries
# when the UI is fronted by a proxy on a different host/port.
ui_allowed_origins: []

# REST API gateway port. Set to 0 to disable.
rest_port: 7446

# How often anti-entropy compares state digests with peers and full-syncs on
# drift. 0 = default (60s). Lower it (e.g. 10) on backup-critical clusters where
# faster drift detection is worth the extra digest traffic.
anti_entropy_interval_sec: 0

# Cluster membership port (used for peer discovery).
gossip_port: 7946

# Path to TLS certificates (CA, host cert/key).
pki_dir: "/etc/litevirt/pki"

# Data directory for images, disks, and SQLite state.
data_dir: "/var/lib/litevirt"

# DNS server port (UDP). Serves <vm>.<stack>.<domain> records.
dns_port: 5354

# DNS domain suffix for VM name resolution.
dns_domain: "litevirt.local"

# Kernel watchdog device for self-fencing. Empty string disables.
# When set, the daemon validates the device exists (and is a character device)
# at startup and REFUSES TO START if it's missing — otherwise a broken watchdog
# would only be discovered at fence time, when the node can no longer self-fence
# (split-brain risk). Override with LITEVIRT_UNSAFE_SKIP_WATCHDOG_CHECK=1.
watchdog_dev: ""

# Load-balancer VIP split-brain safety (see migration-failover.md).
# quorum_loss_demote_after_sec: sustained local quorum loss before an isolated
#   LB host stands its own VIPs down (must be > 0). Default 12.
# keepalived_stop_timeout_sec: how long the stand-down waits for keepalived to
#   confirm stopped before escalating (must be > 0). Default 3.
# no_quorum_vip_policy: how the majority reclaims a VIP whose holder can't be
#   reached or proven released. Only "safe" is accepted (empty → safe): reclaim
#   ONLY on a release proof, else leave the VIP down + alert (never a blind
#   takeover). A weaker takeover-without-proof tier is intentionally not
#   implemented; recover a dead unreachable holder with `lv host fence-confirm`.
quorum_loss_demote_after_sec: 12
keepalived_stop_timeout_sec: 3
no_quorum_vip_policy: safe

# Peers to join on startup. At least one existing host.
join_peers:
  - "10.0.50.10:7946"

# PCI device management.
pci:
  # How often to rescan PCI devices. "0" disables periodic rescan.
  rescan_interval: "5m"

  # Install udev rule for real-time PCI hotplug events.
  udev_hook: true

  # SR-IOV configuration.
  sriov:
    # false: operator creates VFs manually. true: litevirt manages VF lifecycle.
    managed: false
    # Maximum VFs per physical function (only when managed: true).
    max_vfs_per_pf: 8

# Host-level storage pools (created as libvirt pools on startup).
# See storage.md for driver details. Operators may also add pools at
# runtime via `lv pool create` — those land in the cluster's
# storage_pools table without editing this file.
storage_pools:
  - name: default
    driver: local                         # local | nfs | ceph | iscsi | zfs | btrfs | lvm-thin | dir
    target: /var/lib/litevirt/disks

  - name: shared-nfs
    driver: nfs
    source: "10.0.10.1:/exports/vms"
    target: /var/lib/litevirt/mounts/shared-nfs

  - name: ceph-pool
    driver: ceph
    source: "litevirt"
    options:
      id: admin
      conf: /etc/ceph/ceph.conf

# Split-brain-family enforcement kill-switches. Each is a per-node on/off for a
# hardening feature whose capability token the build advertises but does NOT enforce
# until you opt in. Enforcement = this flag AND the token's cluster-wide latch, so the
# flag is BOTH the enable and the kill switch: set it false + restart to disable,
# regardless of any durable latch (never delete marker files). All default false; a
# fresh deploy changes no behavior. Enable fleet-uniformly for lww_skew_guard (it
# changes merge behavior) and for vip_* enable the pair together.
enforcement:
  safe_fence_default: false   # a best-effort (unconfirmable) fence must carry an operator
                              # proof (`lv host fence-confirm`) before reschedule/promote
  lww_skew_guard: false       # quarantine an incoming LWW row >5 min future-skewed (future-skew only)
  vip_self_demote: false      # a minority node releases its VIPs on sustained quorum loss
  vip_proof_reclaim: false    # majority refuses a VIP takeover without a release/fence proof

# Authentication realms. The "local" realm is always present (bcrypt
# passwords in the cluster DB) and need not be listed here. OIDC and
# LDAP realms are loaded into a Registry at startup; `Login` dispatches
# by realm name. See docs/auth.md for the realm model.
auth:
  # Session lifetimes as Go duration strings. Empty = built-in defaults
  # (idle 8h / hard 7d). session_idle_timeout is the inactivity window
  # (refreshed on each request); session_hard_expiry is the absolute cap.
  session_idle_timeout: ""                # e.g. "8h"
  session_hard_expiry: ""                 # e.g. "168h" (7 days)
  # Strict mTLS identity: when true (and the strict_mtls_identity_v1 capability
  # is active cluster-wide), a bearerless "client" certificate (the distributable
  # CLI client cert, or any cert whose CN is not a live cluster host) is no longer
  # treated as admin — it must present a session bearer (`lv login`). Host/peer
  # certs and on-node loopback are unaffected. Default false. This flag is the
  # enforcement + kill switch. See docs/auth.md.
  strict_mtls_identity: false
  # Forwarded identity: when true (and the forwarded_identity_v1 capability is
  # active cluster-wide), the owning node re-authenticates a forwarded user's
  # bearer and runs RBAC + audit as the real user instead of the peer=admin
  # trusted-forward. Default false.
  forwarded_identity: false
  realms:
    - name: corp                          # realm short name; users login as alice@corp
      kind: oidc
      issuer_url: https://idp.corp/realms/main
      client_id: litevirt
      client_secret_file: /etc/litevirt/oidc-secret
      redirect_url: https://litevirt.corp/oidc/callback
      groups_claim: groups               # JWT claim that lists group memberships
    - name: ad
      kind: ldap
      url: ldaps://dc.corp:636
      bind_dn: CN=svc-litevirt,OU=Service,DC=corp,DC=local
      bind_password_file: /etc/litevirt/ad-bind-password
      user_base_dn: OU=Users,DC=corp,DC=local
      group_base_dn: OU=Groups,DC=corp,DC=local

# WebAuthn second-factor enrolment. Empty rp_id disables WebAuthn —
# the gRPC RPCs return Unimplemented and the UI's /account/2fa page
# stays TOTP-only. See docs/auth.md.
webauthn:
  rp_id: litevirt.corp                    # bare host operators reach via the UI
  rp_display_name: "Litevirt Cluster"     # shown in the browser prompt
  rp_origins:
    - https://litevirt.corp

# Backup repositories. Maps a logical repo name (referenced from
# compose `backup.repo:` and `lv backup schedule --repo`) to an
# on-disk path. The snapshot scheduler opens these locally; daemons
# not hosting backup data leave this empty. The /backups UI page
# also reads this map to render the configured-repos overview.
backup_repos:
  main: /srv/backup/main
  offsite: /mnt/dr/offsite

# Billing-event webhook. Empty disables (the default — events
# are dropped). When set, `internal/billing` POSTs JSON
# {kind, project, subject, vcpu, mem_mib, disk_gib, …, at} on every
# VM lifecycle transition. Fire-and-log: a slow webhook never blocks
# the caller; 5xx triggers exactly one retry. See docs/tenancy.md.
billing_webhook_url: ""

# Per-VM event store (vm_events) retention, enforced by a daily prune so the
# operational activity history (VM lifecycle + backup outcomes, surfaced on the
# VM detail page and via `lv events <vm>`) stays bounded. Each host prunes only
# its own rows. info/success events are kept retention_days; errors (rarer +
# higher-value, e.g. backup failures) are kept error_retention_days; each VM is
# capped at max_per_vm rows. 0 disables that sweep. Defaults shown.
vm_event_retention_days: 30
vm_event_error_retention_days: 90
vm_event_max_per_vm: 1000
vm_event_prune_hours: 24

# Post-upgrade health watchdog. After a self-upgrade re-exec, verify the NEW
# binary's local gRPC becomes pingable within the deadline; if not, roll back to
# the previous binary (.old) and exit so systemd restarts it. Catches a binary
# that starts but is non-functional (the gap systemd's crash-loop rollback
# misses). See docs/upgrades.md.
upgrade_watchdog_enabled: true        # false to disable (also LITEVIRT_UNSAFE_NO_UPGRADE_WATCHDOG=1)
upgrade_health_deadline_sec: 120      # 0 → 120s; widen for very slow N-step schema migrates

# Container host-loss relocation. When a host is fenced, the failover coordinator
# relocates its containers (on_host_failure != none), preferring a faithful
# restore from the latest backup (networking + non-image state) before falling
# back to recreate-from-image. container_restore_timeout_sec bounds how long a
# relocate-restore is treated as in-flight before giving up and image-recreating.
container_restore_timeout_sec: 600    # 0 → 600s (10m)

# ACME / autocert for the web UI cert (#13). When set, the daemon TERMINATES UI
# TLS itself (port 7445) using a cert from the configured ACME directory, with an
# internal-PKI fallback during issuance. Unset (default) = UI stays plain HTTP
# (e.g. behind a fronting proxy). HTTP-01 only — needs inbound :80 reachable from
# the CA. directory_url points at internal step-ca or Let's Encrypt.
acme:
  directory_url: ""                 # e.g. https://ca.internal/acme/acme/directory  (empty = disabled)
  email: "ops@example.com"
  domains: ["litevirt.example.com"] # SANs to request; must resolve to this host
  cache_dir: ""                     # default {data_dir}/acme

# Notifications (#5). Optional shortcut: seed a catch-all webhook target+route
# (min-severity warn) from config without using `lv notify` / the UI. Manage
# additional targets/routes (webhook, Slack) via `lv notify` or the /notifications
# page; they are CRDT-replicated cluster-wide.
notifications:
  default_webhook: ""               # e.g. https://hooks.slack.com/services/…  (empty = none)

# Telemetry: structured logging + distributed tracing over OTLP (see
# telemetry.md). Metrics stay on Prometheus (metrics_port) — this block does NOT
# touch them. Export is OFF until otlp_endpoint is set; with no endpoint the
# daemon logs locally and attaches no otel handler to any gRPC path (zero cost).
# The auth secret for the collector belongs in LITEVIRT_OTEL_HEADERS (env), not
# here. LITEVIRT_* env overrides win over these fields — including for DISABLING:
# clearing otlp_endpoint here does not turn export off while LITEVIRT_OTEL_ENDPOINT
# (or OTEL_EXPORTER_OTLP_ENDPOINT) is still set in the daemon's environment.
telemetry:
  otlp_endpoint: ""                 # OTLP HTTP endpoint URL, e.g. http://otel-collector:4318 (http://|https:// required; empty = export disabled)
  environment: ""                   # service.env label, e.g. "prod"/"homelab"
  # sample_rate: 1.0                # trace sampling 0.0–1.0; unset = library default (100%), 0 = disabled
  log_level: "INFO"                 # TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
  log_format: "console"             # json|console|pretty (default console; set json for structured export)

# Peer self-upgrade (auto-catch-up). A lagging daemon pulls a newer *released*
# binary from a healthy peer and re-execs, so a host that was down during a
# cluster upgrade converges on its own. Forward-only + release-only: it never
# downgrades, and never chases a dev / git-describe (`vX.Y.Z-N-gHASH`) build.
# See docs/self-upgrade-from-peer.md.
auto_upgrade:
  from_peer: true                   # default true (unset = on). Set false to PIN this
                                    # node's binary (e.g. hold a test build in place) —
                                    # it then upgrades only via `lv host upgrade`.
  interval_minutes: 5               # how often to check peers for a newer build; 0 → 5

# Image-pull bounds for URL pulls (`lv image pull <url>`). The block_* / blocked_cidrs
# deny policy is an OPT-IN SSRF guard (all default off). See "Image-pull controls".
max_image_bytes: 0                  # hard ceiling per pull/import, bytes; 0 → 64 GiB default
image_pull_timeout_sec: 0           # total wall-clock timeout for a pull; 0 → 30 min default
image_pull_block_metadata: false    # block link-local / cloud-metadata (169.254.0.0/16, IMDS)
image_pull_block_private: false     # block RFC1918 + loopback + CGNAT + ULA + link-local
image_pull_blocked_cidrs: []        # extra explicit CIDRs to block; an invalid CIDR fails startup

# Superseded-row garbage collection — an hourly, local, deterministic sweep that
# hard-deletes provably-inert rows past a retention floor. See "Garbage collection".
tombstone_gc_retention_hours: 0         # provably-inert rows (superseded set / stale LB gen); 0 → 24h
tombstone_gc_orphan_retention_hours: 0  # rows whose owning pointer/config is absent; 0 → 168h (7d)
```

## Minimal config

For a single-host setup, only `host_name` is required:

```yaml
host_name: "host-a"
```

All other fields use sensible defaults.

## Joining a cluster

Every host after the first needs `join_peers` pointing to at least one existing host:

```yaml
host_name: "host-b"
join_peers:
  - "10.0.50.10:7946"
```

Multiple peers can be listed for redundancy. The membership protocol discovers the remaining cluster members automatically, and state replication streams mutations to all peers via gRPC.

## Image-pull controls

URL-based image pulls (`lv image pull <url>`) are bounded by `max_image_bytes`
and `image_pull_timeout_sec`, plus an OPT-IN SSRF network deny policy
(`image_pull_block_metadata` / `image_pull_block_private` / `image_pull_blocked_cidrs`)
— all in the reference above. A pull's RESOLVED destination IP is rejected at
connect time if it falls in a blocked range, checked on every connection, so it is
DNS-rebinding- and redirect-safe. Notes:

- **Opt-in.** With no policy set (the default) pulls are unrestricted and honor
  `HTTP(S)_PROXY`. Recommended on cloud hosts: set `image_pull_block_metadata: true`
  so a hostile image URL can't reach the instance-metadata endpoint.
- **Direct-only when a policy is set.** Enabling any deny policy disables proxy use
  for pulls (a proxied request can't be validated against the post-proxy target);
  connections go direct so the resolved IP is always inspectable.
- **Scope.** The deny policy applies to **URL pulls only**. `lv image import` /
  `push` are streamed over gRPC (no outbound fetch) and are bounded only by
  `max_image_bytes`.
- An invalid CIDR in `image_pull_blocked_cidrs` **fails daemon startup** (a
  configured security policy is never silently dropped).

## Garbage collection

Re-enrolling 2FA recovery codes and recreating load balancers leave behind rows
that can never validate or render again (superseded recovery-code sets, stale LB
backend generations). An hourly per-node sweep hard-deletes them once they age
past a retention floor (`tombstone_gc_retention_hours` /
`tombstone_gc_orphan_retention_hours` in the reference above); the count is exported
as `litevirt_gc_rows_deleted_total` (labeled by `table`).

The sweep is local-only and deterministic (each node prunes its own copy; it
never touches a current-active-set or current-generation row), so it is safe on a
live cluster.

## Ports summary

| Setting | Default | Protocol | Purpose |
|---------|---------|----------|---------|
| `grpc_port` | 7443 | gRPC/mTLS | API (CLI, inter-host) |
| `metrics_port` | 7444 | HTTP | Prometheus `/metrics` |
| `ui_port` | 7445 | HTTP | Web dashboard |
| `rest_port` | 7446 | HTTP | REST API gateway |
| `gossip_port` | 7946 | TCP+UDP | Cluster membership |
| `dns_port` | 5354 | UDP | VM name DNS |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `LITEVIRT_CONFIG` | Override config file path |
| `LV_CONFIG_DIR` | CLI: override the per-user config directory (default `~/.config/litevirt`; holds the CLI cert and stored login credential) |
| `LV_HOST` | CLI: default remote gRPC/mTLS target (`host` or `host:port`; a legacy `user@host` prefix is ignored) |
| `LV_TOKEN` | CLI: bearer token to authenticate gRPC calls. Overrides the credential stored by `lv login`. |
| `LITEVIRT_UNSAFE_NO_KILLMODE_CHECK` | Skip startup `KillMode=process` self-check (development / non-systemd hosts only). Default check protects against unit-file regressions that would kill child QEMU processes on daemon stop. |
| `LITEVIRT_OTEL_ENDPOINT` | Telemetry: OTLP endpoint; turns logs+traces export on. Overrides `telemetry.otlp_endpoint`. |
| `LITEVIRT_OTEL_HEADERS` | Telemetry: OTLP headers, e.g. `Authorization=Basic <b64>` (collector auth — keep in env, not the config file). |
| `LITEVIRT_LOG_LEVEL` | Telemetry: log level `TRACE`\|`DEBUG`\|`INFO`\|`WARNING`\|`ERROR`\|`CRITICAL`. |
| `LITEVIRT_LOG_FORMAT` | Telemetry: log format `json`\|`console`\|`pretty`. |
| `LITEVIRT_TELEMETRY_ENV` / `LITEVIRT_TELEMETRY_SERVICE` / `LITEVIRT_TELEMETRY_VERSION` | Telemetry: `service.env` / `service.name` / `service.version` labels. |
| `LITEVIRT_TRACES_SAMPLE_RATE` | Telemetry: trace sample rate `0.0`–`1.0`. |
| `LITEVIRT_OTEL_TIMEOUT` / `LITEVIRT_OTEL_RETRIES` / `LITEVIRT_OTEL_BACKOFF` | Telemetry exporter resilience (seconds / count / seconds): bound the OTLP export calls so a slow collector can't stall the daemon. Fan out to logs + traces. Off by default. |
| `LITEVIRT_OTEL_FAIL_OPEN` | Telemetry: drop on export failure instead of blocking (`true`/`false`). Fans out to logs + traces. |
| `LITEVIRT_OTEL_SHUTDOWN_TIMEOUT` | Telemetry: drain cap (seconds) on daemon stop; logs signal only. |

See [telemetry.md](telemetry.md) for the full telemetry setup and an OpenObserve quick start.
