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
| `LV_HOST` | CLI: default SSH target (`user@host`) |
| `LV_TOKEN` | CLI: bearer token to authenticate gRPC calls. Overrides the credential stored by `lv login`. |
| `LITEVIRT_UNSAFE_NO_KILLMODE_CHECK` | Skip startup `KillMode=process` self-check (development / non-systemd hosts only). Default check protects against unit-file regressions that would kill child QEMU processes on daemon stop. |
