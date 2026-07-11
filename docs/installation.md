# Installation

## Prerequisites

Each host needs:

- Linux (x86_64) with KVM support (`/dev/kvm` must exist)
- QEMU/KVM and libvirt installed (`apt install qemu-system-x86 libvirt-daemon-system`)
- `genisoimage` for cloud-init ISO generation
- SSH access (the CLI connects via SSH tunnel)

Optional:

- `haproxy` and `keepalived` for load balancing
- `socat` for HAProxy runtime API
- `conntrackd` for stateful SNAT failover (used when `snat: true` on load balancers)
- `nftables` for host isolation and SNAT rules
- IOMMU enabled in BIOS/kernel for PCI passthrough

## Build from source

```bash
git clone https://github.com/litevirt/litevirt.git
cd litevirt
make build
```

This produces a single static binary (no CGO, no runtime dependencies):

- `bin/litevirt` — the whole platform. `litevirt daemon` runs the server;
  `litevirt <cmd>` is the CLI; `litevirt schema-migrate <db>` pre-stages schema.
- `bin/lv` — a convenience symlink to `litevirt` (so `lv <cmd>` keeps working).

Requires Go 1.26+. Install Go from https://go.dev/dl/ if needed.

## Standalone single-node setup

The fastest way to get started — run everything on one machine:

```bash
sudo cp bin/litevirt /usr/local/bin/
sudo ln -sf /usr/local/bin/litevirt /usr/local/bin/lv
sudo litevirt host init --local --name node-1
sudo systemctl enable --now litevirt.service
```

This generates the PKI, installs dependencies (libvirt, QEMU), writes the config, and sets up the systemd unit — all locally, no SSH needed.

```bash
export LV_HOST=root@127.0.0.1
lv status
```

## Bootstrap a remote host

1. Copy the daemon binary to the host:

```bash
scp bin/litevirt root@10.0.50.10:/usr/local/bin/
```

2. Initialize the cluster from your workstation:

```bash
export LV_HOST=root@10.0.50.10
lv host init root@10.0.50.10 --name host-a
```

This generates the cluster PKI (CA + host certificate), creates `/etc/litevirt/config.yaml`, and installs a systemd unit.

3. SSH into the host and start the daemon:

```bash
ssh root@10.0.50.10
systemctl enable --now litevirt
```

4. Verify the cluster is running:

```bash
lv status
```

## Add hosts to the cluster

1. Copy the daemon binary:

```bash
scp bin/litevirt root@10.0.50.11:/usr/local/bin/
```

2. Add the host (this copies the CA cert and generates a host certificate):

```bash
lv host add root@10.0.50.11 --name host-b
```

3. Edit `/etc/litevirt/config.yaml` on the new host to set the join address:

```yaml
join_peers:
  - "10.0.50.10:7946"
```

4. Start the daemon:

```bash
ssh root@10.0.50.11
systemctl enable --now litevirt
```

5. Verify both hosts appear:

```bash
lv host ls
```

Repeat for each additional host.

## CLI setup

The `lv` binary connects to litevirtd over gRPC/mTLS. On a node with
`/etc/litevirt/config.yaml`, it connects to the local daemon automatically. For a
remote entry point, set the target host:

```bash
export LV_HOST=10.0.50.10
```

Or specify per-command:

```bash
lv --host 10.0.50.10 status
```

Any host in the cluster can serve as the entry point since state is replicated.
The CLI uses the client certificate bundle in `~/.config/litevirt/pki` by
default. `lv host init --local` creates this bundle for the installing user so a
single-node install does not require copying daemon certificates out of
`/etc/litevirt/pki`.

## Directory layout on hosts

```
/usr/local/bin/litevirt        # daemon binary
/etc/litevirt/config.yaml       # daemon configuration
/etc/litevirt/pki/              # TLS certificates
  ca.crt                        # cluster CA certificate
  ca.key                        # cluster CA private key (first host only)
  host.crt                      # this host's certificate
  host.key                      # this host's private key
~/.config/litevirt/pki/         # per-user CLI client bundle
  ca.crt
  client.crt
  client.key
/var/lib/litevirt/              # data directory
  images/                       # base VM images
  disks/                        # VM disk images
  state.db                      # local SQLite state store
```

## Upgrading

litevirt tracks the daemon version on each host. You can see which version every host is running with:

```bash
lv host ls
```

The VERSION column shows the build version of litevirt on each host. Hosts running older versions show their current version; hosts that haven't reported yet show `-`.

### How upgrades work

Upgrading litevirt is safe and non-disruptive:

- **Running VMs** are managed by libvirt/QEMU, not by litevirt directly. They survive daemon restarts without interruption (the systemd unit ships `KillMode=process`, which the daemon also self-checks at startup).
- **HAProxy** runs in its own session (via `setsid`) with PID files. The LB Manager re-discovers running instances on startup.
- **Keepalived** double-forks and reparents to init. VIPs remain assigned through daemon restarts.
- **Schema migrations** are applied automatically on daemon startup via `InitSchema()`. Each host creates its own tables/columns/indexes locally — DDL is not replicated across the cluster. The daemon refuses to start if the local DB has been forward-migrated by a newer binary (downgrade refusal via `schema_state.version`).
- **Pre-flight gate**: `lv host upgrade` runs `PreflightUpgrade` first and refuses on blocking conditions (in-flight migrations or backups, leader-lease holdings with pending fences, replication backlog, clock skew, witness-host risk). Pass `--force` to override.
- **`upgrading` host state**: the host marks itself `upgrading` in the cluster state before the binary swap. Failover coordinators on peer hosts skip fence candidacy for `upgrading` hosts, so the restart window can't trigger a destructive false-positive failover.
- **Automatic rollback**: if the new binary panic-loops past `StartLimitBurst=3` within 10 minutes (systemd's threshold), the `litevirt-rollback.service` companion unit fires, restores the previous binary from `litevirt.old`, and restarts. Operator sees a `litevirt-rollback` tagged entry in `journalctl`.
- **Cluster version-skew check**: peer Crescent handshakes carry the sender's schema version. Peers more than one minor version apart refuse to apply mutations from each other, so a runaway upgrade can't corrupt downstream replicas.

No drain is needed for typical upgrades. The upgrade flow per host is:
preflight gate → mark `upgrading` → copy binary → checksum → backup `.old`
→ atomic swap → re-exec via `syscall.Exec` (preserving PID for systemd) →
new daemon clears `upgrading` state on healthy startup.

### Scenario 1: Rolling upgrade from a workstation (recommended)

Build new binaries on your dev machine (or download a release), then push to all hosts with a single command:

```bash
# Build
make build

# Push to every host in the cluster
LV_HOST=root@10.0.50.10 lv host upgrade --binary ./bin/litevirt
```

The CLI connects to the cluster via SSH, lists all hosts, identifies which ones are outdated, and upgrades them sequentially. The connected host (10.0.50.10 in this example) is automatically upgraded **last** so the control-plane connection stays alive throughout.

You'll see a plan before anything happens:

```
Upgrade plan: 3 host(s) → v0.2.0

  HOST      ADDRESS       CURRENT     NOTE
  host-b    10.0.50.11    v0.1.0
  host-c    10.0.50.12    v0.1.0
  host-a    10.0.50.10    v0.1.0      (connected — upgraded last)

Proceed? [y/N]
```

To upgrade specific hosts only:

```bash
lv host upgrade --binary ./bin/litevirt host-b host-c
```

To skip the confirmation prompt (useful in scripts):

```bash
lv host upgrade --binary ./bin/litevirt --yes
```

### Scenario 2: Upgrade from a cluster node

If you're running `lv` directly on a cluster host (local mode, no `LV_HOST`), the workflow is similar but you first need to get the new binary onto that host:

```bash
# On your dev machine — copy the new binary to a cluster host
scp bin/litevirt root@10.0.50.10:/tmp/litevirt-new

# On the cluster host
lv host upgrade --binary /tmp/litevirt-new
```

The command detects that it's running on a cluster node and upgrades the local host last. The SSH session used for the self-upgrade is handled by sshd (not litevirt), so the copy-swap-restart sequence completes even though litevirt restarts underneath.

### Scenario 3: Manual single-host upgrade

If you prefer to upgrade hosts one at a time without the rolling upgrade command:

```bash
# Copy new binary to the host
scp bin/litevirt root@10.0.50.10:/usr/local/bin/litevirt.new

# SSH in and swap
ssh root@10.0.50.10
cp /usr/local/bin/litevirt /usr/local/bin/litevirt.old    # backup
mv /usr/local/bin/litevirt.new /usr/local/bin/litevirt
chmod 755 /usr/local/bin/litevirt
systemctl restart litevirt

# Verify
systemctl is-active litevirt
lv host ls   # check version column
```

If the new binary fails to start, roll back:

```bash
mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt
systemctl restart litevirt
```

### Scenario 4: Debian/Ubuntu packages (deb)

litevirt does not publish official `.deb` packages yet, but you can build your own for integration with `apt` and unattended-upgrades.

**Building a deb package:**

```bash
# Build the binary
make build

# Create the package structure
mkdir -p litevirt_0.2.0/DEBIAN
mkdir -p litevirt_0.2.0/usr/local/bin
mkdir -p litevirt_0.2.0/etc/systemd/system

cp bin/litevirt litevirt_0.2.0/usr/local/bin/

cat > litevirt_0.2.0/DEBIAN/control << 'EOF'
Package: litevirt
Version: 0.2.0
Architecture: amd64
Maintainer: your-team <team@example.com>
Depends: qemu-system-x86, libvirt-daemon-system, genisoimage
Recommends: haproxy, keepalived, socat
Description: litevirt hypervisor daemon
 Lightweight KVM/QEMU orchestrator with decentralized WAL-based replication.
EOF

cat > litevirt_0.2.0/DEBIAN/postinst << 'EOF'
#!/bin/bash
set -e
systemctl daemon-reload
# Restart only if already running (upgrade), don't start on fresh install.
if systemctl is-active --quiet litevirt; then
    systemctl restart litevirt
fi
EOF
chmod 755 litevirt_0.2.0/DEBIAN/postinst

dpkg-deb --build litevirt_0.2.0
```

**Installing/upgrading with dpkg:**

```bash
# Copy the deb to each host and install
scp litevirt_0.2.0.deb root@10.0.50.10:/tmp/
ssh root@10.0.50.10 dpkg -i /tmp/litevirt_0.2.0.deb
```

The `postinst` script restarts litevirt automatically if it was already running, so VMs continue uninterrupted.

**Hosting in a local apt repository:**

For larger clusters, host the `.deb` in an apt repository (using `reprepro`, Aptly, or a simple Nginx directory with `dpkg-scanpackages`). Then upgrade all hosts with your existing config management:

```bash
# On each host (or via Ansible/Salt/etc.)
apt update && apt install --only-upgrade litevirt
```

This integrates with standard Debian tooling: unattended-upgrades, apt pinning, version holds, and rollback via `apt install litevirt=0.1.0`.

### Rollback

The `lv host upgrade` command always backs up the old binary to
`/usr/local/bin/litevirt.old` before swapping. There are two rollback paths:

**Automatic:** If the new daemon panics on startup and systemd
restarts it past `StartLimitBurst` (3 restarts within 10 minutes), the
`litevirt-rollback.service` oneshot fires automatically:

1. Restores `litevirt.old` over `litevirt`.
2. Runs `systemctl reset-failed litevirt.service`.
3. Restarts the main service.
4. Logs the rollback to journal with `litevirt-rollback` tag.

This works without any operator action. Verify with:

```bash
journalctl -t litevirt-rollback
systemctl status litevirt
```

**Manual (anytime after a successful upgrade):**

```bash
ssh root@10.0.50.10
mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt
systemctl restart litevirt
```

### Mixed-version clusters

During a rolling upgrade, hosts temporarily run different versions. This is safe because:

- **WAL replication streams data mutations, not schema.** Each host applies its own DDL on startup.
- **Schema changes are always additive** (new columns, tables, indexes). Columns are never removed or renamed.
- **Schema-version pin**: the daemon refuses to start if the DB has been forward-migrated by a newer binary (`schema_state.version > CurrentSchemaVersion`). This catches the "old binary onto new DB" footgun.
- **Skew tolerance**: peer Crescent handshakes carry sender's `schema_version`. Peers more than 1 minor version apart refuse to apply mutations from each other (logged at WARN; surfaces in metrics).
- **Proto3 forward compat**: the gRPC API handles unknown fields gracefully in both directions, but the schema-skew check above provides the actual safety guarantee.

Recommended practice: keep version skew to one release within the cluster. The CLI's rolling-upgrade command sequences hosts serially so the skew window is bounded by your network bandwidth + restart time per host (typically a few minutes for the whole cluster).

## Uninstall

Remove litevirt from a host using the CLI:

```bash
# Remove host from cluster first (if cluster is still active)
lv host rm host-a --force

# Uninstall litevirt from the host
lv uninstall root@10.0.50.10 --confirmed
```

This stops the daemon, removes the binary, config, PKI certificates, systemd unit, and udev rules. By default it also deletes all VM data (images, disks). To keep VM data:

```bash
lv uninstall root@10.0.50.10 --confirmed --keep-data
```

To uninstall manually via SSH:

```bash
systemctl stop litevirt
systemctl disable litevirt
rm -f /etc/systemd/system/litevirt.service
rm -f /usr/local/bin/litevirt
rm -rf /etc/litevirt
rm -rf /var/lib/litevirt          # remove VM data
rm -f /etc/udev/rules.d/99-litevirt-pci.rules
systemctl daemon-reload
```
