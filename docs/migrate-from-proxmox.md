# Migrating from Proxmox VE to litevirt

This guide walks an operator from a running Proxmox VE 9.x cluster to
litevirt 1.0 — single host first, then incrementally cut over the
rest. Read alongside the per-feature docs in `docs/`.

## Audience

You have:

- A working PVE 9.x cluster of two or more hosts (Debian-based).
- Root SSH to every host.
- A pilot workload (one VM, one container) you can move first.
- Spare storage on at least one host — enough to hold one VM's disk
  while it migrates.

You want:

- A no-data-loss path off Proxmox onto litevirt.
- Parity for every PVE feature you're using today.
- Rollback if something breaks.

## What ports across as-is

| Proxmox feature | litevirt equivalent | Notes |
|---|---|---|
| KVM/QEMU VMs | first-class | qcow2 disks copy as-is; libvirt domain XML auto-generated |
| LXC containers | first-class | rootfs reuses your PVE volume; no re-provision needed |
| Bridges + VLANs | networks (`bridge`, `vxlan`, `isolated`, `sriov`, `direct`) | declarative in compose; a VLAN is a `vlan:` tag on a network, not its own type |
| HA + fencing (HA-Manager) | quorum-based failover | IPMI / SSH / watchdog / manual fencing — wider matrix than HA-Manager |
| ZFS / BTRFS / LVM-thin storage | per-driver storage | use `driver: zfs/btrfs/lvm-thin` in compose |
| Ceph RBD | `driver: ceph` | `lv host ceph init` deploys via cephadm — same hyperconverged shape as PVE |
| PBS-equivalent backup | `lv backup repo` + `lv backup snapshot` | BLAKE3 chunks + dirty-bitmap incremental + AES-256-GCM |
| Cluster firewall | distributed firewall | `pve-firewall.fw` rules → `security-groups:` in compose |
| OIDC / LDAP / TOTP | realms + 2FA | OIDC code flow; LDAP search-then-bind |
| Live migration | `lv migrate <vm> <host>` | qemu native; storage replicated via `lv replicate-volume` |
| Live storage motion | `lv move-volume` | libvirt blockdev-mirror, no downtime |

## What's different (intentionally)

- **No `/etc/pve` mesh filesystem.** Cluster state lives in CRDT
  (Crescent/Corrosion); there's no shared posix dir. `lv` reads
  cluster state from any node.
- **No webGUI for everything.** litevirt's UI is read-mostly today —
  list views for security groups, containers, and backups ship; most
  mutation flows through `lv …` CLI or compose YAML. Both are
  GitOps-friendly.
- **Compose YAML is the source of truth.** PVE's imperative
  per-VM `qm set` lives in shell history; compose lives in git.
- **Decentralised by design.** No primary node election. `lv`
  connects to whichever host is reachable.

## Step 1 — Bootstrap a litevirt host alongside PVE

Pick one PVE host that has spare CPU + RAM headroom. We'll install
litevirt on it without disturbing the running PVE stack.

```bash
# On the chosen host:
sudo apt install -y qemu-system-x86 libvirt-daemon-system bridge-utils
curl -L https://litevirt.example/dl/litevirt-1.0 -o /usr/local/bin/litevirt
sudo chmod +x /usr/local/bin/litevirt
sudo ln -sf /usr/local/bin/litevirt /usr/local/bin/lv   # `lv` is a symlink to the single binary

# Initialise cluster state on this host (port 7443):
sudo litevirt host init --local --name pilot-1
sudo systemctl enable --now litevirt.service
```

`litevirt` listens on its own ports (7443 gRPC, 7445 UI, 7446 REST,
7444 Prometheus) so it doesn't collide with PVE's 8006. The PVE
cluster keeps running.

Sanity check:

```bash
lv host ls
lv host inspect pilot-1
```

## Step 2 — Inventory and pick a pilot

List your PVE workloads:

```bash
# On any PVE node:
qm list           # KVM VMs
pct list          # LXC containers
```

Pick a small, non-critical VM. Note its qcow2 path
(typically `/var/lib/vz/images/<vmid>/vm-<vmid>-disk-0.qcow2`).

## Step 3 — Migrate one VM cold

Cold migration is the safest first move. The pilot VM has at most one
restart window during the cut.

```bash
# On the PVE side:
qm shutdown <vmid>

# Copy the disk image to the litevirt host (or NFS share).
scp /var/lib/vz/images/<vmid>/vm-<vmid>-disk-0.qcow2 \
    pilot-1:/var/lib/litevirt/disks/pilot-vm-root.qcow2
```

Write a tiny compose file:

```yaml
# /etc/litevirt/stacks/pilot.yaml
volumes:
  local:
    driver: local

networks:
  prod:
    type: bridge
    interface: vmbr0       # the PVE bridge name still works

vms:
  pilot-vm:
    image: ""              # disk pre-staged
    cpu: 2
    memory: 4G
    disks:
      root: { volume: local, source: /var/lib/litevirt/disks/pilot-vm-root.qcow2 }
    network:
      - { name: prod, ip: <vm-ip> }
```

Deploy:

```bash
lv compose up /etc/litevirt/stacks/pilot.yaml
lv ls            # confirm pilot-vm running
```

## Step 4 — Migrate one container

OCI / LXC parity:

```bash
# On the PVE side:
pct stop <ctid>
pct list --format json   # find rootfs path

# Bind-mount the rootfs onto the litevirt host (or rsync it).

lv ct create pilot-ct --template /var/lib/litevirt/lxc/pilot-ct/rootfs
lv ct start pilot-ct
```

Or pull a fresh OCI image and skip the migration:

```bash
mkdir -p /var/lib/litevirt/lxc/pilot-ct/rootfs
lv ct pull docker.io/library/alpine:3.19 \
    --dest /var/lib/litevirt/lxc/pilot-ct/rootfs --local
```

## Step 5 — Recreate firewall rules

PVE writes datacenter / node / VM firewall rules to
`/etc/pve/firewall/cluster.fw` and `/etc/pve/nodes/*/host.fw`. Each
rule maps to litevirt as follows:

| PVE rule | litevirt equivalent (in compose) |
|---|---|
| `IN ACCEPT -p tcp -dport 22` | `direction: ingress, proto: tcp, port: 22, action: accept` |
| `OUT REJECT -d 192.0.2.0/24` | `direction: egress, cidr: 192.0.2.0/24, action: reject` |
| `[OPTIONS] enable: 1; policy_in: DROP` | `firewall: { default-deny: true }` |
| Security group `web` with rules | `security-groups: { web: { rules: [...] } }` |
| NIC binding `IPFILTER, "+vmgroup"` | `network[].security-groups: [vmgroup]` |

Example translation:

```yaml
# In your stack compose
firewall:
  default-deny: true
  cluster-rules:
    - { direction: egress, proto: tcp, port: 25, action: drop, comment: "block outbound SMTP" }

security-groups:
  web:
    rules:
      - { direction: ingress, proto: tcp, port: 80,  action: accept }
      - { direction: ingress, proto: tcp, port: 443, action: accept }

vms:
  pilot-vm:
    # …
    network:
      - { name: prod, ip: 10.0.0.10, security-groups: [web] }
```

Apply:

```bash
lv compose up /etc/litevirt/stacks/pilot.yaml
lv firewall reload                  # forces immediate re-render
lv firewall show                    # inspect the live nftables ruleset
```

## Step 6 — Switch backups to a litevirt repo

If you're running PBS, you can run both side-by-side until the cut.
Initialise a litevirt repo (host-local, NFS, or a dedicated backup
host):

```bash
# On the host that will own the repo:
sudo lv backup repo init /srv/backup/main

# Optional encryption:
openssl rand -hex 32 | sudo tee /etc/litevirt/backup.key
sudo chmod 600 /etc/litevirt/backup.key
sudo lv backup repo init /srv/backup/main \
    --encrypted --key-file /etc/litevirt/backup.key
```

Take the first backup:

```bash
lv backup snapshot pilot-vm --repo /srv/backup/main
lv backup repo ls /srv/backup/main
```

Verify a restore round-trip into a scratch directory:

```bash
lv backup restore-from \
    --repo /srv/backup/main \
    --vm pilot-vm --disk root \
    --timestamp <stamp-from-ls> \
    --target-path /tmp/restore-test.qcow2
qemu-img info /tmp/restore-test.qcow2
```

Once you trust the repo, retire your PBS once.

## Step 7 — Wire OIDC / LDAP

Drop the realm config into `/etc/litevirt/config.yaml`:

```yaml
auth:
  realms:
    - name: corp-okta
      kind: oidc
      oidc:
        issuer_url: https://corp.okta.com
        client_id: 0oa…
        client_secret_file: /etc/litevirt/okta-secret
        redirect_url: https://litevirt.corp/oidc/callback
    - name: corp-ad
      kind: ldap
      ldap:
        url: ldaps://ad.corp.example
        bind_dn: cn=svc-litevirt,ou=Users,dc=corp,dc=example
        bind_password_file: /etc/litevirt/ldap-secret
        user_base_dn: ou=Users,dc=corp,dc=example
```

Restart, then test:

```bash
sudo systemctl restart litevirt
lv login --realm oidc:corp-okta
```

PVE realms map 1:1: `pve` → `local`, `pam` → `local` (with a manual
sync if you really need PAM, though OIDC/LDAP is the cleaner path).

## Step 8 — Repeat for the rest

Once the pilot has been running stably for a few days:

1. Migrate VMs in waves of 5–10 at a time.
2. Cut DNS for each as it's confirmed healthy.
3. Decommission a PVE node only after all its VMs have moved.

For zero-downtime moves between litevirt hosts:

```bash
lv migrate <vm> <target-host>
```

For zero-downtime disk pool moves (e.g. local → Ceph):

```bash
lv move-volume <vm> root <ceph-pool-name>
```

## Rollback

If something breaks:

1. Scale the litevirt VM down (`lv stop`) — its qcow2 stays put.
2. Re-import on PVE via `qm importdisk` and start there.
3. File the bug.

The qcow2 on either side never had to change format, so the rollback
is symmetric. Backup repos sit in their own directory; nothing in
litevirt ever overwrites a PVE file.

## Verification — capability parity

A litevirt cluster after this guide has parity for every PVE capability
the guide promises:

- ✅ KVM/QEMU lifecycle, live + cold migration
- ✅ HA + fencing
- ✅ Compose YAML
- ✅ Per-driver storage (local, dir, nfs, iscsi, ceph, zfs, btrfs, lvm-thin)
- ✅ PBS-equivalent backup
- ✅ LXC + OCI containers
- ✅ Distributed firewall (nftables, three-tier)
- ✅ OIDC / LDAP realms
- ✅ TOTP + WebAuthn 2FA
- ✅ Storage motion (offline + live)
- ✅ Cross-host gRPC for backup, containers, firewall reload

If any of these doesn't behave like PVE in your testing, file a bug —
the migration is supposed to be loss-less.
