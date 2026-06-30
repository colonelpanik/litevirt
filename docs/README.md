# litevirt Documentation

## Introduction

litevirt is a lightweight KVM/QEMU orchestrator built for teams that want the simplicity of a single binary with the power of a full virtualization platform. There are no external databases, no container runtimes, no sidecars — just one static Go binary (`litevirt`) that you `scp` onto a Linux host and start.

Every host in a litevirt cluster is equal. There is no master node, no leader election, and no single point of failure. State is stored in an embedded SQLite database on each host and replicated across the cluster using the Crescent protocol — a relay-quorum replication topology. Conflicts resolve last-writer-wins by each row's wall-clock `updated_at` (so all hosts must run NTP); Hybrid Logical Clocks order the replication log and de-duplicate mutations, but do not arbitrate conflicts. If a host goes down, the others continue operating with a consistent view of the cluster.

### Why litevirt?

Most virtualization platforms fall into two camps: heavyweight enterprise suites that require dedicated infrastructure just to run the management plane, or minimal wrappers around libvirt that leave orchestration as an exercise for the operator. litevirt sits in between.

It gives you:

- **Multi-VM stacks** defined in Docker Compose-style YAML — networks, disks, placement constraints, service inheritance, load balancers, all in one file.
- **Live migration** with pre-copy memory transfer and automatic convergence. Move running VMs between hosts with near-zero downtime.
- **Automatic failover** with quorum-based failure detection and IPMI/watchdog fencing. VMs are rescheduled to healthy hosts without manual intervention.
- **Networking** that works — bridges, VXLAN overlays, SR-IOV, isolated networks with host isolation, built-in DHCP/DNS via dnsmasq, and NAT for outbound connectivity.
- **Storage pools** across local disks, NFS, Ceph, and iSCSI, with snapshots and backup/restore.
- **GPU and PCI passthrough** including SR-IOV virtual functions, NVIDIA MIG, and NVMe devices, with hot-plug support.
- **mTLS everywhere** with auto-generated ECDSA P-256 PKI. Zero-trust between hosts, no manual certificate management.
- **A web UI, REST API, and CLI** — pick the interface that fits your workflow.

The entire platform compiles to a single binary, `litevirt` (~30 MB): `litevirt daemon` runs the server and `litevirt <cmd>` is the CLI (also installed as the `lv` symlink). No CGO, no runtime dependencies beyond QEMU and libvirt on the host.

### Architecture overview

```
┌─────────────────────────────────────────────────────────┐
│  Workstation                                            │
│  ┌───────┐                                              │
│  │  lv   │ CLI binary                                   │
│  └───┬───┘                                              │
│      │ SSH tunnel                                       │
└──────┼──────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────┐
│  Host A (litevirt)                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ gRPC API │  │ REST API │  │  Web UI  │              │
│  │  :7443   │  │  :7446   │  │  :7445   │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       └──────────────┴─────────────┘                    │
│                      │                                  │
│  ┌───────────────────▼───────────────────────────────┐  │
│  │              Core Engine                           │  │
│  │  libvirt · cloud-init · networking · storage       │  │
│  │  migration · failover · DNS · load balancing       │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │                                  │
│  ┌───────────────────▼───────────────────────────────┐  │
│  │          SQLite + Crescent Replication             │  │
│  │  State store with relay-quorum sync to all peers   │  │
│  └───────────────────┬───────────────────────────────┘  │
│                      │ mTLS                             │
└──────────────────────┼──────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
   │ Host B  │   │ Host C  │   │ Host N  │
   │litevirt│   │litevirt│   │litevirt│
   └─────────┘   └─────────┘   └─────────┘
```

The CLI (`lv`) connects to any host in the cluster over an SSH tunnel. Since every host has the full cluster state, any host can serve as the entry point. The daemon exposes three interfaces: gRPC (primary API, used by the CLI and inter-host communication), a REST gateway (for curl and CI scripts), and a web UI (HTMX-based, no JavaScript build step).

### Getting started

The fastest path from zero to a running VM:

```bash
# Build
make build

# Single-node setup
sudo cp bin/litevirt /usr/local/bin/
sudo lv host init --local --name node-1
sudo systemctl enable --now litevirt

# Run a VM
export LV_HOST=root@127.0.0.1
lv image pull https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img --name ubuntu
lv run --name my-vm --image ubuntu --cpu 2 --memory 2048
lv ls
```

See the [Installation](installation.md) guide for multi-host cluster setup, adding hosts, and upgrading.

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](installation.md) | Build from source, bootstrap a cluster, add hosts, upgrade |
| [Configuration](configuration.md) | Daemon config file reference and environment variables |
| [CLI Reference](cli-reference.md) | All `lv` commands and flags |
| [Compose Stacks](compose.md) | Multi-VM stack definitions with YAML |
| [Networking](networking.md) | Bridge, VXLAN, SR-IOV, isolated networks, IPv6, host isolation |
| [Storage](storage.md) | Local, NFS, Ceph, and iSCSI storage pools |
| [Backups & Replication](backups.md) | Dedup chunk store, incremental, schedules, live restore, scheduled volume replication |
| [Containers](containers.md) | LXC/OCI lifecycle, compose integration, networking, limits |
| [Migration & Failover](migration-failover.md) | Live migration, health checking, fencing, manual-fence confirmation, witness hosts |
| [Placement & Rebalancer](placement.md) | Per-VM policies, named modes (`balance`, `bin-pack`, `spread-strict`, `cost-aware`), rebalancer modes, scope chain, troubleshooting |
| [Upgrades](upgrades.md) | Pre-flight gates, `upgrading` host state, auto-rollback, operator playbook |
| [Operating Model](operating-model.md) | What the cluster guarantees and does NOT guarantee; recovery playbook; even-N witness sizing |
| [GPU & PCI Passthrough](pci-passthrough.md) | Device assignment, SR-IOV VFs, MIG, hot-plug |
| [REST API](rest-api.md) | HTTP/JSON gateway with SSE for streaming RPCs |
| [Web UI](ui.md) | Browser-based dashboard |
| [Tenancy](tenancy.md) | Projects, quotas (6 dimensions), billing webhook, RBAC integration |
| [Federation](federation.md) | Region label, cross-region migrate, anycast service endpoints with weighted-RR DNS |
| [Audit log](audit-log.md) | SHA-256 hash chain, `lv audit verify`, WORM JSON export |
| [Diagnostics](diagnostics.md) | `lv doctor divergence` scanner, equal-timestamp tie resolution, runtime ownership repair, metrics/alerts, repair runbook |
| [GitOps](gitops.md) | `litevirt gitops` reconcile subcommand, `DiffStack` short-circuit, `gh` post-back |
