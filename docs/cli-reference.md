# CLI Reference

The CLI and daemon are one binary, `litevirt`. `lv` is a convenience symlink, so
`lv <cmd>` and `litevirt <cmd>` are identical — this reference uses `lv`. (The
server runs as `litevirt daemon`; see [Installation](installation.md).)

The `lv` CLI connects to any cluster host via SSH tunnel. Set the target with `LV_HOST`:

```bash
export LV_HOST=root@10.0.50.10
```

Every subcommand also accepts `lv <cmd> --help` for full flag detail; this
reference is a discovery map, not an exhaustive spec.

## Authentication

```bash
lv login                               # Log in with username and password
lv logout                              # Log out and remove stored credentials
lv whoami                              # Show current authenticated identity
lv session ls [--user <name>]          # List active sessions (admin: any user)
lv session revoke <session-id>         # Revoke a session immediately
```

## Two-factor authentication

```bash
lv 2fa enroll-totp --label <name>          # Enroll TOTP; prints otpauth URL + recovery codes
lv 2fa disable --method totp --label <l>   # Drop a single factor
lv 2fa ls [--user <name>]                  # List enrolled factors
```

WebAuthn enrollment is browser-only; use the `/account/2fa` page.

## Cluster

```bash
lv status                          # Cluster overview (JSON)
lv events [--type <filter>]        # Stream cluster events live
lv events <vm> [--limit N] [--since <RFC3339>]   # One VM's activity history (lifecycle + backup outcomes)
lv top [--interval 3s]             # Live resource dashboard
lv ui [--open]                     # Show web UI URL
lv version                         # Print version
lv cluster digest                  # Per-table state digest for each host
lv cluster sync                    # Pull full state from connected host and merge
lv health                          # Cluster health matrix
```

## Hosts

```bash
lv host init <user@host> --name <name>    # Bootstrap first host (remote)
lv host init --local --name <name>        # Bootstrap on localhost (standalone)
lv host add <user@host> --name <name>     # Add host to cluster
lv host ls                                # List hosts
lv host ls --names                        # Print only host names, one per line (for scripts)
lv host inspect <host>                    # Host details
lv host drain <host> [--parallel 2]       # Evacuate VMs off host
lv host shutdown-workloads <host>         # Stop VMs in reverse startup-order (honors stop-delay)
lv host undrain <host>                    # Return host to scheduling
lv host rm <host> [--force]               # Remove host (--force with running VMs)
lv host fence <host> --confirmed          # Manually fence a host (real fence)
lv host fence-confirm <host>              # Confirm an already-powered-off manual-fence host
lv host rescan [host]                     # Rescan PCI devices
lv host devices <host> [--type gpu|network|nvme|infiniband]   # List PCI devices
lv host upgrade --binary <path> [host...] # Rolling upgrade of litevirt
  [--yes]                                 # Skip confirmation prompt
  [--force]                               # Skip preflight blocks (warnings still printed)
  [--no-prestage]                         # Skip the cluster-wide schema pre-stage pass
lv host preflight-upgrade <host>          # Report preflight findings without upgrading
lv host label set <host> key=value ...    # Set labels on a host
lv host label rm <host> <key> ...         # Remove labels from a host
lv host label ls <host>                   # List labels on a host
lv host config <host>                     # Configure host settings
  [--fence-strategy ssh|ipmi|watchdog]
  [--ipmi-address <addr>] [--ipmi-user <u>] [--ipmi-pass <p>]
  [--watchdog-dev <path>]
  [--role worker|witness]                 # witness = vote-only tiebreaker
  [--region <name>]                       # Region label (federation)
lv host stats <host>                      # Host resource statistics
lv host ceph init                         # Bootstrap Ceph cluster on this host
lv host ceph add-mon <host>               # Add a Ceph monitor
lv host ceph add-mgr <host>               # Add a Ceph manager
lv host ceph add-osd <host> <device>      # Add an OSD on the named device
lv host ceph status                       # Ceph cluster health summary
lv host ceph osd-tree                     # Ceph CRUSH topology
```

## Virtual machines

```bash
lv run --name <vm> --image <img> [flags]  # Create and start a VM
  --cpu <n>             # vCPUs (default 2)
  --memory <mib>        # Memory in MiB (default 4096)
  --disk <size>         # Root disk size (default 20G)
  --host <name>         # Target host (auto-placed if omitted)

lv ls [--stack <name>] [--host <name>]    # List VMs
lv inspect <vm>                           # VM details
lv start <vm>                             # Start stopped VM
lv stop <vm> [--force]                    # Stop VM (--force = hard power off)
lv restart <vm>                           # Restart VM
lv rm <vm> [--keep-disks]                 # Delete VM
lv console <vm>                           # Serial console (Ctrl+] to exit)
lv vnc <vm>                               # Show VNC connection info
lv spice <vm> [--launch]                  # SPICE connection info
lv exec <vm> <cmd> [args...]              # Run command via guest agent
lv ssh <vm> [-u root] [-i key] [-- cmd]   # SSH into VM
lv logs <vm> [-f] [-n 50]                 # VM logs (-f to follow)
```

## VM configuration

```bash
lv config <vm> --ip <ip> --network <net>     # Set VM IP address
lv config <vm> --boot disk|cdrom|network     # Set boot order

# lv update reconfigures an existing VM. Restart policy, autostart and startup
# ordering apply LIVE (no stop needed); the resource fields require the VM stopped.
lv update <vm> --restart on-failure          # set/clear restart policy (live)
  [--restart-max-attempts N --restart-delay 5s --restart-window 1h]
  [--restart none]                           # clear the policy
lv update <vm> [--onboot] [--startup-order N] [--start-delay N] [--stop-delay N]   # autostart/ordering (live)
lv update <vm> [--cpu N] [--memory N]        # resources — VM must be STOPPED
  [--cpu-mode host-passthrough|host-model|custom] [--disable-vnc]
  [--machine q35] [--firmware uefi|bios] [--guest-agent]
  [--min-mem N] [--max-mem N]
lv rebuild <vm>                              # Recreate from stored spec
lv cutover <vm>                              # Snapshot-and-replace update
lv resize-disk <vm> --disk <name> --size <size>   # Grow a disk
lv stats <vm>                                # VM resource statistics
```

## Containers (LXC / OCI)

```bash
lv ct pull <oci-image> --dest <rootfs>       # Pull an OCI image (skopeo + umoci)
lv ct pull <oci-image> --dest <rootfs> --username <u> --password-stdin   # ad-hoc auth pull
lv ct create <name> [--image <oci>] [--distro alpine --release 3.19] [--local]
lv ct create <name> --restart on-failure [--restart-max-attempts 5 --restart-delay 5s]  # auto-restart on unexpected stop
lv ct create <name> --on-host-failure image-recreate   # rebuild on a surviving host if this one is fenced
lv ct start <name>
lv ct stop <name>
lv ct rm <name>
lv ct ls
lv ct exec <name> -- <cmd> [args...]
lv ct backup <name> --repo <dir>                       # full rootfs backup → dedup chunk store
lv ct restore <name> --repo <dir> --timestamp <ts> [--start]  # rebuild from a backup manifest
lv ct migrate <name> <target-host> --repo <shared-dir> # cold-migrate (stop → transfer → start)
lv ct snapshot create <name> <snapshot>                # freeze+tar point-in-time snapshot
lv ct snapshot ls <name>                               # list a container's snapshots
lv ct snapshot revert <name> <snapshot>                # roll back (stop → restore → restart)
lv ct snapshot rm <name> <snapshot>                    # delete a snapshot
lv ct template <name> [--revert]                       # convert a stopped ct to a clone template
lv ct clone <source> <new-name> [--project p] [--start] # full-copy clone with a fresh identity
```

`--local` runs against the local lxc-* binaries instead of the gRPC service
(used during bootstrap and debugging).

`lv ct backup` freezes a running container, archives its rootfs + LXC config,
and pushes a self-contained manifest into a PBS-equivalent repo (dedup against
earlier backups is automatic). `lv ct restore` rebuilds it from the repo alone
— even after `lv ct rm` — refusing to clobber a live container of the same name.

`lv ct migrate` cold-migrates a container to another host by reusing that
backup→restore transport: stop → archive → restore on target → restart (if it
was running). `--repo` must be reachable from **both** hosts (e.g. an
NFS-mounted repo). A failure before cutover leaves the container intact on the
source. No live migration / CRIU.

## Registry credentials

Logins for private OCI/Docker registry pulls. Per-user by default; `--global`
stores a cluster-wide credential (operator-only). At pull time the caller's
per-user credential for the image's registry wins, else the global one, else an
anonymous pull. See [containers.md](containers.md#private-registry-credentials).

```bash
echo "$TOKEN" | lv registry add <registry> --username <u> --password-stdin   # store (per-user)
echo "$TOKEN" | lv registry add <registry> --username <u> --password-stdin --global   # store (cluster-wide; operator)
lv registry ls                               # your own + global (secrets never shown)
lv registry ls --all                         # every user's + global (operator)
lv registry ls --global                      # global only
lv registry rm <registry>                    # remove your own
lv registry rm <registry> --global           # remove the cluster-wide one (operator)
```

`<registry>` is a host: `docker.io`, `ghcr.io`, `registry.example.com:5000`.
Prefer `--password-stdin` over `--password` so the secret stays out of argv and
shell history.

## Migration

```bash
lv migrate <vm> <target-host>                  # Live migrate
lv migrate <vm> <target-host> --cold           # Cold migrate (stop, move, start)
lv migrate <vm> <target-host> --with-storage   # Copy disks to the target during migration
```

## Rebalance

```bash
lv rebalance list [--status pending]                    # List proposals (pending|approved|applying|applied|failed|rejected|expired)
lv rebalance run [--dry-run]                            # Force one evaluation cycle
lv rebalance approve <proposal-id>                      # Approve → leader's executor live-migrates it
lv rebalance reject  <proposal-id> [--reason "text"]    # Reject a pending proposal
```

The rebalancer runs automatically every 60 s on the leader (proposing moves);
the leader's executor applies approved proposals (`approved → applying →
applied/failed`), bounded by the cluster rebalance budget.
See `docs/placement.md` for policies, modes, and execution.

## Regions (federation)

```bash
lv region ls                                   # List regions and host counts
lv region status [--region <name>]             # Region health rollup (all, or one)
lv region migrate <vm> <target-host> \
    [--with-storage] [--target-pool <pool>]    # Cross-region VM move (region inferred from host)
lv region anycast add --name <svc> --ip <ip> --region <r> [--weight N]   # one endpoint per call
lv region anycast ls [--name <svc>]
lv region anycast rm --name <svc> --ip <ip>
```

See `docs/federation.md` for the model.

## Compose stacks

```bash
lv compose up [-f litevirt-compose.yaml] [-y]      # Deploy/update stack
lv compose down [-f litevirt-compose.yaml] [-y]    # Tear down stack
lv compose down --name <stack> [-y]                # Tear down by stack name
lv compose ps [-f litevirt-compose.yaml]           # List stack VMs
lv compose diff [-f litevirt-compose.yaml]         # Preview changes
lv compose ls                                      # List all stacks
lv compose export <stack> [-o file.yaml]           # Export stack compose YAML
```

## Networks

```bash
lv network ls                                     # List networks
lv network inspect <name>                         # Show network details
lv network create <name> --type bridge [flags]    # Create a network
  --interface <name> | --vni <int> --underlay <iface>
  --subnet <cidr> [--dhcp]
  --pf <iface> --spoof-check                      # SR-IOV variants
lv network rm <name> [--force]
```

## Storage pools

```bash
lv pool create <name> --driver <d> [--source <s>] [--target <t>] [--option k=v]
  # drivers: local | dir | nfs | iscsi | ceph | zfs | btrfs | lvm-thin
lv pool ls
lv pool inspect <name>
lv pool delete <name>
```

`lv pool create` runs the driver's Prepare() hook (mount NFS, log into
iSCSI, …) before persisting. See `docs/storage.md` for driver details.

## Volumes

```bash
lv move-volume <vm> <disk> <target-pool>       # Move a disk between pools (live or offline)
lv replicate-volume <vm> <disk> <target-pool>  # Crash-consistent point-in-time copy

# Migrate every VM's volumes in a stack to a different pool (rolling, online):
lv stack migrate-volumes <stack> --to <pool>
lv stack migrate-volumes <stack> --to fast --map pg-1/data=archive --map pg-2=warm
#   --map vm=pool | vm/disk=pool   per-VM/per-disk override (most-specific wins)
#   --parallel N                   VMs migrated at once (default 1 = rolling)
#   --order a,b,c                  explicit VM sequence (e.g. replicas before primary)
#   --delete-source                reap each source after cutover
#   --dry-run                      preview the resolved plan, move nothing
```

## Images

```bash
lv image pull <url> --name <name> [--format qcow2] [--checksum sha256:...]
lv image import <file> --name <name>
lv image push <image> --to <host>
lv image build <vm> --name <name>        # Create image from running VM
lv image ls
lv image rm <image>
```

## Snapshots

```bash
lv snapshot create <vm> <name>            # disk-only (external qcow2 overlay)
lv snapshot create <vm> <name> --memory   # also capture guest RAM (live snapshot);
                                          # revert resumes the running VM at that instant.
                                          # Falls back to disk-only if the VM is stopped.
lv snapshot ls <vm>                       # TYPE column shows disk | memory
lv snapshot restore <vm> <name>           # repeatable; memory snapshots are host-local
lv snapshot rm <vm> <name>
```

## Memory ballooning

```bash
# Set min/max at create time (compose: min-memory / max-memory):
lv run --name web --image ubuntu --memory 2048 --min-mem 1024 --max-mem 4096
lv set-memory <vm> <MiB>                   # live balloon target, within [min, max]
```

## Resource mappings (cluster-wide passthrough device aliases)

```bash
lv mapping create <name> [--description <text>]
lv mapping add-device <name> <pci-address> [--host <h>] [--vendor <v>] [--device <d>]
lv mapping rm-device <name> <pci-address> [--host <h>]
lv mapping ls
lv mapping rm <name>
# Reference from a VM: `lv run … ` device spec / compose `devices: [{mapping: <name>}]`
```

## Boot ordering

```bash
lv run … --onboot --startup-order 10 --start-delay 5 --stop-delay 0
# onboot VMs start in startup-order on host boot (not on a plain daemon restart).

lv host shutdown-workloads <host>
# Gracefully stop every running VM on a host in REVERSE startup-order (highest
# startup-order first), honoring each VM's ACPI stop-grace-period and waiting its
# --stop-delay before moving to the next VM. This is the ONLY thing that consumes
# --stop-delay. It is an explicit operator action for an orderly host shutdown —
# a normal daemon restart/upgrade leaves VMs running and does NOT trigger it.
```

## Restart policy

```bash
lv run … --restart on-failure --restart-max-attempts 5 --restart-delay 5s --restart-window 1h
# Auto-restart a VM that stops UNEXPECTEDLY (crash, fence/external destroy).
# A clean guest shutdown or an `lv stop` always sticks — under `on-failure` AND
# `always` (the guest-stick rule). Default is `none` (opt-in). See docs/compose.md
# "Restart policy" for the full reason→action matrix and the container caveat.
```

## Notifications

```bash
lv notify target add --name ops-slack --type slack --url <incoming-webhook-url>
lv notify target add --name ops-hook --type webhook --url <url>
lv notify target ls
lv notify route add --pattern "backup.*" --target <target-id> --min-severity error
lv notify route add --pattern "*" --target <target-id> --min-severity warn
lv notify route ls
lv notify test <target-id>
lv notify route rm <id>
lv notify target rm <id>
# Events: backup.failed, host.fenced, replication.failed, quota.exceeded. See notifications.md.
```

## ACME (web UI cert)

```bash
lv acme status [host]   # show the TLS cert the UI is serving (subject/issuer/SANs/expiry)
# Configure under `acme:` in the daemon config; see configuration.md.
```

## Backups

```bash
# Repository management (host-local)
lv backup repo init <path> [--encrypted --key-file <file>]
lv backup repo ls <path>
lv backup repo verify <path>
lv backup repo gc <path>
lv backup repo prune <path> [--keep-{last,daily,weekly,monthly,yearly} N] [--apply]
lv backup repo sync <src> <dst>

# Schedule management (cron-driven). Scope is inferred from --pool/--project
# when --scope is omitted; with neither, pass a <vm> arg or --scope cluster.
lv backup schedule add <vm> --repo <name> --cron "0 2 * * *" [--keep-* N]   # per-VM
lv backup schedule add --pool <pool> --repo <name> --cron "..."            # per-pool fan-out
lv backup schedule add --project <name> --repo <name> --cron "..."         # per-project
lv backup schedule add --scope cluster --repo <name> --cron "..."          # every VM
lv backup schedule ls
lv backup schedule rm [vm] --repo <repo> [--scope vm|pool|project|cluster] [--pool <p>] [--project <p>]

# Push / restore via the daemon
lv backup snapshot <vm> --repo <path> [--disk <name>] [--incremental] [--quiesce auto|off]
#   --quiesce auto (default): freeze guest filesystems via the qemu-guest-agent for an
#   application-consistent backup when the VM has an agent, else crash-consistent.
#   --quiesce off: always crash-consistent. A freeze failure never fails the backup.
lv backup restore-from --repo <p> --vm <v> --disk <d> \
    --timestamp <ts> --target-path <path>
lv backup restore-live --repo <p> --vm <v> --disk <d> \
    --timestamp <ts> --target-path <overlay.qcow2> [--bind 127.0.0.1:0]
  [--auto-start]      # define + start the VM against the overlay automatically
  [--name <new>]      # rename the restored VM (avoids collision with the original)
  [--blockpull]       # after start, localize the disk then tear down the NBD server
  [--from-existing]   # fall back to an existing vms record for the VM spec

# Legacy file-export interface (full-disk; no dedup)
lv backup create <vm> [-o backup.qcow2]
lv backup restore <file> --name <vm> --cpu 2 --memory 2048
```

## Replication

```bash
# Cron-driven volume replication to a target pool/host.
lv replication schedule add <vm> --target-pool <pool> --cron "0 */4 * * *"
  [--target-host <host>]   # explicit destination (else shared-pool / auto-selected peer)
  [--keep N]               # keep N newest replicas (0 = keep all)
  [--incremental]          # transfer only dirty extents (raw replicas)
  [--auto-promote]         # failover may promote the freshest replica on host loss
  [--disabled]             # create the schedule disabled
  [--scope vm|pool|cluster|project] [--pool-name <p>] [--project-name <p>]
lv replication schedule ls
lv replication schedule rm <vm> --target-pool <pool> [--scope ...] [--pool-name <p>] [--project-name <p>]

# Disaster recovery: bring a VM up from its replica.
lv replication promote <vm>
  [--pool <p>] [--host <h>]   # where the replica lives (default: from the VM's schedule)
  [--replica <file>]          # exact replica filename (default: newest)
  [--new-name <name>]         # promote alongside a still-running original
  [--no-localize]             # boot off an overlay backed by the replica (fast; pins it)
  [--force]                   # promote even if the original is on a healthy host
```

## Clones and templates

```bash
lv template <vm> [--revert]        # Convert a stopped VM to a clone template (or revert)
lv clone <source> <new-name>       # Clone a template or stopped VM into a new VM
  [--mode auto|linked|full]        # auto (default): linked on shared storage, full on local
  [--project <name>]               # tenancy project for the clone (default: source's)
  [--ip <ip>]                      # static IP for the clone's first NIC (default: DHCP)
  [--start]                        # start the clone after creation
  [--snapshot <name>]              # clone from this snapshot of the source
```

## GitOps

```bash
lv gitops --repo <url>             # Reconcile a Git repo of compose YAMLs into the cluster
  [--branch main]                  # branch to track
  [--local-dir <path>]             # working-tree location
  [--compose-glob '**/compose.yaml']
  [--poll 60s]                     # polling interval (0s disables polling)
  [--webhook-bind 127.0.0.1:7700]  # reconcile webhook listener (empty = disabled)
```

See `docs/gitops.md` for the controller model.

## Load balancers

```bash
lv lb ls                                          # List load balancers
lv lb inspect <name>                              # LB details + backends (real HAProxy health; state=degraded if VIP unassigned)
lv lb create <name> --vip <cidr> --port <l:t/proto> --backend <name=addr>
  --algorithm roundrobin     # roundrobin | leastconn | source
  --host <name>              # Hosts to run LB on (repeatable)
  --vm-backend <vm-name>     # Use VM IP as backend (repeatable)
lv lb update <name> [flags]                       # Update config (zero-downtime)
lv lb delete <name>
lv lb stats <name>                                # Live backend metrics
lv lb drain <name> --backend <vm>                 # Graceful drain
lv lb disable <lb> --backend <vm>                 # Hard disable
lv lb enable <lb> --backend <vm>                  # Re-enable
```

## Hot-plug (attach/detach)

```bash
lv attach-disk <vm> <disk> --size 50G [--bus virtio]
lv detach-disk <vm> <disk>
lv attach-nic <vm> <network> [--model virtio] [--mac ...]
lv detach-nic <vm> <mac>
lv attach-pci <vm> --type gpu [--vendor 10de] [--count 1] [--sriov]
lv detach-pci <vm> <pci-address>
```

## Users and tokens

```bash
lv user create <username> --role admin|operator|viewer
lv user ls
lv user delete <username>
lv user passwd [username]           # Change your own password (or, as admin, another user's)
  [--old-password <p>] [--new-password <p>]   # prompts if unset; old not needed for an admin reset
lv user token-create <username> <token-name> [--expires <RFC3339>]
  [--scope-path <path>] ...        # Repeatable; intersect with role bindings
lv user token-revoke <token-id>
lv user reset-admin                # Re-mint the admin password
```

## Roles (path-based RBAC)

```bash
lv role grant <role> <principal> --path <path> [--propagate]
lv role revoke <binding-id>
lv role ls [--principal user:alice]
```

Principals are `user:<name>` or `group:<name>@<realm>`. Paths are RBAC
scopes (`/`, `/projects/acme`, `/projects/acme/vms/web-1`). See
`docs/auth.md` for the role catalog and propagation semantics.

## Projects (tenancy)

```bash
lv project create <name> [--display "..."] [--parent <name>]
lv project ls
lv project rm <name>
lv project quota <name> --vcpu N --mem N --disk N \
    --nics N --ips N --backup N
  # --mem is MiB; --disk/--backup are GiB; --ips is the public-IP count; 0 = unbounded
lv project usage <name>
```

Hierarchical names like `/acme/team-foo`. Admission gates VM creation on
all six quota dimensions. See `docs/tenancy.md`.

## Security groups and firewall

```bash
lv sg create <name>
lv sg ls
lv sg rm <id>
lv sg rule-add <sg-id> --direction ingress|egress --proto tcp \
    --port <p> --cidr <c> [--action accept|drop|reject] [--priority N]
lv sg rule-ls <sg-id>
lv sg bind <vm> --network <name> --sg <name> [--sg <name>...]   # Bind SGs to a VM NIC
  # --network matches the compose network name on the NIC; --sg is repeatable
  # (an empty --sg list clears the bindings).

lv firewall show              # Render the live nft ruleset for this host
lv firewall reload            # Force the reconciler to re-read state and apply now

# Cluster-tier rules (apply to every NIC on every host):
lv firewall cluster-rule add --direction ingress|egress --proto tcp \
    --port <p> --cidr <c> [--action accept|drop|reject] [--comment <s>] [--priority N]
lv firewall cluster-rule ls
lv firewall cluster-rule rm <id>

# Host-tier rules (apply to every NIC on one host):
lv firewall host-rule add --host <name> --direction ingress|egress --proto tcp \
    --port <p> --cidr <c> [--action accept|drop|reject] [--comment <s>] [--priority N]
lv firewall host-rule ls [--host <name>]
lv firewall host-rule rm <id>

# Named CIDR lists (reference from a rule with --cidr @<name>):
lv firewall ipset add <name> --cidr <c> [--cidr <c> ...]   # --cidr repeatable
lv firewall ipset ls
lv firewall ipset rm <id>

# Default forward policy (deny = drop anything not explicitly accepted):
lv firewall default-deny <on|off> [--scope <host>]   # no --scope = cluster-wide
```

See `docs/firewall.md` for the three-tier model.

## Audit log

```bash
lv audit ls [--limit N] \
    [--target <path>] [--action <a>] [--user <u>] [--since <RFC3339>]   # Tail/filter recent audit entries
  #   --action supports a trailing-* prefix glob (e.g. sg.*)
lv audit verify                                # Walk the SHA-256 hash chain
lv audit export [--since <ts>] [--until <ts>] [--out audit.json]   # Export WORM-ready JSON
```

See `docs/audit-log.md` for the chain semantics.

## Monitoring

```bash
lv health                                    # Cluster health matrix
lv audit ls [--limit N] [--target T] [--action A] [--user U] [--since TS]   # Audit log (default 50 entries)
lv host stats <host>                         # Host resource statistics
lv stats <vm>                                # VM resource statistics
```

## Ansible integration

```bash
lv ansible-inventory --list     # JSON inventory for Ansible
lv ansible-inventory --host <ip>
```

## Uninstall

```bash
lv uninstall <user@host> --confirmed              # Remove litevirt from host
lv uninstall <user@host> --confirmed --keep-data  # Keep VM images and disks
```
