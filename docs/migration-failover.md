# Migration & Failover

## Live migration

Move a running VM to another host with near-zero downtime:

```bash
lv migrate my-vm host-b
```

litevirt uses QEMU's pre-copy memory migration:

1. **Validating** — checks VM state, target host capacity, storage compatibility
2. **Preparing** — sets up target host (network, disks)
3. **Copying** — iterates dirty memory pages to target
4. **Converging** — auto-converge reduces page dirtying rate if needed
5. **Cutover** — brief pause, final state transfer, VM resumes on target
6. **Completing** — updates cluster state, cleans up source

Progress is streamed to the CLI in real-time.

### Requirements

- VM must be in `running` state
- Target host must be `active` and have sufficient resources
- All disks must be on shared storage (NFS/Ceph/iSCSI), OR use `with-storage: true`
- PCI passthrough devices block live migration (hot-detach first)

### Migration with local disks

For VMs whose disks are on local (non-shared) pools, the disk content is
copied to the target during migration. Pass `--with-storage` on the CLI for a
**live** migration:

```bash
lv migrate my-vm host-b --with-storage
```

The disk is streamed to the target over libvirt's block-copy / NBD channel
while the VM keeps running; the source is undefined after a successful cutover.
You can also set it as a per-VM default in compose:

```yaml
# In compose
    migrate:
      with-storage: true
```

Or cold migrate (stops the VM, copies disks, starts it on the target):

```bash
lv migrate my-vm host-b --cold
```

## Host drain

Evacuate all VMs from a host before maintenance:

```bash
lv host drain host-a
lv host drain host-a --parallel 4    # Migrate 4 VMs at a time
```

Drain live-migrates running VMs and cold-reassigns stopped VMs. When done:

```bash
# Perform maintenance...
lv host undrain host-a
```

## Health checking

### Host health

Every host probes every other host via TLS connection to the gRPC port (7443) every 2 seconds. Results are stored in the `host_health` table.

A host transitions to `suspect` after 3 consecutive probe failures. The failover coordinator takes action after quorum confirmation.

Clock skew between hosts is also monitored — warnings are logged if skew exceeds 1 second.

### VM health

VMs with a `healthcheck` defined in their compose spec are periodically checked:

```yaml
    healthcheck:
      type: "http"                # tcp | http | exec
      target: "http://localhost:8080/health"
      interval: "10s"
      timeout: "5s"
      retries: 3
      action: "restart"           # restart | migrate | alert
```

| Type | What it checks |
|------|----------------|
| `http` | HTTP GET, healthy if 2xx/3xx status |
| `tcp` | TCP connection succeeds |
| `exec` | Command exits 0 via guest agent |

**Correlated failure detection:** If 3+ VMs fail health checks simultaneously, litevirt suppresses automatic restarts (likely a shared dependency failure, not individual VM issues).

## Automatic failover

When a host goes offline, the failover coordinator:

1. **Detects failure** — quorum of observers must agree the host is unreachable (floor(n/2) + 1)
2. **Acquires leader lease** — only one host coordinates failover (30s TTL lease)
3. **Fences the failed host** — prevents split-brain by ensuring the failed host cannot access shared resources
4. **Reschedules VMs** — based on each VM's `on-host-failure` policy

### Fencing methods

| Method | How it works |
|--------|-------------|
| `ipmi` | Power cycle via IPMI/BMC (requires `ipmi_address`, `ipmi_user`, `ipmi_pass` on host). Verified post-fence by polling `chassis power status`. |
| `ssh` | `systemctl poweroff` over SSH; reports failure if unreachable. |
| `watchdog` | Local watchdog self-fence (the host writes its own watchdog timer dead). Requires `watchdog_dev` in config. When `watchdog_dev` is set the daemon validates the device at startup and refuses to start if it's absent, so a broken watchdog is caught before it's needed rather than at fence time (override: `LITEVIRT_UNSAFE_SKIP_WATCHDOG_CHECK=1`). |
| `manual` | Coordinator does NOT auto-reschedule; operator must run `lv host fence-confirm <host>` after physically powering it off. Required when shared storage would corrupt under split-brain. |
| `best-effort` | Tries SSH; succeeds regardless. Used in homelabs / single-tenant clusters that explicitly opt out of split-brain protection. |

Configure per-host:

```bash
lv host config host-b \
  --fence-strategy ipmi \
  --ipmi-address 10.0.50.111 \
  --ipmi-user admin \
  --ipmi-pass <secret>
```

### Manual fence confirmation flow

Under `manual` strategy, the failover coordinator records the failure but
refuses to reschedule VMs until an operator confirms the host is genuinely
powered off:

```bash
# Quorum has detected host-b unreachable. VMs on host-b are NOT
# automatically restarted yet (which would be split-brain on shared NFS).
# Operator powers off host-b out of band, then:
lv host fence-confirm host-b
# Next coordinator cycle reschedules the VMs.
```

The coordinator marks the host `fenced` once `lv host fence-confirm`
records a `manual-confirmed` row in `fencing_log`. This gate prevents
the coordinator from rescheduling a manually-fenced host's VMs before
an operator has actually confirmed the fence.

### Witness hosts (even-N quorum)

For 2-node or 4-node deployments, add a vote-only witness host to break
ties cleanly:

```bash
lv host config witness-1 --role witness
```

Witnesses participate in failover quorum but never run workloads. The
placement engine refuses to schedule any VM onto them. See
[operating-model.md](operating-model.md) for sizing guidance.

### VM failure policies

Set in compose `migrate` section:

```yaml
    migrate:
      on-host-failure: "restart-any"
```

| Policy | Behavior |
|--------|----------|
| `restart-any` | Restart on any available healthy host |
| `restart-same` | Wait for original host to recover |
| `none` | Do not reschedule |

## Load-balancer VIP split-brain safety

Load-balancer VIPs (keepalived/VRRP) are protected against split-brain by the same core
rule as VM/container ownership: **no quorum or proof ⇒ no new ownership action. A safe gap
(a VIP briefly down) is acceptable; two hosts answering the same VIP is the bug.**

This hardening is **capability-gated and rolled out per-cluster** — it activates only once
every participating host advertises support, so a mixed-version cluster keeps its previous
behavior until the whole fleet can enforce it. **No hardware watchdog is required** for any
of it; a watchdog, where present, is only an optional self-fence backstop.

### Minority self-demotes

An isolated load-balancer host that loses quorum stands its **own** VIPs down — stops
keepalived and removes the address — so it can't keep answering on the wrong side of a
partition. A brief blip never triggers this (there's a sustained-loss threshold,
`quorum_loss_demote_after_sec`); a freshly-restarted host still in warm-up never drops a
healthy VIP. If the stand-down can't be confirmed (e.g. a wedged keepalived) and the host
has a verified hardware watchdog, it self-fences; otherwise it keeps retrying and raises a
persistent `HA degraded` status rather than ever pretending to be down.

### Majority reclaims only with proof

The surviving majority (re)claims a VIP only on **proof the old holder has released it** —
either the old holder is reachable (directly, or relayed through a peer that can reach it)
and reports the VIP absent, or an operator has attested it is down (below). If the old
holder is **unreachable and unproven**, the majority leaves the VIP **down and raises an
alert** — an outage, never a blind takeover. This is the `safe` policy, and it is the only
supported one:

```yaml
# daemon config — the default; the only accepted value
no_quorum_vip_policy: safe
```

There is intentionally **no** weaker "take over after a timeout without proof" tier — it
would reintroduce the dual-master risk this feature exists to prevent. The supported way to
recover a stuck VIP is the manual fence-confirm below, not a weaker policy.

### Recovering a VIP from a dead, unreachable holder

If a VIP's holder has failed and can't be reached — and you need the VIP back — verify the
host is genuinely powered off out-of-band (IPMI / PDU / console), then attest it:

```bash
lv host fence-confirm <host>
```

This is the same operator attestation that releases a manually-fenced host's VMs, and it
also releases that host's VIPs: a host you have confirmed down has, by definition, let go of
its VIP, so the majority reclaims it. The attestation is trusted only briefly (re-run it if
recovery drags on), and **only an explicit `fence-confirm` counts** — an automatic fence
*attempt* that may have partially failed does not. This is the answer to "I need my VIP
back now": a fast, safe, operator-driven override — no weaker cluster-wide policy needed.

### Coverage boundaries

- A **data-plane-only** partition — gRPC/gossip quorum intact on both sides but the VRRP L2
  segment split — is not auto-resolved (neither side loses quorum, so neither self-demotes).
  Watch for a VIP-conflict alert and resolve the L2 fault.
- Reclaiming an unreachable holder's VIP **automatically** (without the manual attestation
  above) requires proof-grade fencing (IPMI power-off / SBD), a separate optional rollout.
  Until then the unreachable case is a deliberate availability trade-off: VIP down + alert,
  recovered by the fence-confirm step above.

## Containers

**Cold migration** — `lv ct migrate <name> <target> --repo <dir>` moves a
container to another host by reusing the backup→restore transport (stop →
archive → restore on target → restart if it was running). The source archives
into `--repo` locally and **streams the manifest to the target over peer mTLS**
(into a per-transfer staging repo), so `--repo` no longer needs to be reachable
from both hosts. If the target predates peer streaming it falls back to
re-opening `--repo` by name, which then must be shared. No live/CRIU migration.

**Host-loss relocation** — when a host is fenced, the failover coordinator
relocates its containers that carry an `on_host_failure` policy (set with
`lv ct create --on-host-failure image-recreate`) onto a placement-chosen healthy
host, preferring the most faithful option: **restore from the latest backup**
(`ct.relocate.restored` — preserves networking + non-image state, when a
reachable repo holds a valid manifest and the survivor is schema-compatible),
falling back to **recreate from image** (`ct.relocate.recreate` — managed NICs
reconstructed from the persisted create spec), and finally **skip** a container
that's neither restorable nor re-pullable (`ct.relocate.skipped`, left visible for
operator recovery). The restore path is idempotent + crash-recoverable (source
marker `relocate-restore:<target>:<token>`, where the attempt token is stamped on
the restored target row so the coordinator only completes the handoff against a
row proven to be its own restore; `container_restore_timeout_sec`). See
[containers.md](containers.md#host-loss-relocation).

## Monitoring

### Prometheus metrics

Scrape `http://<host>:7444/metrics` for:

- `litevirt_host_cpu_total`, `litevirt_host_memory_total_mib` — host resources
- `litevirt_host_vm_count` — VMs per host
- `litevirt_vm_state` — `1` if the VM is running, `0` otherwise
- `litevirt_migration_duration_seconds` — histogram of migration end-to-end wall time (labels: `strategy`, `result`)
- `litevirt_migration_downtime_ms` — histogram of guest-visible downtime during the cutover
- `litevirt_fence_failures_total` — cumulative non-success rows in `fencing_log`; pages should fire on any non-zero increase
- `litevirt_failover_leader` — `1` on the host currently holding the failover lease, `0` elsewhere
- `litevirt_failover_attempts_total{phase,result,error_class}` — failover decision points, counted by
  `phase` (`lease`, `quorum`, `health-query`, `skip`, `fence`, `split-brain-guard`, `recovery`),
  `result` (`ok`/`skipped`/`success`/`partial`/`refused`/`error`/`recovered`), and a bounded
  `error_class` (e.g. `no_quorum`, `upgrading`, `already_fenced`, `no_candidates`, `manual_unconfirmed`,
  `db_error`, `fence_log_write_failed`). A skip is `result=skipped` with the reason in `error_class`
- `litevirt_failover_vm_actions_total{action,result,error_class}` — per-VM failover actions
  (`action` = `promote`/`reschedule`)
- `litevirt_failover_container_actions_total{action,result,error_class}` — per-container failover actions
  (`action` = `relocate`)
- `litevirt_peer_healthy` — `1` if a peer host is reachable, `0` otherwise (one series per peer)
- `litevirt_hlc_rejected_total` — count of remote HLC timestamps clamped due to clock skew
- `litevirt_replication_min_watermark_seq` — minimum `last_seq` across all peers; a stalled value means replication is backing up
- `litevirt_mutation_log_rows` — total rows in `mutation_log`; coupled with the watermark above this gives backlog visibility
- `litevirt_replication_pending_entries` — `mutation_log` entries written but not yet acknowledged by the slowest **live** peer (`MAX(seq) − MIN(live last_seq)`); reads `0` when there are no live peers. A sustained climb means one peer is falling behind even though replication itself is healthy
- `litevirt_replication_peer_pending_entries` — per-peer backlog (`MAX(seq) − peer last_seq`), one series per live peer; a single series climbing while the others stay flat pinpoints the lagging peer. The daemon also logs a warning when a peer stays maxed-out for several rounds

### Event stream

```bash
lv events                  # Stream all events
lv events --type vm        # Filter by type
```

### Cluster status

```bash
lv status                  # JSON cluster summary
lv top                     # Live dashboard
```
