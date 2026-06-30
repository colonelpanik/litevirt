# litevirt Operating Model

> Plain-language description of what a litevirt cluster guarantees and what
> it does *not* guarantee. Read this before deploying.

---

## Architecture in one paragraph

Every host runs `litevirt`. There is **no master node**. State (hosts, VMs,
networks, etc.) is replicated as a CRDT via the embedded Corrosion store using
the Crescent relay-quorum protocol over mTLS gRPC. Each host's Hybrid Logical
Clock orders the replication log and de-duplicates mutations; row **conflict
resolution is last-writer-wins by the row's `updated_at`** (sub-second monotonic
per node), so all hosts must run NTP (HLC does not arbitrate conflicts). An
**exact-timestamp tie** with differing content is settled by a **table-aware
resolver**: a deterministic winner where any pick is safe, otherwise the row is
kept-local and flagged for repair (ownership/tenancy/policy/auth are never
coin-flipped) — see [Diagnostics](diagnostics.md). Health is observed
peer-to-peer (TLS probes every 2 s).
Failover is decided by quorum among observers, gated by a CRDT-stored leader
lease. Fencing has multiple strategies; safety guards refuse to reschedule
VMs after a fence failure so that the same VM never runs on two hosts at once.

---

## What the cluster guarantees

### Replication
- **Eventual consistency** of all CRDT-replicated tables across all healthy
  members. After any partition heals, all hosts converge to the same state
  for any record whose `updated_at` you can observe stabilizing.
- **No data loss for committed local writes** as long as one healthy peer
  remains reachable before the host dies.
- **Anti-entropy** (`internal/corrosion/antientropy.go`) runs every 60 s
  and is the safety net for divergence the WAL replicator missed. Public,
  operator-readable state uses `StreamStateDump`; eligible secret-bearing config
  uses a separate peer-mTLS-only sensitive dump. The older unary `GetStateDump`
  is retained as a fallback for mixed-version clusters and is the path
  `lv cluster sync` still uses, so manual operator sync intentionally remains
  redacted.

### HA / Failover
- **Quorum-gated fencing.** A host is fenced only after `floor(N/2)+1` fresh
  observers report `consecutive_failures ≥ 5` for it (where N is non-offline
  active hosts). Stale observer rows (older than 30 s) are excluded.
- **Leader-gated recovery.** Only one coordinator at a time drives recovery.
  The lease is held in a CRDT row with a 30 s TTL and re-validated before
  every destructive action.
- **No double-fencing.** Once a successful fence is recorded in `fencing_log`
  (or operator confirmation under manual strategy), no coordinator will
  re-fence the same host within a 5-minute window.
- **Split-brain refusal.** If a fence fails (and the strategy is not
  `best-effort`), the coordinator refuses to reschedule the host's VMs.
  Operator must intervene.

### Time
- HLC rejects remote timestamps more than **5 minutes ahead** of local wall
  time. One misconfigured peer cannot pin the cluster's logical time forward.
- Clock skew above 1 s is logged as a warning and recorded in the
  `clock_skew` table for metrics.

---

## What the cluster does NOT guarantee

### CRDT is not linearizable
- The leader lease is a CRDT row, **not** a strongly-consistent CAS. Under a
  partition, both sides may briefly believe they hold the lease.
  Consequences:
  - Two coordinators may race to fence a host. Both will find each other's
    work via the `recentlyFenced()` check on the next cycle, but during the
    race window both may have called `fence.Execute`.
  - Fencing primitives are designed to be idempotent (IPMI on an already-off
    host is a no-op; SSH poweroff likewise). Ensure your fence method has
    this property.
- VM placement and other state writes use last-writer-wins on the row's
  wall-clock `updated_at`. **The most recent writer (by wall clock) wins**; there
  is no two-phase commit. If two operators concurrently modify the same VM, one
  set of changes is silently lost — and under clock skew the host with the faster
  clock wins, so NTP is required.

### Even-N clusters cannot fence in a 2/2 partition
- A 4-node cluster split exactly 2/2 has no majority. Both sides compute
  quorum=3 with 2 observers each → neither side can fence.
- **Use a witness host** for any even-N deployment. A witness participates
  in quorum but holds no workloads. Add the host normally, then promote it
  (the host must have no VMs):
  ```
  lv host config witness-1 --role witness
  ```

### NTP is required
- All hosts must run NTP (chrony / systemd-timesyncd / ntpd). HLC tolerates
  ±5 minutes, but **anti-entropy LWW depends on monotonic, comparable
  timestamps** across hosts. Sustained skew above tolerance silently
  corrupts ordering of LWW-resolved fields.
- The daemon emits the `litevirt_cluster_clock_skew_seconds` metric per
  peer. Alert if any value exceeds 5 s.
- **Recommended alerting** on `litevirt_hlc_rejected_total > 0`: if any
  remote HLC has been rejected, a peer's clock is severely wrong; investigate
  immediately.

### CRDT replication is not synchronous
- A write committed locally may take **seconds** to appear on every peer in
  a healthy LAN cluster, longer over WAN. Code that needs "this write is
  visible everywhere before I act" should use a confirmation read on the
  target peer, not assume convergence.

### Secret-bearing repair is peer-only
- Secret-bearing config is **excluded from the operator-readable full-state
  dump**. `lv cluster sync` and `GetStateDump` do not export registry passwords,
  notification webhook URLs, or 2FA material.
- Eligible secret-bearing config (`registry_credentials`,
  `notification_targets`, `notification_routes`, `user_2fa`, `user_2fa_sets`,
  `recovery_codes`, `recovery_code_sets`) is repaired by a separate peer-mTLS-only
  anti-entropy lane. Peers already receive these rows through WAL replication; the
  peer-only pull is a repair path when a push was missed.
- 2FA/recovery are LWW-repairable: `user_2fa` soft-deletes, and each of 2FA and
  recovery codes is gated by a per-user active-set pointer (`user_2fa_sets`,
  `recovery_code_sets`). A factor/code is valid only when its epoch/set_id matches
  the pointer, so a row a partitioned peer resurrects (one a node never saw) can
  merge but never validate, and `DeleteUser` tombstones the pointers so a
  delete→recreate can't bring old auth state back. Safety holds once all
  auth-mutating nodes run ≥ schema v32.

### Disk-full is not auto-recovered
- The Corrosion store is a SQLite file. If the disk fills, the daemon stops
  accepting mutations. The cluster does not auto-evict the host. Monitor
  free disk; alert below 10%.

### Manual fence requires manual confirmation
- `FenceStrategy = "manual"` does not assume the host has been powered off.
  The operator MUST run `lv host fence-confirm <host>` after confirming the
  hardware is off. Without confirmation, VMs on the host remain in their
  pre-fence state, **even if the cluster has marked the host offline**.
- This is the safest behavior for clusters using shared storage where two
  running copies of a VM would corrupt the disk.

### No application-aware quiescence
- Backups, snapshots, and live migration are crash-consistent at the block
  level. The guest's database, filesystem, etc. must tolerate "as if power
  was cut" recovery. For application-consistent backups, install
  `qemu-guest-agent` in the guest and use the `freeze`/`thaw` hooks
  (currently best-effort; richer integration is on the roadmap).

---

## Sizing and deployment recommendations

### Cluster size
- **3 nodes**: minimum for any HA workload. 1-node failure tolerated.
- **5 nodes**: recommended. 2-node failure tolerated.
- **Even N**: only with a witness. 2-node with witness is fine for homelab.
- **Up to ~50 nodes**: tested and supported. Beyond, the relay-quorum
  protocol scales O(n) but the cluster's anti-entropy interval may need
  tuning.

### Network
- **Inter-host RTT < 10 ms**: comfortable. Default replicator and
  health-check intervals work without tuning.
- **Inter-host RTT 10-100 ms**: still works but increase `pollInterval`,
  `healthFreshness`, and `leaseDuration` proportionally to avoid lease
  thrash.
- **Multi-DC (RTT > 100 ms)**: supported in principle; tune intervals up
  significantly. The federation API on the roadmap is the recommended
  approach for cross-DC clusters once it ships.

### Fencing strategy
- **Production with shared storage**: `ipmi` (mandatory). SSH and watchdog
  are insufficient because a network-isolated but otherwise-healthy node can
  refuse SSH but continue writing to the shared volume.
- **Production without shared storage**: `ssh` is acceptable; `best-effort`
  for clusters that explicitly opt out of split-brain protection.
- **Homelab / single-tenant**: `manual` works if you're awake to confirm.
- **All hosts**: configure `watchdog` as a backstop so a hung daemon
  self-fences within the watchdog timeout.

### NTP
- Mandatory. Run `chrony` and verify `chronyc tracking` reports
  `Leap status: Normal` on every host.

---

## Observability checklist

Operators should monitor these Prometheus metrics:

| Metric | Alert threshold |
|---|---|
| `litevirt_peer_healthy` | 0 for any pair sustained > 30 s |
| `litevirt_cluster_clock_skew_seconds` | > 5 |
| `litevirt_hlc_rejected_total` | > 0 (sustained) |
| `litevirt_fence_failures_total` | rate > 0 over 5 min |
| `litevirt_failover_leader` | sum across cluster != 1 sustained |
| `litevirt_failover_attempts_total{result="error"}` | rate > 0 over 5 min (a failover decision hit a store/fence error) |
| `litevirt_mutation_log_rows` | rapidly growing (replication backlog) |
| `litevirt_replication_min_watermark_seq` | not advancing for > 5 min |
| `litevirt_daemon_open_fds` | > 5000 (FD leak) |
| `litevirt_lb_keepalived_up{lb}` | `== 0` sustained (a load balancer's VIP is not assigned — see [compose.md](compose.md#load-balancer)) |

The web UI at port 7445 surfaces the most critical of these on the
**Cluster** page; full dashboards are on the roadmap.

---

## Recovery playbook (one-line summaries)

| Symptom | Action |
|---|---|
| Host unreachable, fence-pending alert | Confirm out-of-band; if dead, `lv host fence-confirm <host>` |
| Fence failed, VMs stuck on offline host | Inspect IPMI; if power-off confirmed externally, run fence-confirm |
| Two leaders observed via metric | Kill the older daemon; investigate clock skew |
| HLC rejected counter rising on one peer | Check NTP on that peer; expect to fence it |
| Replication backlog growing | Identify slow peer via watermarks; consider `lv host drain` |
| Disk full on one host | Drain → repair disk → re-add as fresh peer |

---

## Anti-features (deliberate non-guarantees)

litevirt does not provide any of the following. Each is an intentional
boundary, not an oversight:

- **Strong consistency for cluster state.** Use anti-entropy + LWW; design
  workloads to tolerate it.
- **Synchronous cross-host writes.** All writes are local; replication is
  async.
- **Automatic *true* split-brain reconciliation.** A divergence that's safe to
  resolve — a workload running on exactly one host whose DB ownership drifted — is
  reclaimed automatically (runtime owner-assert / re-key, on all-peers-absent
  proof). But a genuine split-brain (the same workload running on two hosts) is
  never auto-resolved by host-order: litevirt refuses, alerts, and a human decides
  (destruction needs positive fencing proof). See [Diagnostics](diagnostics.md).
- **Cluster-wide rolling-upgrade automation that is invisible to operators.**
  Upgrades are explicit (`lv host upgrade`) and can be batched but never
  silent.
- **Multi-master reconciliation of conflicting application state.** That's
  the application's job; we sync metadata, not user data.
