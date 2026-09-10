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
  is retained as a fallback for mixed-version clusters. Convergence is automatic;
  `lv cluster converge` only *accelerates* it (kicks an immediate anti-entropy
  pass) and *verifies* it (cross-host digest report) — it never exports or merges
  redacted state itself.

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

### Leader-lease terms, and what enforcing on them does and does not buy

Every acquisition of a leader lease — `failover`, the rebalancer, the dual-run
detector — records a **term**: an incarnation number for that holder's tenure,
in the `leader_lease_terms` table. A renewal keeps its term, so a leader's term
is stable for as long as it holds the lease, and a coordinator that restarts
still holding its lease recovers the same number rather than a new one.

Terms exist because `leader_election` records *who* holds a lease but not
*which tenure*, which is what makes a stale leader's writes indistinguishable
from a current leader's.

A term is minted whenever a **tenure** begins, which is not the same as
whenever the holder changes. These all mint:

- another host taking the lease (the ordinary case);
- the same host re-taking its own lease **after it expired** — a GC pause,
  SIGSTOP or IO stall longer than the TTL ends a tenure, because the lapse is
  exactly the window other hosts were entitled to act in;
- once per lease key, ever: a node upgraded from a build with no term ledger
  comes back still holding its lease with no term recorded, and mints one.

Nothing mints until the cluster has finished rolling. Minting waits for
`lease_term_ledger_v1` to latch durably on the node doing it — a token with no
config flag, advertised by every build that has the ledger, so nothing is
required of you: it latches on its own once every host is upgraded, and terms
begin at the next tenure change. Before it latches, leases are taken exactly as
they were before terms existed; you will see `leader_election` move with an
empty `leader_lease_terms`.

It gates the mint rather than the read because the mint is the first write this
table ever replicated, and a host still on the previous release cannot decode
it: the write would not be ignored, it would stall that host's replication
entirely. So the latch is the proof that no such host is listening any more.

**"Every host" means every host still receiving replication, not every host that
votes.** A host in `maintenance` does not vote, but its daemon is up, it is in
memberlist, and it is still a replication target — so it holds this latch off
until it is upgraded or its daemon is stopped. That is the invariant rather than
a quirk: while it is listening, we must not send it shapes it cannot decode. If
a roll appears not to complete, look for a host parked in `maintenance` on an
older build.

Three operational consequences.

A cluster stuck mid-roll — one host held back — mints no terms at all. This is
by design: you see an empty `leader_lease_terms` rather than an error, and
`litevirt_ha_degraded{reason="capability_rollout_pending"}` rather than
`unsupported_member`. The two are deliberately distinct — a rollout in progress
is not a fault, so it does not page, but a rollout that never finishes is worth
a look. `unsupported_member` stays reserved for a capability you asked to
enforce that the cluster cannot confirm, and for one that latched and later
regressed.

`lease_term_v1` will not advertise ready on a host whose ledger token has not
latched, because enforcing on terms while producing none would refuse every
reschedule that host coordinates. The withheld-readiness reason names the token,
so a host that looks stuck says which of the two is outstanding.

There is no way to stand the ledger token down, deliberately. It has no config
flag, and deleting its marker file does not last — the monitor re-latches as
soon as the fleet is uniform. If you need minting to stop, stop the fleet being
uniform: roll a host back below this build, or leave one on the previous
release. Terms are additive audit facts and nothing acts on them until
`enforcement.lease_term` is enabled, and that IS a flag — so the thing you would
actually want to stop in an incident is reachable the ordinary way.

So an ordinary rolling restart of an N-host cluster mints roughly 3N terms —
each of the three leases moves once per host — on **every** roll. Size a
term-growth alert against that, not against the one-off upgrade backfill.

#### Turning enforcement on

Enforcement is **off by default** and needs two things: `enforcement.lease_term`
in config, AND the `lease_term_v1` capability latch. Neither alone does
anything. Before both hold, behaviour is exactly what it was before terms
existed — a stale term refuses nothing.

`lease_term_v1` will not latch on a cluster with **fewer than three
voting-eligible hosts**, whatever the flag says. The barrier needs
`liveHosts/2+1` answers: on two hosts that is both of them, so a single host
outage would refuse every protected action — and a host outage is precisely when
failover has to work. On one host quorum is self-satisfied and the barrier is a
no-op that protects nothing. Three is the smallest size where enforcing is both
meaningful and survivable.

**The latch is one-way.** A cluster that shrinks below three hosts after
latching keeps enforcing, because a latch that re-opened when a peer became
unreachable would fail open in exactly the partition it exists for. Setting
`enforcement.lease_term: false` and restarting is the way out: the flag is
authoritative for enforcement and for recovery, so it stops enforcement
regardless of the latch marker. Do not delete marker files to achieve this.

#### The two refusal reasons

Both appear in `litevirt_runtime_action_refused_total{action,reason}` and in the
refusal returned to the caller. They mean different things and are deliberately
not merged:

- **`stale_lease_term` — FENCED.** The proof's term is below the
  quorum-observed high water for its lease, or it names a coordinator this node
  did not record as holding that term. The mechanism worked and refused
  something it should refuse. A burst of these around a failover is the feature
  doing its job; a steady trickle in calm conditions means something is minting
  proofs from a tenure it no longer holds.
- **`lease_term_unconfirmed` — NOT fenced; could not establish whether it
  was.** This node could not reach a quorum to ask. It is a degradation and
  wants investigation: the action was refused for lack of evidence, not because
  anything was found wrong. Look for a partition or unreachable peers, not for a
  split-brain.

An operator who cannot tell these apart will hunt a split-brain that never
happened, which is why they are separate strings rather than one "refused".

#### What it costs

An **accepted** proof pays one bounded peer fan-out — a quorum read of every
reachable peer's newest term for that lease key. The budget is 3s for the whole
sweep, not per peer, so an unreachable fleet cannot multiply it. Concurrent
callers share one sweep, which matters because the load arrives in bursts: a
host loss with 40 workloads would otherwise run 40 fan-outs at the one moment
the system is meant to be fast. A **refusal** can be served from a short-lived
cache without any fan-out, because the observed high water only rises — so an
old reading is a lower bound, and refusing on a lower bound is sound while
accepting on one is not.

#### What enforcement does NOT do

Stated plainly, because the name invites more confidence than the mechanism
earns:

- **It does not stop two nodes believing they hold the lease.** That needs
  consensus, which a CRDT row store does not provide. Everything in *CRDT is not
  linearizable* above still holds in full.
- **It is not consensus, and a contested term is not resolved cluster-wide.**
  Two partitioned nodes can each mint the same term naming themselves, and
  nothing here elects a winner or ever will — see *What this table will and will
  not show you* below.
- **One host will not act for two claimants of one tenure.** That is the real
  guarantee, and it is narrower than it sounds: the claim binds an executor to
  the first claimant it acted for at that `(key, term)`, so the second is
  refused on that host.
- **But two hosts may each act for a different claimant**, and nothing produces
  agreement about which was legitimate. If that happens you have two
  coordinators that each got one host to act, and the ledger's job is to make it
  VISIBLE rather than to prevent it.

So enforcement narrows the blast radius of a stale leader; it does not eliminate
the split. Do not size a recovery plan as though it did.

#### Which proofs carry a term, and which legitimately do not

Not every proof is stamped, and an unstamped one is usually correct rather than
broken. A producer can only stamp a term if it holds a lease to take one from.

- The **failover coordinator** holds the failover lease, so it stamps the term
  of its own recorded tenure onto the reschedule and relocate proofs it mints.
  `reschedule` is the one action whose every producer holds a lease, so it is
  the one action where an unstamped proof is refused outright.
- **Container cold migration, LB apply and automated replica promotion** hold no
  lease at all. They mint term 0 with an empty key, and that is their normal
  output — refusing it would break container migration, load-balancer
  reconfiguration and post-fence promotion the moment the token latched, which
  is why the term requirement is scoped to `reschedule` rather than applied
  everywhere.

One consequence worth knowing: `relocate` has producers of both kinds, so an
unstamped relocate proof is either a lease-less producer's ordinary output or a
coordinator on an older build, and nothing can tell those apart. Narrowing that
needs a decision about whether container cold migration may require the
coordinator.

A proof's term and key are also part of a check that is INDEPENDENT of term
enforcement and runs whether or not it is switched on. An executor field-matches
the proof it was handed against the proof row it has persisted — action, target
kind and name, coordinator, destination, relocation token, fence epoch, owner
epoch, and now the lease term and key; `corrosion.ProofBindingEqual` is the one
definition of that set. A mismatch refuses the action ungated, exactly as a
mismatched relocation token already did. That catches a DIVERGENT PROOF ROW,
which is a different question from whether the term is current.

A carried proof's term and key are persisted on receipt and replicate from
there, so the executor validates the key against the closed set of lease names
before storing it, and refuses a negative term outright. An unknown key would
otherwise become that row's permanent authorization record — and enforcement
reading a nonexistent ledger for it would find `MAX(term) = 0` and pass every
proof naming it.

To read the current terms:

```sql
SELECT key, term, holder, acquired_at
FROM leader_lease_terms
ORDER BY key, term DESC;
```

A term is never reused, even after its row is tombstoned: allocation takes
`MAX(term) + 1` over every retained row, and the table survives a reseed for the
same reason. Do not add retention or GC to it without reading the constraints
recorded at `nextLeaseTerm` in `internal/corrosion/leader_lease.go`.

#### What to alert on

`litevirt_leader_lease_term{key=...}` is the highest recorded incarnation per
lease key. Its **rate** is leadership churn: terms climbing faster than the
failover rate you expect means flapping health checks, a TTL too short for the
environment, or a partition that keeps re-electing. This is the routine signal,
and it needs no conflict to be useful.

`litevirt_lww_tie_unresolved_current` going above zero for this table is the
serious one: **two nodes recorded themselves as holding the same term.** That is
the event the ledger exists to make visible, and it is a safety fault, not a
transient. `litevirt_lww_tie_unresolved_total` counts them cumulatively.

`litevirt_runtime_action_refused_total{reason="stale_lease_term"}` is
enforcement firing. Expect a burst around a genuine failover; a steady trickle
in calm conditions means a producer is minting proofs from a tenure it no longer
holds, and that producer is worth finding.

`litevirt_runtime_action_refused_total{reason="lease_term_unconfirmed"}` is
enforcement UNABLE to fire. It says actions are being refused for lack of
quorum evidence, so alert on it separately and treat it as an availability
signal rather than a safety one — this is the reason that appears when a
partition, not a stale leader, is the problem.

The three signals above are the EXECUTOR refusing. The coordinator has its own
precheck, and its counters answer a different question — not "was a bad proof
stopped" but "did a producer notice it had gone stale before writing one".

`litevirt_failover_attempts_total{phase="lease",result="skipped",error_class="stale_lease_term"}`
is that precheck firing. Read it against the executor's refusals: the
coordinator catching it means the producer stood down at the source, and the
executor catching it means one did not. A steady executor count with a flat
coordinator count says some producer is not running the precheck at all.

`litevirt_failover_attempts_total{phase="lease",result="error",error_class="db_error"}`
is the precheck's threshold read failing. It stamps ANYWAY when this happens —
deliberately, because refusing after the fence abandons the workload and the
executor's barrier still guards the stale case. So this counter is the one place
enforcement is permissive rather than fail-closed, and a persistent nonzero rate
means the coordinator has effectively stopped prechecking.

The stranded-workload sweep is off by default (`failover.stranded_recovery`) and
reports on `phase="stranded-recovery"`, with the two results meaning different
things:

`result="recovered"` is the sweep having actually MOVED workloads an earlier
refusal left behind. Any nonzero value is worth reading — not because the sweep
is broken, but because something upstream refused AFTER the host was fenced, and
those workloads sat on a powered-off machine until the sweep came back for them.
Alert on it and go find the refusal that preceded it; the sweep is the safety
net, not the fix.

`result="skipped"` is the sweep having tried and moved nothing: every remaining
workload was refused again. That is a different condition and usually a worse
one — a blocker nobody has cleared, typically an ownership dispute, no placement
that satisfies the workload's constraints, or a shared-disk VM whose proof-grade
fence evidence has aged out. It is reported separately precisely so it cannot
drown the signal above. A steady `skipped` rate with no `recovered` means the
sweep is spinning on something only an operator can resolve.

Note the phase label too. `phase="recovery"` with `result="recovered"` is a HOST
returning to active, which is routine and which you do not want to alert on;
`phase="stranded-recovery"` is workloads being evacuated from a host that never
came back.

#### Holding a fenced host

The sweep admits a host only while quorum still reports it down, so it will not
fight a host that has come back. But it does not ask permission either: once a
blocker clears it evacuates within a poll interval.

**The only hold is the flag.** Clear `failover.stranded_recovery` on the leader
and the sweep stands down cluster-wide, immediately and without stopping the
coordinator (which would also stop fencing). There is deliberately no per-host
hold, and no way to fake one: the sweep keys on `hosts.state == "fenced"`, and
the only ways out of that state are `lv host undrain <host>`, which marks the
host `active` and hands it back to placement and to the fence loop, or a genuine
recovery. `maintenance` reads like a parking state in the fence loop's skip list
but nothing in the tree ever writes it, so it is not one.

If you need a single host held while you investigate, clear the flag for the
duration. That is a real gap rather than a recommendation.

What the sweep cannot recover, by construction: a host whose fence succeeded but
whose `hosts.state` write did NOT (that write is deliberately non-fatal, so the
fence is not lost to a store blip) never reaches `fenced`, so the sweep never
admits it. Those workloads still need an operator. The guarantee is "a refusal
after a recorded fence is retried", not "no workload is ever stranded".

`litevirt_ha_degraded{reason="capability_rollout_pending"}` says a mandatory
token has not latched yet. During an upgrade that is expected and should not
page; persisting long after one is the signal that a host is stuck — most often
one parked in `maintenance` on an older build.

#### What this table will and will not show you

`PRIMARY KEY (key, term)` makes two rows for one term unrepresentable, so **no
single node's query can show you that two nodes held the same term.** Each node
keeps its own claim and refuses to overwrite it, so the disagreement lives
*between* nodes and in the metric above — never as two rows on one host. An
ordinary-looking table on the host you happened to query is not evidence that no
concurrent leadership happened.

A contested term is deliberately **not** resolved into a winner. Electing one
would destroy the losing claim and hand a future enforcement path a confident
answer to a question the cluster never agreed on. Instead both claims persist on
their own nodes and the conflict is flagged, which is why the alert above is the
access path rather than a query.

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
  dump**. `GetStateDump` (and the `lv cluster converge` digest report, which shows
  only table hashes) do not export registry passwords, notification webhook URLs,
  or 2FA material.
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
