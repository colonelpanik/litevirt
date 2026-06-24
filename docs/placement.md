# Placement and Rebalancing

> Companion to `docs/operating-model.md`.
>
> Two orthogonal axes:
>
>   1. **Policy** — initial-placement scoring (where new VMs go).
>   2. **Rebalancer mode** — day-2 reconciliation (does the engine react to ongoing imbalance?).
>
> Earlier the placement engine defaulted to bin-pack (the bug behind
> "VMs pile onto a single host"). The cluster default is now
> **balance + dry-run**: spread by default, propose moves to operators
> rather than acting unilaterally.

---

## TL;DR

```yaml
# Most users want the cluster default; nothing to set.
# To opt into a different policy on a specific VM:
vms:
  prod-db:
    placement:
      mode: ha-critical              # spread-strict + on-demand rebalance

  batch-job-1:
    placement:
      mode: savings                  # bin-pack + auto rebalance off-hours
```

Named modes available out of the box: `performance`, `savings`, `ha-critical`, `spot-cheap`. Or set `policy:` and `rebalance:` directly.

---

## The cost function

For each (host, request) pair the engine computes a weighted-sum score over
multiple resource dimensions:

```
score(h) = Σᵢ wᵢ · contribᵢ(h)

with contribᵢ depending on policy:
  balance / spread-strict / cost-aware:  contribᵢ = max(0, 1 − pressureᵢ)
  bin-pack:                              contribᵢ = min(1, pressureᵢ)
  pressureᵢ = (used + demand) / capacity
```

Default weights (tunable via `Request.Weights`):

| Dimension | Weight | Wired? |
|---|---|---|
| CPU | 25 | yes |
| RAM | 25 | yes |
| Disk IOPS | 15 | placeholder (planned) |
| Network bandwidth | 10 | placeholder (planned) |
| NUMA fit | 10 | label-driven |
| Host generation | 5 | label-driven |
| Power / thermal | 5 | placeholder |

Dimensions without telemetry (capacity ≤ 0) contribute zero — the cluster
runs cleanly even before all sensors are online.

Soft bonuses on top of the dimensional score:

- `+5` per matching `placement.prefer` label.
- `+20` per matching `placement.affinity` VM on the host.
- `−30` for SR-IOV networks without an explicit device requirement.
- Per-host `cost.hourly` divides the score under `cost-aware`.

Hard filters (host eliminated outright):

- State not `active` (offline, fenced, maintenance).
- Witness role.
- Insufficient CPU / RAM headroom.
- `placement.anti-affinity` violation.
- `placement.max-per-node` cap reached.
- `placement.require` labels not all matched.
- Required PCI devices unavailable.
- `spread-strict` policy: any wired dimension's post-placement pressure > 0.5.

---

## Placement policies

| Policy | When to use |
|---|---|
| `balance` (default) | Recommended cluster default. Spreads load evenly; tolerates moderate concentration to fit. |
| `bin-pack` | "Consolidate and forget" — prep for scale-down or maintenance. Pair with `rebalance.mode: off`. |
| `spread-strict` | HA-critical workloads; refuses to place above 50 % pressure on any single dimension. |
| `cost-aware` | Service providers / spot instances; prefers cheap hosts (label `cost.hourly`). |

A mixed cluster is the norm: batch jobs `bin-pack` while production VMs `spread-strict`. The engine evaluates each VM independently using its own resolved policy.

---

## Rebalancer modes

The day-2 loop runs every 60 s on the leader-only coordinator (gated by the `leader_election` lease, distinct from the failover lease).

| Mode | Behavior |
|---|---|
| `off` | No proposals emitted. |
| `dry-run` (recommended default) | Proposals written to `rebalance_proposals` table; never applied automatically. Operator reviews via `lv rebalance list` and may `approve` one to execute it. |
| `on-demand` | Proposals written; require explicit `lv rebalance approve <id>` before the executor applies them. |
| `auto` | Proposals written and immediately approved (subject to budget); the executor applies them automatically. |

Proposals score destinations with the **same hard-constraint pipeline as initial
placement** — anti-affinity, required labels, max-per-node, device fit, witness
exclusion, and the spread-strict pressure cap — so a proposed move can never land
a VM somewhere admission would have refused.

To opt a VM out of rebalancing, set `no_migrate: true` (or `migrate.strategy:
none`, or `rebalance.mode: off`). Note that `placement.host` does **not** opt a
VM out: the daemon auto-populates it with the planner-resolved host for every
compose VM, so it is not a "never move" signal — only the explicit flags above
are.

### Execution

Approved proposals are applied by the **rebalance executor**, a leader-gated loop
(sharing the rebalancer's `leader_election` lease, so exactly one node executes).
Each cycle it atomically claims approved rows (`approved` → `applying`),
re-validates them against live state (VM still exists, still running, still on the
proposed source, still migratable; destination still active), runs the live
migration, and records the terminal status (`applied` with `applied_at`, or
`failed` with the error in `detail`). A claim whose migration never completes
(daemon killed mid-flight) is reaped back to `failed` after a stale timeout.
Track progress with `lv rebalance list` / `--status applying|applied|failed`.

### Per-VM cooldown and per-cluster budget

- **Cooldown**: same VM is not re-proposed within `placement.rebalance.cooldown` (default 5 min).
- **Per-cycle cap**: at most `MaxConcurrent` proposals generated per cycle (default 2).
- **Concurrency cap**: the executor keeps at most `MaxConcurrent` migrations in flight (`applying`) at once.
- **Hourly cap**: no more than `MaxPerHour` migrations are applied per rolling 60 minutes (default 10) — enforced by both the proposer and the executor.
- **Budget resolution**: the cluster budget is the element-wise maximum of the per-VM `placement.rebalance.budget` values across migratable VMs (defaults when none declare one); proposer and executor share it.
- **Cycle commits**: each chosen move updates a working snapshot in-memory so subsequent VMs in the same cycle see the new pressure layout — prevents "every VM wants the same destination" cascades.

---

## Compose schema

```yaml
vms:
  web-1:
    cpu: 4
    memory: 8192
    placement:
      # ── Initial scoring ──
      policy: balance              # balance | bin-pack | spread-strict | cost-aware
                                   # (or use `mode:` for a named bundle)

      # ── Day-2 reconciliation ──
      rebalance:
        mode: dry-run              # off | dry-run | on-demand | auto
        threshold: 15              # min % score gain to propose a move
        cooldown: 5m               # min interval per VM
        budget:
          max-concurrent: 2
          max-per-hour: 10
          window: off-hours        # named cluster time-window (planned)

      # ── Hard constraints ──
      anti-affinity: [web-2]       # never co-locate
      affinity: [redis-1]          # prefer co-location
      require:                     # host MUST have all these labels
        zone: us-east-1a
      prefer:                      # bonus per match (+5)
        ssd: "true"
      max-per-node: 1              # max replicas of this VM group per host

      # ── Pinning ──
      host: bigbox-1               # pin to a specific host
      no-migrate: true             # rebalancer ignores; storage motion forbidden
```

### Named modes (alias bundles)

```yaml
placement:
  mode: performance       # balance + dry-run
  mode: savings           # bin-pack + auto + generous budget + off-hours window
  mode: ha-critical       # spread-strict + on-demand
  mode: spot-cheap        # cost-aware + auto + tight budget
```

The mode expansion happens at compose-parse time. Explicit `policy:` or
`rebalance:` fields on the same `placement` block override the alias defaults.

### Scope chain (cluster → project → stack → VM)

The effective placement for a VM is the merger of cluster default → project
default (planned) → stack-level placement → per-VM placement, with each
level overriding the last. Use `MergePlacement` (in `internal/compose/`) to
trace what gets applied.

---

## CLI reference

```sh
# List all proposals (any status)
lv rebalance list

# Filter by status
lv rebalance list --status pending

# Force an immediate evaluation cycle (respects per-VM mode)
lv rebalance run

# Force evaluation in dry-run regardless of per-VM mode
lv rebalance run --dry-run

# Approve a proposal — the leader's executor then live-migrates it
lv rebalance approve <proposal-id>
# Watch it execute
lv rebalance list --status applying
lv rebalance reject  <proposal-id> --reason "operator: not now"
```

---

## Metrics

The placement engine exports:

| Metric | Type | Labels |
|---|---|---|
| `litevirt_placement_decisions_total` | counter | `policy`, `result` |
| `litevirt_host_pressure` | gauge | `host`, `dim` |
| `litevirt_rebalance_proposals_pending` | gauge | `policy` |
| `litevirt_rebalance_proposals_total` | counter | `status` (applied / failed / rejected / expired terminal; approved / applying in-flight) |

Recommended alerts:

| Condition | Threshold |
|---|---|
| Cluster has hosts with pressure > 0.9 sustained | 5 min |
| Pending proposals not approved | > 1 day |
| Host pressure variance > 0.3 across cluster | 30 min (suggests rebalancer not approved) |

---

## Worked examples

### Single-tenant homelab — accept the default

Nothing to configure. Cluster runs `balance + dry-run`. The web UI's
**Cluster → Rebalance** page shows any drift; operator approves moves they
agree with.

### Service provider — auto-rebalance off-hours

```yaml
# /etc/litevirt/cluster.yaml
placement:
  mode: savings        # cluster-wide default applies to all stacks
```

Cluster fills hosts under bin-pack; off-hours, the rebalancer flattens any
imbalance. Operators almost never see proposals on prod hours.

### HA-critical database trio

```yaml
vms:
  db-1: { ... placement: { mode: ha-critical, anti-affinity: [db-2, db-3] } }
  db-2: { ... placement: { mode: ha-critical, anti-affinity: [db-1, db-3] } }
  db-3: { ... placement: { mode: ha-critical, anti-affinity: [db-1, db-2] } }
```

Three replicas always on three different hosts; if a host goes offline, the
rebalancer (`on-demand`) proposes a move that operators approve.

### Mixed batch + prod cluster

```yaml
vms:
  batch-render-1:
    placement: { policy: bin-pack, rebalance: { mode: off } }
  prod-api-1:
    placement: { policy: spread-strict, rebalance: { mode: on-demand } }
```

The same cluster runs both. The rebalancer evaluates each VM under *its own*
policy — batch jobs stay concentrated, prod stays spread.

---

## Architecture

```
                                Daemon (every host)
                                     │
                       ┌─────────────┼─────────────┐
                       │             │             │
                  ┌────▼──┐    ┌─────▼─────┐  ┌────▼────────┐
                  │Failover│   │Rebalancer │  │Health      │
                  │ coord. │    │  coord.  │  │ checker    │
                  └────┬───┘    └────┬─────┘  └────┬───────┘
                       │             │             │
                       │   leader-election lease   │
                       │   (one row per coord type)│
                       │             │             │
                  ┌────▼─────────────▼─────────────▼────┐
                  │            Corrosion CRDT            │
                  │                                      │
                  │   hosts, vms, host_health,           │
                  │   leader_election,                   │
                  │   rebalance_proposals,               │
                  │   ip_allocations, ...                │
                  └──────────────────────────────────────┘

Placement engine (internal/placement/):
   ClusterSnapshot ─────→ scoreCandidates ─→ pickBest
       (one read)            ↑
                             Dimension[]
                             (CPU, RAM, NUMA, …)

Rebalancer (internal/scheduler/):
   periodic 60s ──→ resolveVMPolicy(vm)
                ──→ for each VM: bestMove = RankFromSnapshot (full hard filters)
                ──→ commit-in-snapshot → next VM's scoring sees update
                ──→ write rebalance_proposals row
                ──→ if mode=auto: mark approved

Rebalance executor (internal/grpcapi/, leader-gated):
   periodic 30s ──→ claim approved rows (approved → applying)
                ──→ re-validate against live state
                ──→ MigrateVM (live)  → applied | failed
                ──→ honor concurrency + hourly budget; reap stale applying rows
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| VM creation fails with "no eligible host found … strict-spread pressure cap" | `spread-strict` would put all candidates above 50% on a wired dimension | Add hosts, or relax to `policy: balance` |
| Rebalancer proposes nothing despite obvious imbalance | All VMs in `mode: off` | Set `mode: dry-run` cluster-wide |
| Same VM proposed every cycle | Cooldown only suppresses the *same* VM after a successful proposal write | Approve (the executor applies it) or reject the proposal; cooldown then takes effect |
| Approved proposal never applies | Not the leader, or cluster budget exhausted (`applying` ≥ MaxConcurrent / `applied` ≥ MaxPerHour this hour), or it failed re-validation | `lv rebalance list --status applying\|failed`; check `detail`; confirm a leader holds the `rebalancer` lease |
| Bin-pack doesn't concentrate | Hosts have unequal capacity → balance-style spread emerges naturally even under bin-pack scoring | Use placement labels to tier hosts |
| Cost-aware ignores `cost.hourly` label | Label format must be parseable as a positive float | `cost.hourly: "0.10"` not `cost.hourly: cheap` |

---

## Migrating from earlier defaults

If you were running litevirt before the placement-engine rewrite:

- **The default placement policy changed from bin-pack to balance.** New VMs spread by default. To restore the old behavior cluster-wide:
  ```yaml
  # /etc/litevirt/cluster.yaml
  placement: { policy: bin-pack, rebalance: { mode: off } }
  ```
- The old `placement.spread: true` flag still works (translates to
  `policy: spread-strict`). Migrate to `policy:` when convenient.
- New tables: `rebalance_proposals`. Auto-created by the schema migration.
- New gRPC: `ListRebalanceProposals`, `RunRebalance`,
  `ApproveRebalanceProposal`, `RejectRebalanceProposal`.
- New CLI: `lv rebalance` group.
- New metrics: `litevirt_host_pressure`, `litevirt_rebalance_*`.
