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
| `dry-run` (recommended default) | Proposals written to `rebalance_proposals` table; never applied. Operator reviews via `lv rebalance list`. |
| `on-demand` | Proposals written; require explicit `lv rebalance approve <id>` before the migration controller picks them up. |
| `auto` | Proposals written and immediately approved (subject to budget). Migration controller executes them. |

### Per-VM cooldown and per-cluster budget

- **Cooldown**: same VM is not re-proposed within `placement.rebalance.cooldown` (default 5 min).
- **Per-cycle cap**: at most `MaxConcurrent` proposals per cycle (default 2).
- **Hourly cap**: rebalancer skips a cycle if `MaxPerHour` proposals have been applied in the last 60 minutes (default 10).
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

# Approve / reject a pending proposal
lv rebalance approve <proposal-id>
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
| `litevirt_rebalance_proposals_total` | counter | `status` (applied / approved / rejected / expired) |

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
                ──→ for each VM: find bestMove via dimensional gain
                ──→ commit-in-snapshot → next VM's scoring sees update
                ──→ write rebalance_proposals row
                ──→ if mode=auto: mark approved
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| VM creation fails with "no eligible host found … strict-spread pressure cap" | `spread-strict` would put all candidates above 50% on a wired dimension | Add hosts, or relax to `policy: balance` |
| Rebalancer proposes nothing despite obvious imbalance | All VMs in `mode: off` | Set `mode: dry-run` cluster-wide |
| Same VM proposed every cycle | Check it's NOT actually being applied; cooldown only suppresses the *same* VM after a successful proposal write | Apply or reject the proposal; cooldown will then take effect |
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
