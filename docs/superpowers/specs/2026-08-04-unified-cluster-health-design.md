# Unified cluster health, effective capacity, and admission safety (v50)

Status: implemented (schema v50). Companion to
[2026-08-01-split-brain-ownership-generations-design.md](2026-08-01-split-brain-ownership-generations-design.md),
which this extends: the ownership-generations design gave the cluster proof
machinery; this gives it a durable memory, one health surface, and an
admission policy that reads the same state the operator does.

## Why one durable health model

Before v50 the cluster's knowledge about its own safety was scattered across
four places with four lifetimes: a replicated connectivity matrix
(`host_health`), a per-leader in-memory dual-run debounce, an alerts field no
release ever populated, and log lines. The failure modes followed directly:

- a detector leadership handover **re-armed the debounce** and silently
  un-confirmed standing findings — a split-brain page could vanish because a
  lease moved;
- admission could not consult what the detector knew, so a create could land
  on a host the detector had just watched double-running a disk;
- the operator's view (`lv health`) and the machinery's view could disagree,
  because they read different state.

The v50 model stores conditions as **replicated rows** (`health_conditions`),
keyed by `(evaluator, code, subject_kind, subject_id)`, with the evaluator's
scan coverage in `health_evaluator_status`. Health is cluster STATE: it must
survive restarts and leader changes, converge on every node, and be the one
thing every consumer — CLI, REST, MCP, UI, dashboard, and **admission** —
reads. Events and notifications are outputs of lifecycle *transitions*, never
the state itself.

## Condition lifecycle

```
            positive scan            2nd consecutive          2 consecutive complete
   (none) ───────────────► observed ───────────────► confirmed ───────────────► resolved
                            warning                   critical*                 (30-day history,
                                                                                 then tombstoned)
```

- The **first** positive observation writes an `observed` row at warning
  severity. Positive evidence is recorded **without quorum**: refusing to
  write down corruption because the cluster is degraded would hide exactly
  the state an operator needs most.
- The **second consecutive** positive scan confirms. Confirmed VM/CT/VIP
  dual-run, runtime-owner mismatch, and owner-epoch mismatch are *critical*;
  coverage gaps and unresolved ties stay degraded *warnings* unless they
  accompany positive corruption evidence (which then carries its own critical
  row).
- **Resolution is stricter than observation**: two consecutive clean scans
  with COMPLETE coverage (no unreachable, partial, or unsupported peer), by
  the detector lease holder, while its decision gate is valid. An incomplete
  scan can neither resolve nor reset the observation streak — it proves
  nothing about absence. Blind is not clean.
- Leadership changes preserve counts and confirmed state — the rows are the
  state, and the new leader's first pass continues them exactly.
- There is **no operator force-clear API**, deliberately. Operators remove
  the cause; evaluators prove the resolution. A force-clear would make the
  health record say what someone wished, not what was measured — and
  admission acts on this record.

## Health aggregation (`GetClusterHealth`)

One RPC returns conditions, evaluator coverage, the connectivity mesh, and
per-host capacity assessments, rolled into one overall state:

| overall  | meaning |
|---|---|
| CRITICAL | any ACTIVE critical condition (observed included — the operator should be looking before the confirm lands) |
| DEGRADED | warning conditions, incomplete evaluator coverage, or an incomplete capacity observation |
| UNKNOWN  | no evaluator has ever completed a scan — nothing watching is not nothing wrong |
| HEALTHY  | none of the above |

`lv health` exits 0/1/2 for HEALTHY / DEGRADED-or-UNKNOWN / CRITICAL, via a
silent typed exit — a report ending `overall: CRITICAL` is the answer, and is
not followed by a generic error line.

## One runtime-inventory source

`GetRuntimeInventory` (peer-only) is the single local-truth collector behind
the detector, owner assertion, owner-epoch readiness, capacity sampling, and
health evidence. Per workload it reports kind, name, runtime state,
disk-holder status, the runtime's OWN configured size, the host-local
owner-epoch marker classified `valid|missing|corrupt|unreadable`, an
uncapped flag, and per-item probe errors — plus kernel VIPs, the
unresolved-tie count, and an honest completeness flag. The collector reads
local runtime truth ONLY; database comparison is the caller's job, because
the database is exactly the disputed value the callers corroborate against.

## Effective capacity

Each host publishes `host_capacity_observations` — the union of database and
runtime workloads:

- matching workload → charge the **greater** configured allocation;
- database-only running workload → keep the database charge;
- runtime-only workload → **add** its runtime allocation;
- an uncapped runtime-only container, or any probe failure → the observation
  is **incomplete**.

Placement counts the runtime-only extra against headroom and **refuses**
hosts whose observation is incomplete or stale. A never-sampled host stays
eligible: the owning host's admission always runs a fresh LOCAL inventory
comparison, so bootstrap cannot dead-lock on telemetry — and replicated
telemetry is never the final say on the host that must live with the
decision.

## Admission policy

One host-safety gate fronts every operator-driven create, start, restore,
migrate, placement, and resource-growth admission:

| condition | effect |
|---|---|
| VM/CT dual-run, runtime-owner mismatch, owner-epoch mismatch (ACTIVE — observed or confirmed) | blocks capacity-growing admission to every involved host; blocks runtime-changing actions on the affected workload anywhere |
| incomplete/stale runtime inventory | blocks NEW residency on that host (fresh local probe at admission; replicated observation at placement) |
| VIP dual-run | blocks that VIP's LB/ownership changes; deliberately does NOT block unrelated VM placement |
| unresolved ties | block the affected ownership transition when the subject is known |

`--allow-overcommit` bypasses **numeric headroom only** — the overcommit
draw path consults the same gate. Automated recovery may restore an
already-database-accounted workload, but never adds an unaccounted holder
and never acts on a workload with an active ownership condition: restarting
one side of a dual-run is exactly how a transient condition becomes a
corrupted disk.

## Owner-epoch corrections

`owner_epoch_v1` readiness now proves runtime truth, per node (the latch
requires every node, so the fleet-wide AND emerges): a fresh complete local
scan, every owned workload's epoch nonzero, every RUNNING workload's marker
valid and equal to its DB epoch, no unresolved ties, and no active ownership
condition anywhere. The latch stays monotone; later violations become the
`owner_epoch_mismatch` condition (critical) and block unsafe actions through
the admission gate — the latch never re-opens.

Automated owner assertion re-keys only on **exact-marker proof**: the local
marker valid and exactly equal to the DB epoch being superseded, every
workload-capable peer completely probed and proving absence, no
migration/pending operation/lock, and a valid execution gate. Missing,
corrupt, unreadable, unequal, or ambiguous evidence refuses, each with a
distinct observable reason.

## Future containment contract (documentation only)

No automatic destruction exists, and no configuration switch enables any.
This is deliberate: today's evidence cannot always distinguish the
authoritative holder from the stale one, and a wrong kill is strictly worse
than a paged dual-run. If containment is ever implemented, it must require —
before stopping anything:

1. complete fleet runtime coverage (every workload-capable host fully
   probed, no partial or unsupported peers);
2. a current-epoch authoritative holder, proven by a valid marker equal to
   the current DB epoch;
3. a strictly OLDER conflicting holder (marker proof, not inference);
4. no migration, pending operation, workload lock, or failover in flight;
5. quorum, or exact fencing authorization, for the decision;
6. durable evidence and the decision itself recorded (a condition row plus
   audit) BEFORE any stop is issued.

Anything less re-creates the failure this architecture exists to prevent:
acting on a view that cannot prove which side is real.
