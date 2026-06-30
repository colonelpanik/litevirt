# Cluster diagnostics

Tools for inspecting and repairing cluster-state health. The **divergence
scanner** (`lv doctor divergence`) is strictly read-only — it never writes or
merges state. **Repair commands** under `lv doctor` (e.g. `repair-owner`,
below) are intentionally mutating and audited; each is called out as such.

## `lv doctor divergence`

Read-only.



Scans every active node and reports replicated rows that **disagree across nodes**,
plus cluster-wide **semantic-invariant violations**. This is the pre-remediation
evidence-capture step for the equal-timestamp last-writer-wins repair: run it
*before* any change to merge behavior, because convergence destroys the per-node
evidence.

```
lv doctor divergence [--json] [--table <name>]... [--include-sensitive]
```

Admin-only. The daemon you call fans out to every active peer (over peer mTLS),
compares per-row metadata, and returns a classified report.

### What it detects

**Diverging rows** — for each primary key, how the row differs across nodes:

| Class | Meaning |
|---|---|
| `equal_updated_at_different_content` | Same PK, **same `updated_at`** on every node, different content — the pathological LWW tie that never re-converges. |
| `stuck_different` | Different `updated_at` that **persisted across both samples** — a converged-wrong or lost-write split. |
| `different_updated_at` | (Transient) usually in-flight replication; only reported as `stuck_different` if it survives resampling. |
| `missing_row` | Present on some nodes, absent on others. |
| `tombstone_vs_live` | Tombstoned (soft-deleted) on some nodes, live on others. |
| `terminal_vs_live` | A workload terminal (stopped/error) on some nodes, running on others. |
| `schema_shape_mismatch` | The table's column set differs across nodes. |

A divergence is reported **only when it persists across two samples** with
unchanged per-node content hashes — an in-flight replication delta changes between
samples and is filtered out.

**Semantic-invariant violations** — states that survive convergence (every node
holds the *same* rows, digests match, a dump-diff is clean) yet are *jointly*
illegal:

- `duplicate_live_container` — the same container name live on more than one host
  (a cross-host ownership split the per-row resolver structurally can't see).
- `duplicate_ip_owner` — one IP owned by more than one workload. Owner identity is
  fully qualified (`vm:<name>`, `ct:<host>:<name>` with `owner_kind`/`owner_host`),
  so two same-named containers on different hosts are never collapsed into one
  owner.

> **Not yet covered (deferred to a later phase):** *duplicate runtime ownership*
> and *runtime-vs-DB owner mismatch* — i.e. the DB rows have converged but disagree
> with which host actually runs the workload. Detecting those requires per-host
> runtime introspection (`CheckVMRuntime`/`CheckContainerRuntime`), which lands with
> the runtime-repair phases; until then `lv doctor divergence` checks only the
> DB-level invariants above. A clean report does **not** yet prove the DB agrees
> with runtime truth.

### The sensitive lane

`--include-sensitive` also scans secret-bearing tables (2FA factors, recovery
codes, registry credentials, notification targets). Those tables' primary keys and
content are themselves secret — a `recovery_codes` PK contains a bcrypt hash — so
the lane **never returns raw PKs or plaintext**. Each node computes
**domain-separated keyed HMACs** of its rows under a single random per-scan key
distributed to peers only over the peer-mTLS channel (never logged). Identical rows
produce identical HMACs across nodes, so divergence is still detectable, while a
different scan reveals no cross-scan equality.

### Reachability, partials, and stability

Comparison runs only over nodes reachable **in both samples** (per lane). A node
that flaps between samples is excluded from row classification — so its absence
can't fabricate a `missing_row` — and surfaced in `nodes_unreachable`. Under
`--include-sensitive`, a host whose sensitive (HMAC) lane fails is listed in
`sensitive_unreachable`: its secret-bearing tables were **not** scanned, so the
sensitive result is partial for that host and never silently "clean".

The report's `stable` flag is true only when the cluster was **quiescent** across
the scan: the reachable node set was identical in both samples **and** no scanned
table's content changed between them. When `stable` is false, a reported
`stuck_different` may be lagging replication backlog rather than a true permanent
split — re-run once the cluster settles. An unknown `--table` value is rejected
outright rather than scanning nothing.

### Output

Human-readable table by default; `--json` for the full structured report (node
lists incl. `sensitive_unreachable`, per-row per-node `updated_at`/hash, `stable`,
and violations). `--table` restricts the scan to specific tables.

## Equal-timestamp tie resolution

Strict last-writer-wins settles every conflict whose `updated_at` values differ.
An **exact** tie (byte-equal instant) with differing content is the pathological
case `equal_updated_at_different_content` above: keeping local on the tie is a
per-node choice, not a cluster total order, so the two values never re-converge.

On an exact tie the merge consults a **table-aware resolver**. Every replicated
table is assigned exactly one resolution chain (enforced by coverage tests — a new
table cannot silently get a default). A chain is either a deterministic total
order (both nodes pick the same winner, so the row converges) or it deliberately
**refuses to converge** and leaves the row for a human / runtime repair:

| Category | Tables | On an exact tie |
|---|---|---|
| content-default | inventory/config tables with no authorization, isolation, runtime, or auth meaning (`images`, `hosts`, `dns_records`, …) | a one-sided soft-delete wins, else the canonically-greater row wins (deterministic; converges) |
| runtime-owned | `vms.host_name` | **unresolved** — never adopt an owner by value (it could name a non-running host); defer to runtime repair |
| tenancy | `project` on `vms`/`containers`/`networks`/`storage_pools`/`volumes`, `project_name` on `backup_schedules` | **unresolved** when the tenancy column differs (a content-max could silently move a resource between tenants) |
| policy | `roles`, `role_bindings`, `users`, `tokens`, `projects`, firewall/SG tables, secret-bearing config | a delete wins, else **unresolved** (a value tiebreak could converge to the more-permissive grant) |
| auth | `user_2fa` (replay ratchet → max; consume/tombstone irreversible), `recovery_codes`, the active-set pointers | converging rules where safe, else **unresolved** (never resurrect a superseded factor/code) |
| LB | `lb_configs`, `lb_backends` | a non-empty incarnation token beats empty; two different non-empty tokens are **unresolved** |

`containers` ownership is part of the primary key, so an ownership split is two
distinct rows (not a single-row tie) — detected by `duplicate_live_container`
above and repaired by the container runtime-repair phase, not the row resolver.

The anti-entropy merge is the authority; the WAL fast-path resolves full-image
upserts through the same engine and otherwise keeps local and lets anti-entropy
converge the row, so the two paths can never disagree.

### Metrics & repairing an unresolved tie

- `litevirt_lww_tie_break_total{table,resolver,winner}` — ties that converged. A
  steadily climbing value means a node is minting colliding timestamps (the
  upstream smell), not just a one-off split.
- `litevirt_lww_tie_unresolved_total{table,path,category}` — **distinct** ties
  with no safe winner (counted once per row, not per cycle). Any nonzero value is
  alert-worthy: the row is intentionally left divergent and needs operator or
  runtime repair.

The **signal** is bounded — `lww_tie_unresolved_total` counts a row once and the
alert fires once per distinct divergence, not per cycle. The **divergence itself
is not suppressed**: while a row remains unresolved its table's digest stays
mismatched, so anti-entropy may continue to re-pull that table each cycle until
the row is repaired (a row-proofed suppression that re-pulls only when an
unrelated row also diverges is a future optimization). In practice this cost is
paid only by genuinely-stuck rows awaiting repair.

Resolve an unresolved row by making one side authoritative with a fresh write —
which clears the tracking and lets the table converge. A VM ownership split is
repaired with `lv doctor repair-owner <vm> <host>` (re-stamps the running host
with a new timestamp so it wins everywhere by ordinary LWW).
