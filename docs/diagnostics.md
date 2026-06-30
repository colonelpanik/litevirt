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
| opaque definition | the workload/resource definition blobs: `vms.spec`, `containers.create_spec`, `networks.config`, `volumes.config`, `stacks.spec`/`compose_yaml` | **unresolved** when the blob differs — the canonical encoder orders specs by their length prefix, so content-max is an arbitrary, non-semantic tiebreak that could silently downgrade a live definition to a stale serialization; a human / runtime repair makes one side authoritative |
| tenancy | `project` on `vms`/`containers`/`networks`/`storage_pools`/`volumes`, `project_name` on `backup_schedules` | **unresolved** when the tenancy column differs (a content-max could silently move a resource between tenants) |
| policy | `roles`, `role_bindings`, `users`, `tokens`, `projects`, firewall/SG tables, secret-bearing config | a delete wins, else **unresolved** (a value tiebreak could converge to the more-permissive grant) |
| auth | `user_2fa` (replay ratchet → max; consume/tombstone irreversible), `recovery_codes`, the active-set pointers | converging rules where safe, else **unresolved** (never resurrect a superseded factor/code) |
| LB | `lb_configs`, `lb_backends` | a non-empty incarnation token beats empty; two different non-empty tokens are **unresolved** |

A table can mix categories in one chain — e.g. `vms` resolves a `host_name` tie as
runtime-owned, a `project` tie as tenancy, a `spec` tie as opaque, and any other
column tie by content-max — applied in that order, first strict decision wins.

`containers` ownership is part of the primary key, so an ownership split is two
distinct rows (not a single-row tie) — detected by `duplicate_live_container`
above and repaired by the container runtime-repair phase, not the row resolver.

The anti-entropy merge is the authority; the WAL fast-path resolves full-image
upserts through the same engine and otherwise keeps local and lets anti-entropy
converge the row, so the two paths can never disagree.

### Metrics

- `litevirt_lww_tie_break_total{table,resolver,winner}` — ties that converged by a
  deterministic resolver (`content_max`/`numeric_max`/`timestamp_max`/
  `non_null_wins`/`lb_generation`). A steadily climbing value means a node is
  minting colliding timestamps (the upstream smell), not just a one-off split.
- `litevirt_lww_tie_unresolved_total{table,path,category}` — **monotonic counter**
  of distinct unresolved ties *observed* (counted once per row, not per cycle).
  Use `increase(...)` to alert on "a new unresolved tie appeared" — a bare `> 0`
  would page forever, since a counter never decreases. `category` ∈
  {`runtime_owned`, `opaque`, `tenancy`, `policy`, `control_plane`, `auth_factor`,
  `auth_pointer`, `lb_token`}.
- `litevirt_lww_tie_unresolved_current` — **gauge**: distinct ties this node is
  *currently* tracking as unresolved. Drops back to 0 when the rows are repaired
  (the per-(table,PK) tracking is cleared on any newer write). This is the right
  signal for "something is divergent right now."
- `litevirt_lww_tombstone_tie_total{table}` — ties a one-sided soft-delete settled
  (a delete racing a write). Benign and expected; tracked separately so it doesn't
  muddy the tie-break smell.
- `litevirt_runtime_owner_assert_total{kind,result}` — runtime ownership repair
  outcomes. `kind` ∈ {`vm`, `ct`}; `result` ∈ {`asserted`, `rekeyed`,
  `split_brain`, `inconclusive`, `error`}. A `split_brain` is a workload running on
  two hosts at once → page; sustained `inconclusive` means a peer the repair needs
  is unreachable.

### Alerts

```promql
# Something is divergent RIGHT NOW (clears automatically on repair — gauge, not counter).
max(litevirt_lww_tie_unresolved_current) > 0
# A NEW auth/policy-critical unresolved tie appeared — page distinctly (use increase,
# since the _total series is a monotonic counter that never returns to 0).
increase(litevirt_lww_tie_unresolved_total{category=~"auth_factor|auth_pointer"}[15m]) > 0   # auth_unresolved_tie
increase(litevirt_lww_tie_unresolved_total{category="policy"}[15m]) > 0                       # policy_unresolved_tie
# Sustained ties ⇒ a node is minting colliding timestamps (an upstream clock/ID bug).
# Tombstone ties (a delete racing a write) are benign individually but, if sustained,
# are the same colliding-timestamp evidence — include at a lower severity.
rate(litevirt_lww_tie_break_total[15m]) > 0
rate(litevirt_lww_tombstone_tie_total[15m]) > 0   # lower severity
# A workload running in two places at once — page immediately.
increase(litevirt_runtime_owner_assert_total{result="split_brain"}[10m]) > 0
```

The **signal** is bounded — `lww_tie_unresolved_total` counts a row once and the
alert fires once per distinct divergence, not per cycle. The **divergence itself
is not suppressed**: while a row remains unresolved its table's digest stays
mismatched, so anti-entropy may continue to re-pull that table each cycle until
the row is repaired (a row-proofed suppression that re-pulls only when an
unrelated row also diverges is a future optimization). In practice this cost is
paid only by genuinely-stuck rows awaiting repair.

Resolve an unresolved row by making one side authoritative with a fresh write —
which clears the tracking and lets the table converge.

### VM ownership ties — automatic and manual repair

A `vms.host_name` split is the runtime-owned category: the resolver keeps it
local (never picks an owner by value) and defers to runtime repair.

- **Automatic (runtime owner-assert).** Each host's reconciler watches for a VM
  that runs **locally** but whose DB row points at another host. Before
  reclaiming it, it queries **every workload-capable peer's local libvirt** (the
  peer-only `CheckVMRuntime` RPC) and re-stamps ownership to itself **only when
  all of them answer `absent`**, no migration/lease marker is present, and the
  condition has persisted past a short debounce. If any host reports `running`
  it's a true split-brain → it refuses to act and logs an alert (destruction
  needs fencing proof, never a host-order coin-flip). If any host is unreachable
  or holds a stale definition → inconclusive → it retries later. This is why a
  segmented host's VM (e.g. one the rest of the fleet can't reach) is left for
  manual repair rather than auto-reclaimed.
- **Manual.** `lv doctor repair-owner <vm> <host>` forwards to `<host>`, which
  re-stamps ownership only if it confirms the VM runs there locally. Use it for
  the segmented case, or to force a specific owner the operator knows is correct.

Either way the fresh timestamp wins everywhere by ordinary LWW and clears the
unresolved tracking.

### Container ownership — automatic runtime re-key

Container ownership is part of the primary key `(host_name, name)`, so an
ownership split is **two distinct rows**, not a single-row tie — the row resolver
can't see it (it's surfaced as `duplicate_live_container` above). The container
reconciler repairs it directly: when a container runs **locally** but its only
live DB row points at another host (and no live local row exists), it queries
**every workload-capable peer's local LXC** (the peer-only `CheckContainerRuntime`
RPC) and, only if none reports it running (a peer's stale *stopped* leftover does
not block; an unreachable/unknown peer does), performs an atomic **PK re-key** of
the container's whole ownership footprint: in one transaction it tombstones the
remote container row **and its managed `container_interfaces` rows**, inserts a
local row carrying the container's `create_spec` and a distinct
`runtime-owner-rekey` provenance marker, rebuilds the managed interface rows on
the local host (veth recomputed), and **transfers the IPAM leases**
(`owner_host`) — so firewall/SG binding, DNS/LB, quota, and IPAM ownership all
follow. It stands
clear of any container under an active relocation/restore/migration (PR #57
markers / `relocate_token`), skips ambiguous cases (a live local row, more than
one remote row, templates), and — like the VM path — only an active worker acts,
a peer reporting `running` is a logged split-brain (no re-key), and a debounce
guards the transition window.

## Operational repair flow

When `lv doctor divergence` reports rows (or an alert fires), work through them in
this order. The ordering is a **safety invariant**: the selfFence non-destruction
guard must be live on every node before the tie resolver runs anywhere, or a
converged-wrong `host_name` could drive a node to destroy a live workload.

1. **Capture evidence first.** Run `lv doctor divergence` (add `--json`) and save
   it — convergence destroys the per-node evidence, so this is your only snapshot
   of who-had-what.
2. **Roll the guard fleet-wide, then the resolver.** When deploying the LWW repair
   itself: get the selfFence guard onto *every* node first; only then roll the
   resolver. Mixed guard/no-guard during the resolver roll is the unsafe window.
3. **Classify each reported row:**
   - **`vms`/`containers` ownership** (`runtime_owned` / `duplicate_live_container`)
     — leave it to the **automatic runtime repair** (it reclaims on positive
     all-peers-absent proof), or force it: `lv doctor repair-owner <vm> <host>` for
     a VM, or for a container that the fleet can't auto-resolve (e.g. a segmented
     host) make the running side authoritative. Never destroy by host-order.
   - **`opaque` / `tenancy` / `policy` / `auth_*` / `lb_token`** — these are
     deliberately unresolved (a wrong auto-pick would lose data or escalate). Pick
     the correct side and make it authoritative with a fresh write **through the
     normal API** (e.g. re-save the VM spec, re-apply the role binding, re-enroll
     the factor). The fresh `updated_at` wins by ordinary LWW and clears the
     tracking.
   - **`schema_shape_mismatch`** — a column-order/shape skew from ALTER history,
     not an LWW tie; harmless but it keeps a table's digest mismatched. Normalize
     it on the next schema touch.
4. **Re-run `lv doctor divergence`** to confirm the row converged, and verify the
   live views agree (`lv ls`, `lv host ls`, per-host `virsh`/`lxc-info`).

> **Never edit `state.db` directly.** Every repair goes through the daemon (an API
> write or an audited `lv doctor` command) so it replicates and is auditable. A
> direct SQLite edit isn't replicated, isn't audited, and re-creates the very
> divergence you're fixing.
