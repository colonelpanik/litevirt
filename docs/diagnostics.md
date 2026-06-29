# Cluster diagnostics

Read-only tools for inspecting cluster-state health. They never write or merge
state.

## `lv doctor divergence`

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
- `duplicate_ip_owner` — one IP owned by more than one workload.

### The sensitive lane

`--include-sensitive` also scans secret-bearing tables (2FA factors, recovery
codes, registry credentials, notification targets). Those tables' primary keys and
content are themselves secret — a `recovery_codes` PK contains a bcrypt hash — so
the lane **never returns raw PKs or plaintext**. Each node computes
**domain-separated keyed HMACs** of its rows under a single random per-scan key
distributed to peers only over the peer-mTLS channel (never logged). Identical rows
produce identical HMACs across nodes, so divergence is still detectable, while a
different scan reveals no cross-scan equality.

### Output

Human-readable table by default; `--json` for the full structured report (node
lists, per-row per-node `updated_at`/hash, and violations). `--table` restricts
the scan to specific tables.
