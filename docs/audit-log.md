# Audit log: hash chain and WORM export

litevirt records every operator-initiated action in the `audit_log`
table — user, action, target, result, timestamp. To make the log
tamper-evident the rows are linked into a SHA-256 hash chain so an
auditor can prove no row has been altered or removed since it was
written.

**Per-host sub-chains.** `audit_log` is a *multi-writer* table: every daemon
appends its own rows and they all replicate cluster-wide via Corrosion. A single
global chain therefore can't stay linear — two hosts appending concurrently
interleave by timestamp and fork it. Instead **each host maintains its own
sub-chain**: a row's `prev_hash` links to the previous row written by the *same*
host. A daemon only ever authors rows for its own host, so each sub-chain is
local and immune to cross-host interleaving or replication ordering, and
`verify` validates each host's sub-chain independently.

The chain logic lives in `internal/corrosion/audit.go` (`InsertAuditLog`,
`VerifyAuditChain`, `ResealAuditChain`) and the `audit_log` table in
`internal/corrosion/schema.go`. Operator surface is `lv audit ls / verify /
export` plus the matching gRPC + REST RPCs.

## Schema

Two columns join the audit row to the chain:

| Column | Type | Set on |
|---|---|---|
| `host_name` | TEXT | the host that authored the row — the sub-chain key |
| `prev_hash` | TEXT (SHA-256 hex) | every new row — the previous **same-host** row's `content_hash` |
| `content_hash` | TEXT (SHA-256 hex) | every new row — `SHA256(prev_hash || canonical(row))` |

The first row of each host's sub-chain has `prev_hash = NULL`. Rows with a NULL
`content_hash` (written before the chain columns existed) **and** rows with no
host identity (background-context writes such as the failover coordinator's, now
stamped with the host going forward) are treated as **chain-reset points** —
verification accepts them without a linkage check and continues. So audit logs
migrated from older binaries don't reject; they just have unverified gaps.

Each daemon **re-bases its own host's sub-chain at startup** (idempotent): rows
written under the pre-v1.0.16 global-chain model are re-linked per host the first
time the upgraded daemon runs, so `verify` passes right after a rolling upgrade
without operator action.

Timestamps are RFC3339 with nanosecond precision so same-second
inserts sort deterministically. Without nanoseconds, two events
within the same second could swap order between reads, and the chain
would compute different hashes.

## Reading

```bash
lv audit ls [--limit 50]                      # Tail recent entries (default 50)
lv audit ls --target /projects/acme --action vm.start
```

`--target` matches the exact target path; `--action` matches an action,
with a trailing `*` acting as a prefix glob; `--user` filters by
username; `--since` takes an RFC3339 timestamp (entries at/after it).

Use cases:
- Who started VM `web-1`? — `lv audit ls --target vms/web-1 --action vm.start`
- What did `alice` do today? — `lv audit ls --user alice --limit 200`
- What touched the firewall recently? — `lv audit ls --action 'sg.*' --since 2026-06-01T00:00:00Z`

## Verifying

```bash
lv audit verify
# OK: verified 12,847 rows; first broken=<none>
```

`verify` walks **each host's sub-chain** (rows ordered by `host_name`, then
timestamp, then id), recomputes each row's hash against the previous same-host
row, and stops at the first mismatch. If it returns a broken row id, that host's
audit sub-chain has been tampered with at or before that row. Common causes:

- A row was deleted (the next same-host row's `prev_hash` no longer matches).
- A row was edited (its own `content_hash` no longer matches).
- A schema migration replayed the table without rebuilding hashes
  (operator error — re-run audit-log import with the chain rebuilder).

The verify check is also exposed as the `VerifyAuditChain` gRPC RPC
and the `/api/v1/audit/verify` REST route, so a monitoring system can
poll it periodically.

## WORM export

```bash
lv audit export > audit.json
lv audit export --out audit.json                 # write directly to a file
lv audit export --since 2026-06-01T00:00:00Z --until 2026-06-30T23:59:59Z --out june.json
# {"rows": [
#   {"id":1,"prev_hash":null,"content_hash":"abc...","timestamp":...},
#   ...
# ]}
```

`export` emits a JSON document suitable for write-once-read-many
offload (S3 Object Lock, immutable filesystem snapshot, tape archive).
`--out <file>` writes the JSON to a file (default stdout); `--since` /
`--until` bound the export window (both RFC3339, inclusive).
The export includes every chain field so an external system can
re-verify without contacting the daemon.

Pair with the cluster's storage offload (Ceph snapshot, ZFS send to a
WORM target, periodic rsync to glacier) for a tamper-evident regulator
trail. Operators in regulated environments typically export daily and
sign the resulting JSON with a separate signing key.

## Operational notes

- The chain is **per-cluster**, not per-host. Audit rows replicate via
  Corrosion like any other table; the chain hashes are computed on
  the writer host at insert time and replicated as a normal column
  value. Two hosts inserting simultaneously each link to whichever
  row their own HLC saw last — a slight ambiguity that does not
  weaken tamper-detection (a missing row still breaks the chain).
- A clock skew that violates HLC's `MaxSkewMS` is clamped, so a wildly
  wrong host clock cannot reorder audit rows in a way that breaks the
  chain.
- Verification is O(N) over chain length. For long-running clusters,
  consider running `verify` on a schedule and storing the result as a
  metric — `litevirt_audit_chain_last_verified_ok` is on the roadmap.
