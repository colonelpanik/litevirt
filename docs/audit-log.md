# Audit log: hash chain and WORM export

litevirt records every operator-initiated action in the `audit_log`
table — user, action, target, result, timestamp. To make the log
tamper-evident the rows are linked into a SHA-256 hash chain so an
auditor can prove no row has been altered or removed since it was
written.

The implementation lives in `internal/grpcapi/audit_chain.go` and the
`audit_log` table in `internal/corrosion/schema.go`. Operator surface
is `lv audit ls / verify / export` plus the matching gRPC + REST RPCs.

## Schema

Two columns join the audit row to the chain:

| Column | Type | Set on |
|---|---|---|
| `prev_hash` | TEXT (SHA-256 hex) | every new row — the previous row's `content_hash` |
| `content_hash` | TEXT (SHA-256 hex) | every new row — `SHA256(prev_hash || canonical(row))` |

The very first row in the chain has `prev_hash = NULL`. Pre-3.4 rows
(written before the columns existed) also have NULL hashes and are
treated as **chain-reset points** — verification stops there and
restarts on the next non-null entry. This means audit logs migrated
from older binaries don't reject; they just have unverified gaps
covering the pre-3.4 window.

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

`verify` walks the chain from the earliest non-null `prev_hash`, recomputes
each row's hash, and stops at the first mismatch. If it returns a
broken row id, the audit log has been tampered with at or before that
row. Common causes:

- A row was deleted (the next row's `prev_hash` no longer matches).
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
