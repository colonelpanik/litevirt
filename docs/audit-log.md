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
# audit chain intact: 12847 rows verified, all signed
```

`verify` walks **each host's sub-chain** (rows ordered by `host_name`, then
timestamp, then id) and recomputes each row's hash against the previous
same-host row. On top of that it checks each row's signature, its per-host
sequence number, and the signed chain heads — a hash can be recomputed by
whoever edited the row, a signature cannot.

It does **not** stop at the first problem. One broken id says nothing about
whether the rest of the log was rewritten too, so every finding is printed,
grouped by what it means:

- **hash mismatch** — a row was edited, or a row before it was deleted, or a
  migration replayed the table without rebuilding hashes (operator error).
- **bad signature** — the row was edited by someone without the authoring
  host's key. This is the finding that survives a reseal.
- **unknown key** — the signer has no published certificate that chains to the
  cluster CA.
- **sequence gap** — a run of rows was deleted from one host's chain.
- **laundered** — a row blanked its own hash to pose as a pre-chain reset point.
- **truncated** — a host's signed chain head attests to more rows than exist.

Any of those exits non-zero and prints `AUDIT CHAIN TAMPERED`.

**Unsigned rows are not tampering.** Rows written before signing was switched on
carry no signature; they are chain-checked only, reported as a count on the
clean line, and exit 0. Same for rows this daemon had no keyring to check and
rows carrying no host name — both mean part of the log went unchecked, not that
it was altered.

The verify check is also exposed as the `VerifyAuditChain` gRPC RPC
and the `/api/v1/audit/verify` REST route, so a monitoring system can
poll it periodically. The REST route always emits every field, including
`tampered: false` — so an alert can key on the field's value and never confuse
a clean chain with a daemon too old to report one.

## Rotating a host's signing key

```bash
lv host rotate-audit-key host-b
lv host rotate-audit-key host-b --ssh root@10.0.50.11   # name isn't the address
```

Rotate when a host's signing key **may have been exposed** — most concretely, any
node provisioned by an `lv host init` old enough to have pushed
`/etc/litevirt/pki/host.key` mode 0644, which any local user could read. The
daemon tightens the mode to 0600 when it finds it loose, but tightening does not
undo a copy already taken: whoever has one can still sign rows as that host.

The command **must run from the node that holds the cluster CA private key** (the
one that ran `lv host init`). There is no CSR flow, so no other machine can have
a certificate signed — for itself or anyone else. It mints the pair locally into
a temp dir, pushes `audit-signing.crt` (0644) and `audit-signing.key` (0600), and
**restarts litevirt on the target**, because the signing keyring is loaded once
at boot. `host.crt` / `host.key` are not touched: those are the identity the gRPC
listener serves, the one the health checker dials peers with, and the target of
the libvirt symlinks `qemu+tls://` migration follows — none of which reload
without a restart, so rotating them would put quorum and any in-flight migration
at risk. That separation is the reason the audit key is its own certificate.

On the next start the daemon publishes the new certificate, retires the old key
at the sequence its chain has reached, and signs a chain head **with the new key**
over the whole existing log. That last step is what rotation is for: from then on,
altering any row the old key wrote contradicts a head whoever holds that key
cannot forge. What it cannot do is repair a log that was already forged before
anyone noticed — no scheme can.

Rows signed by the retired key **stay verifiable forever**. The retired
certificate is marked retired, never deleted, so `lv audit verify` can still
resolve it — deleting it would make every row it signed unverifiable, and a
rotation performed to improve integrity would destroy the history it was
protecting. What retirement adds is a boundary: use of the old key past the
sequence it was retired at is itself a finding.

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

- **The rows are per-cluster; the hash chain is per-host.** Audit rows
  replicate via Corrosion like any other table (append-only,
  `INSERT OR IGNORE`), so every host sees every row. The chain hashes are
  computed on the writer host at insert time and replicated as normal
  column values, but each row's `prev_hash` links only to the previous row
  written by the **same** host — so each host has an independent sub-chain.
  `verify` walks the rows ordered by `host_name` and validates each host's
  sub-chain against a per-host running tail. Because a host only authors its
  own rows, concurrent inserts on different hosts can't fork a single chain,
  and a missing or altered row still breaks that host's sub-chain.
- A clock skew that violates HLC's `MaxSkewMS` is clamped, so a wildly
  wrong host clock cannot reorder audit rows in a way that breaks the
  chain.
- Verification is O(N) over chain length, and the daemon runs it hourly on
  its own rather than waiting to be asked: a check that only happens when an
  operator types `lv audit verify` finds an intrusion after whatever prompted
  them to look. The outcome is published as
  `litevirt_audit_chain_last_verified_ok` (1 when the last check found no
  evidence of tampering), with a per-kind breakdown in
  `litevirt_audit_chain_findings` and a
  `litevirt_audit_chain_heads_published_total` counter. Alert on the first
  going to 0; a stalled head counter means truncation detection has quietly
  stopped.
