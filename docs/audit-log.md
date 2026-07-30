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

**Signatures, not just hashes.** A hash chain proves nothing against an attacker:
`HashAuditRow` is deterministic and takes no secret, so anyone who can write the
table can edit a row and recompute every hash after it. Each row therefore also
carries an ECDSA signature by the authoring host's key. Three replicated tables
hold the evidence the verifier reasons over, and every row in all three is signed:

| Table | Holds |
|---|---|
| `audit_signing_keys` | each host's verification certificate, so any node can check any host's chain |
| `audit_chain_heads` | periodic signed "host H had written seq S, chain hashed to X" — the only thing that can detect a truncated tail, since a hash chain links backward and cannot notice its own end was cut |
| `audit_key_lifecycle` | signed `adopted` / `retired` events bounding each key's signing contract |

All three are append-only, and the verifier ignores `deleted_at` on them: a
retired certificate has to stay resolvable for as long as any row it signed
exists, so tombstoning evidence accomplishes nothing rather than needing a rule to
refuse it. A row deleted outright is re-inserted from a peer by ordinary
anti-entropy.

The keys are asymmetric rather than an HMAC on purpose. A host-local HMAC key
means only the host that wrote a row can check it, so a compromised host verifies
its own edited history and its neighbours cannot contradict it — and neighbours
noticing is the entire mechanism. A cluster-shared key means any one compromised
node can forge any other host's chain.

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

A daemon re-bases its own host's sub-chain at startup **only while that sub-chain
is entirely unsigned**: rows written under the pre-v1.0.16 global-chain model are
re-linked per host the first time the upgraded daemon runs, so `verify` passes
after a rolling upgrade without operator action.

The moment one signed row exists, the reseal stops touching that host. It used to
run unconditionally, and that was the single largest hole in the whole design —
reseal recomputes hashes from whatever the rows currently say, so an attacker with
database write access could edit a row, wait for a restart, and have the daemon
itself rewrite the chain around the edit. `verify` then came back clean. A signed
row is never resealed, locally or via replication, and the guard lives in the SQL
as well as the caller because peers apply that statement by primary key.

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
- **retired key used** — a row signed by a key past the sequence at which it was
  rotated out.
- **chain head mismatch** — a row covered by a signed head was rewritten.
- **unsigned after signed** — a host under a signing contract (see below)
  produced a row with no signature.

Any of those exits non-zero and prints `AUDIT CHAIN TAMPERED`.

**Unsigned rows on their own are not tampering.** Rows written before signing was
switched on carry no signature; they are chain-checked, reported as a count on the
clean line, and exit 0. Flagging them would put a permanent tamper verdict on
every cluster with any history, which is how a check gets ignored.

Rows this daemon had no keyring to check and rows carrying no host name are
neither a finding nor a pass: both mean part of the log went unchecked, not that
it was altered.

### The signing contract

Whether an unsigned row is evidence is decided by one replicated fact: **the
host's published signing certificate.** Publishing one is a CA-signed, per-host
declaration that this host's rows carry a signature from here on.

| State | An unsigned row from that host |
|---|---|
| certificate published, not retired | **tampering** (`unsigned after signed`) |
| certificate retired (signed) | expected — the host stopped, and said so |
| no certificate | pre-enforcement — counted, not flagged |

Three properties matter, and each closes a specific hole:

- **It is per host**, so a gradual rollout cannot false-fire. A host that has not
  published yet is simply not signing yet.
- **It has a start, and no start means no contract.** A certificate says a host
  commits, not *when* — and without the when, publishing one retroactively claims
  every row the host ever wrote. A signed `adopted` record carries the sequence
  the chain had reached when the key took effect; rows at or below it predate the
  commitment. A certificate with **no** verified adoption record is not a
  contract at all, because guessing "from row 0" is exactly the retroactive claim
  that made an ordinary upgrade report a cluster's whole history as tampering.
- **It is bound to the host that owns the key.** A signature proves who is
  speaking, not what they may speak about. Every lifecycle record is checked both
  ways: the signer's certificate must name the host in the record, *and* the key
  the record acts on must belong to that host, proved through the cluster CA.
  Without the second check a node could sign a perfectly valid record about
  somebody else's key.
- **It is not derived from the host's own config or its own log.** A node-local
  flag would let a compromised node declare itself exempt and report clean, and
  two nodes disagreeing about the same replicated rows would destroy the only
  reason to believe either. Asking "has this host signed before?" is worse still:
  the walk is ordered by attacker-chosen timestamps, and the question says nothing
  at all about a host that never managed to sign — which is exactly the case that
  matters.

That last point is why a host configured to sign publishes its certificate **even
when its private key will not load.** "The key is unreadable" is what an attacker
arranges with one `chmod`; it must not also be what makes a host look like one
that was never meant to sign.

The contract covers both the fabricated row inserted straight into the table — the
content hash is unkeyed, so recomputing it costs an attacker nothing, and the
missing signature is the only thing that distinguishes it — and a node that lost
its key and kept writing.

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

On the next start the daemon publishes the new certificate, then waits for
replication — about a minute — before recording a signed retirement of the old key
at the sequence its chain has reached and signing a chain head **with the new key**
over the whole existing log.

The wait is deliberate. Adoption and retirement are permanent sequence boundaries:
records are append-only and the strictest value wins, so one taken from a local
log that is still behind the cluster condemns rows the old key legitimately signed
and can never be raised again. `lv audit verify` will not show the rotation until
that has happened, and the command says so.

That head is what rotation is for: from then on, altering any row the old key
wrote contradicts an assertion whoever holds that key cannot forge. What rotation
cannot do is repair a log that was already forged before anyone noticed — no
scheme can, and claiming otherwise would be worse than saying so.

All of it happens **whether or not `enforcement.audit_signature` is on.** The flag
decides whether new rows get signed, not whether a rotation completes — a rotation
that quietly did nothing on a default-configured host would leave the leaked key
as the only published identity while the command reported the incident closed. The
command reads the flag off the target and tells you which of the two states the
host is in.

## Turning signing back off

Publishing a signing certificate declares that a host's rows are signed from that
point on. It is replicated and CA-signed, so a config edit on one machine cannot
quietly revoke it — a host that stops signing while that declaration stands has
every unsigned row reported as tampering on every node.

That is correct when someone took the key away, and wrong when the operator
simply changed their mind. The two are told apart by who can still sign:

- **Ordinary rollback** — set `enforcement.audit_signature: false` and restart.
  The daemon signs its own retirement at the sequence its chain had reached.
  Rows up to there stay verifiable; rows after it are unsigned and are no longer
  treated as evidence. No command needed.
- **The host cannot sign one** — key lost or unreadable, machine destroyed,
  decommission:

```bash
lv host retire-audit-key host-b
```

If a host somehow has more than one live certificate — a rotation that failed
part-way, or a spurious row filed under its name — the command refuses rather than
closing one and reporting success while the contract stays open. Retire them one
at a time until none remain.

Run it where the cluster CA private key is — the machine that ran
`lv host init`, which is normally an operator workstation rather than a cluster
member. Signing on another host's behalf means minting a certificate carrying that
host's name, which is exactly what holding the CA authorises and nothing else
does.

The signing happens **locally**, in two phases: the daemon reports which key would
be retired and at which sequence, writing nothing; the command mints, signs, and
submits; the daemon verifies against the cluster CA and records the result. The CA
private key is never sent to a node and never has to live on one.

### When the boundary itself is contested — `--at-seq`

The boundary is permanent. Lifecycle records are append-only and the earliest
verified retirement is the one that stands, so a boundary pinned below rows the key
legitimately signed reports those rows as retired-key use on every node forever,
with no way to raise it again.

So the command refuses to run from a node whose copy of the host's log a signed
chain head says is behind. That check counts heads signed by **the key being
retired**, deliberately: a host's chain heads are signed by its own keys, so
excluding them leaves the local tail as the only input at exactly the moment the
local tail is what is in doubt.

The cost is that whoever holds a leaked key can publish one head claiming any
sequence at all. It verifies — the leaked key's certificate still chains to the CA
and names the host — and it cannot be withdrawn, because heads are append-only,
tombstones are inert, and anti-entropy refuses rewrites. Left there, the leaked key
blocks the command that retires it.

Two ways past it:

```bash
lv host rotate-audit-key host-b            # seals the old key's history; needs no boundary
lv host retire-audit-key host-b --at-seq 4210
```

`--at-seq` names the boundary instead of deriving it, and skips the
lagging-replica refusal. It grants nothing new: completing a retirement already
requires minting a certificate with the cluster CA private key, so the only party
who can pass it is the only party who could retire the key at all, and both phase-2
signatures cover the value — a substituted one cannot be replayed. Establish how
far the chain actually reached before using it. A value below what the host really
signed is not recoverable.

An attacker cannot use either path to go quiet: producing a retirement means
holding the key and publishing a permanent, replicated statement of when signing
stopped.

Rows signed by the retired key **stay verifiable forever**. The certificate is
never deleted, so `lv audit verify` can still resolve it — deleting it would make
every row it signed unverifiable, and a rotation performed to improve integrity
would destroy the history it was protecting. What retirement adds is a boundary:
use of the old key past the sequence it was retired at is itself a finding.

A key's contract is one `adopted`..`retired` interval. Once retired, that key is
finished: re-enabling `enforcement.audit_signature` will not resume signing with
it — the daemon says so and points at `lv host rotate-audit-key`. Rows written
meanwhile are unsigned and are not evidence, because the retirement closed the
contract.

A retirement is itself **signed**, and stored append-only in
`audit_key_lifecycle`. That is not decoration. It began as two ordinary columns on
the certificate row, and as plain replicated data either could be set or cleared
by any peer: forging a retirement put every row a host had ever signed past a
boundary, on every node, with no key required — and clearing a genuine one was
just as cheap. The detector for "somebody else has this key" cannot itself be
something somebody else can write.

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
