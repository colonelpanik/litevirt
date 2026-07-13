# Self-upgrade from a peer (auto-catch-up)

## Problem

`lv host upgrade` is operator-initiated and only touches **reachable** hosts. A
host that is **down during a cluster upgrade** comes back on its **old binary**
and stays there — nothing auto-corrects it. If the upgrade bumped the schema at
all, that host is missing migrations, so its skew handshake
(`internal/grpcapi/sync.go`) then **refuses** inbound mutations from the newer
peers (a receiver rejects any sender strictly ahead of it — even by one),
isolating it until an operator re-runs the upgrade. Even a same-schema version
drift is untidy and surprising.

This feature lets a lagging daemon **pull the newer binary from a healthy peer
and self-upgrade**, with no operator action.

## Trigger / "am I behind?"

Each daemon, shortly after a (jittered) startup delay and then on a jittered
periodic tick, evaluates its peers and decides whether it is behind. Peer
`(version, schema_version)` is read from the **replicated `hosts` table** — one
local query — rather than dialing every peer each tick (that was an O(N²)
cluster-wide mTLS Ping fan-out). The chosen candidate is then **confirmed with a
single live `Ping`** right before pulling, because the table is eventually
consistent (a stale row must not drive a pull). Two signals, both **monotonic and
downgrade-safe**:

1. **Schema-behind (definitive):** a reachable, healthy peer reports a
   `schema_version` **strictly greater** than the local `CurrentSchemaVersion`.
   Schema only ever moves forward, so this is unambiguous and is exactly the
   case that would otherwise get replication-refused. → catch up.
2. **Same-schema, newer version (newest-wins):** the most-advanced reachable peer
   is at our schema but a **strictly-newer** `version` (semver compare on the
   `vX.Y.Z` tag). → catch up to it. **No majority is required** — seeding the new
   binary onto a *single* node lets it flow to the entire fleet, which is the only
   model that scales past a handful of nodes. Movement is forward-only (never to an
   older `version`), so a lone stale peer can't drag anyone backwards, and an
   unparseable `version` (a `dev` or git-describe ephemeral build) is never a
   target, so a local build can't pull the cluster onto an un-orderable version.

**Hard guard:** never apply a binary whose advertised `schema_version` is **less
than** ours (no schema downgrade — the daemon already refuses to start against a
forward-migrated DB, but we refuse before swapping to avoid a crash-loop).

The peer to pull from is the most-advanced **active** host (highest schema, then
the newest semver version). When several equally-good sources exist, an
elected **relay** (Crescent `ComputeRelays`) is preferred so a fleet-wide flip
spreads the binary pulls across the ~R relays instead of all hammering one node.

## Mechanism

- **`hosts.schema_version`** (schema v30): each daemon persists its running
  binary's supported schema (its `CurrentSchemaVersion`, the same value `Ping`
  advertises — **not** the DB-applied `EffectiveDBSchema`) into its `hosts` row
  at boot, folded into the single batched startup write. This is what makes the
  local-table read above possible and trustworthy.
- **`FetchBinary` RPC** (server-streaming): a daemon streams its own
  `/usr/local/bin/litevirt` back to the caller in chunks; the first chunk
  carries the SHA-256 checksum, the binary `version`, and `schema_version`.
  **Peer-only:** gated by a cluster **host certificate over mTLS**
  (`requirePeerCert`) — an operator's user/bearer credential cannot stream the
  binary. A serving-side **concurrency semaphore** bounds simultaneous streams
  (`ResourceExhausted` when full), so one source can't become a thundering-herd
  target during a fleet-wide flip; shedded pullers retry on their next tick.
- **`Ping` carries `version` + `schema_version`** and is used for the single
  pre-pull confirmation (and the legacy discovery path).
- **Pull verification:** the streamed binary's advertised `(version,
  schema_version)` must match what the confirm-`Ping` reported; mismatch aborts.
- **Apply** reuses the exact push-upgrade path, factored into
  `applyStagedBinary`: verify checksum → back up `.old` → atomic rename swap →
  mark host `upgrading` → refresh systemd unit → signal `ReExecCh`. The **new**
  binary forward-migrates its own schema on startup (as the daemon already
  does), so no separate migrate step is needed. `OnFailure=litevirt-rollback`
  restores `.old` if the pulled binary panic-loops — same safety net as a push
  upgrade.

## Safety / anti-thrash

- Config-gated: `auto_upgrade.from_peer` (default **on**); `auto_upgrade.interval`
  (default 5m). Set off to require manual `lv host upgrade`.
- **Jittered** startup delay and tick (±50%) so a synchronized fleet reboot
  doesn't herd on the first check or on each interval.
- Only pulls from **active** peers; verifies the **checksum** and the
  confirm-`Ping`/header `(version, schema)` match; refuses a binary whose
  `version` equals ours (no-op) or whose `schema_version` < ours.
- **Cooldown** after any attempt (success re-execs; failure backs off) so a
  broken peer or a transient mixed-version window can't cause a tight loop.
- Skips a tick while this host's state is already `upgrading`, so it never races
  a push upgrade (`lv host upgrade`) already in flight. (It does not currently run
  the full upgrade preflight — in-flight migration / pending fence / replication
  backlog — for self-upgrade; a rejoining laggard typically has no such work, and
  `KillMode=process` keeps VMs alive across the re-exec.)
- Witness hosts self-upgrade like any other (they vote in quorum).

## Out of scope (documented)

- Cross-version *downgrade* is never automatic (guarded above): schema is never
  rolled back, and a same-schema `version` only ever moves forward to a
  strictly-newer semver.
- A newer same-schema binary on **any single** reachable node propagates to the
  whole fleet (newest-wins, above) — putting a build on one node is enough to roll
  the cluster. This is deliberate (it's how a large fleet upgrades from one seed);
  the guardrails are that `FetchBinary` is **peer-mTLS-only** (an operator's
  user/bearer credential can't inject a binary), the streamed checksum +
  confirm-`Ping` `(version, schema)` must match, and a schema downgrade is never
  applied. Don't leave a newer build on a prod node you didn't intend to roll.
- To hold a test build on a subset **without** it propagating, set
  `auto_upgrade.from_peer: false` on those nodes (config + restart) before
  deploying, and re-enable after.
