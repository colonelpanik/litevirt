# Self-upgrade from a peer (auto-catch-up)

## Problem

`lv host upgrade` is operator-initiated and only touches **reachable** hosts. A
host that is **down during a cluster upgrade** comes back on its **old binary**
and stays there — nothing auto-corrects it. If the upgrade bumped the schema by
more than one version, that host's replication is then **refused** by the
skew handshake (`internal/grpcapi/sync.go`), isolating it until an operator
re-runs the upgrade. Even within tolerance, version drift is untidy and
surprising.

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
2. **Same-schema version drift (majority):** the highest-schema peers are at the
   **same** schema as us, but a **strict majority** of the reachable cluster
   (peers + self) runs a single binary `version` that differs from ours. → catch
   up to that version. The majority requirement stops a lone newer node from
   being dragged backwards by one stale peer.

**Hard guard:** never apply a binary whose advertised `schema_version` is **less
than** ours (no schema downgrade — the daemon already refuses to start against a
forward-migrated DB, but we refuse before swapping to avoid a crash-loop).

The peer to pull from is the one at the highest schema (then the majority
version), among **active** hosts. When several equally-good sources exist, an
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

- Cross-version *downgrade* is never automatic (guarded above).
- A binary change with **no** schema bump and **no** clear cluster majority is
  left to the operator (`lv host upgrade`) — we don't guess direction without a
  monotonic (schema) or majority signal.
