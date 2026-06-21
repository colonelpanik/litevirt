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

Each daemon, shortly after startup and then on a slow periodic tick, evaluates
its peers and decides whether it is behind. Two signals, both **monotonic and
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
version), among **active, reachable** hosts only.

## Mechanism

- **`FetchBinary` RPC** (server-streaming): a daemon streams its own
  `/usr/local/bin/litevirt` back to the caller in chunks; the first chunk
  carries the SHA-256 checksum, the binary `version`, and `schema_version`.
  RBAC: operator (the pulling daemon authenticates with its host cert over
  mTLS — same trust boundary as the existing push `UpgradeHost`).
- **`Ping` gains `schema_version`** so detection is a cheap round-trip without a
  new discovery RPC.
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
- Only pulls from **active** peers; verifies the **checksum**; refuses a binary
  whose `version` equals ours (no-op) or whose `schema_version` < ours.
- **Cooldown** after any attempt (success re-execs; failure backs off) so a
  broken peer or a transient mixed-version window can't cause a tight loop.
- Skips while the host is already `upgrading`, draining, or fencing-relevant
  (reuses the upgrade preflight in non-blocking/warn mode; a rejoining laggard
  has no in-flight work to protect, and KillMode=process keeps VMs alive across
  the re-exec).
- Witness hosts self-upgrade like any other (they vote in quorum).

## Out of scope (documented)

- Cross-version *downgrade* is never automatic (guarded above).
- A binary change with **no** schema bump and **no** clear cluster majority is
  left to the operator (`lv host upgrade`) — we don't guess direction without a
  monotonic (schema) or majority signal.
