# Upgrades

> Companion to [installation.md](installation.md) §Upgrading. This doc focuses
> on **what makes a litevirt self-upgrade safe** — pre-flight gates, the
> `upgrading` host state, the auto-rollback mechanism, and operator playbooks.
>
> Scope: upgrades of `litevirt` and `lv` only. Host-OS / kernel / Ceph /
> libvirt upgrades have separate considerations covered in
> [operating-model.md](operating-model.md).

---

## TL;DR

```sh
# Recommended path:
lv host preflight-upgrade host-b      # check first
lv host upgrade --binary ./litevirt  # upgrade all hosts (preflight runs again automatically)
```

If the new binary panics on startup, systemd's `OnFailure` hook restores
the previous binary automatically. If pre-flight blocks the upgrade, the
output tells you why; pass `--force` only after addressing the cause.

---

## Why upgrades are safe by default

Six guarantees the upgrade pipeline enforces:

1. **No VM dies on a steady-state upgrade.** QEMU is a child of `libvirtd`,
   not `litevirt`. The systemd unit ships `KillMode=process`, and the
   daemon self-checks this at startup — refusing to start under any unit
   that would cgroup-kill its children.

2. **No false-positive fence during the restart window.** The host marks
   itself `upgrading` in the cluster state before re-exec — and also on any
   graceful shutdown (SIGTERM from `systemctl restart/stop`), so a plain daemon
   restart isn't mistaken for a failure either. Failover coordinators on peer
   hosts skip fence candidacy for `upgrading` hosts, but only up to a timeout
   (2 min): a host that entered `upgrading` and never came back is still fenced,
   so its VMs aren't stranded. The new daemon transitions back to `active` on
   healthy startup, and a host left `offline` by a transient blip is
   auto-recovered to `active` once a fresh quorum sees it healthy.

3. **Auto-rollback on a panicking binary.** If the new daemon panics
   past systemd's `StartLimitBurst=3` within 10 minutes, the
   `litevirt-rollback.service` companion unit fires automatically:
   restores `/usr/local/bin/litevirt.old` over the bad binary, resets
   the failed state, restarts. Logged to journal with tag
   `litevirt-rollback`.

4. **Refuse to start downgrade-into-forward-DB.** `schema_state.version`
   in Corrosion tracks what version migrated this DB. A daemon that
   expects an older `CurrentSchemaVersion` than the DB has refuses to
   start, surfacing the operator error before it scribbles inconsistent
   rows.

5. **Schema-skew check in CRDT replication.** Every `PushMutations`
   request carries the sender's schema version. Receivers refuse if the
   sender is more than 1 minor version ahead — mid-upgrade drift cannot
   silently corrupt downstream replicas.

6. **Pre-flight gate.** `lv host upgrade` runs `PreflightUpgrade` and
   refuses on blocking conditions (in-flight migrations, leader-lease
   holdings with pending fences, large replication backlog, big clock
   skew, witness-host risk). Pass `--force` to override.

---

## The pre-flight gate

Before the binary swap, the daemon scans for conditions that would make
a restart unsafe. Findings are tagged `block` (refuses) or `warn`
(proceeds with logged warning).

### What it checks

| Code | Severity | Condition |
|---|---|---|
| `vm-transient` | block | Any VM on this host in `migrating | starting | creating | stopping | rebuilding` state. |
| `migrate-incoming` | block | Any VM migrating *into* this host (the destination side dies if the daemon restarts). |
| `leader-with-pending-fence` | block | This host holds the failover lease AND a non-success fence row was written in the last minute. |
| `replication-backlog` | warn | `mutation_log` has > 50,000 rows; restart will extend replication lag. |
| `clock-skew` | warn | This host has > 5 s skew with any peer; HLC reset on restart could land badly. |
| `witness-restart` | warn | This is a witness host for an even-N cluster; restart interrupts the tiebreak. |

### Manual pre-flight

```bash
lv host preflight-upgrade host-b
```

Reports findings without performing the upgrade. Use this before
scheduled maintenance to know what state the cluster needs to be in.

### Override

```bash
lv host upgrade --force
```

Skips `block`-level findings (warnings are still printed and logged).
Use this only when you understand the risk — for example, you've
*already* confirmed the in-flight migration is going to be aborted.

---

## How a normal upgrade flows

```
1. lv host upgrade --binary ./bin/litevirt
        │
        ▼
2. CLI lists cluster hosts; identifies which are outdated.
        │
        ▼
3. For each host (connected host last):
        a. Open SSH session to the host.
        b. Stream binary over gRPC ─→ daemon receives chunks, SHA-256.
        c. Daemon runs PreflightUpgrade (unless --force).
              ↳ blocks → operator addresses or --force.
        d. Backup current binary to /usr/local/bin/litevirt.old.
        e. Atomic rename: staging → /usr/local/bin/litevirt.
        f. Refresh systemd unit (KillMode=process + rollback OnFailure).
        g. Mark host state = "upgrading" (peers won't fence it).
        h. Send response, signal ReExecCh.
        i. Daemon main loop returns ErrReExec → cmd/litevirt
           calls syscall.Exec(binary) → PID is preserved for systemd.
        │
        ▼
4. New daemon startup:
        a. Pre-flight check: KillMode=process? Else refuse.
        b. InitSchema: applies any new migrations. Refuse if the local
           schema_state.version > binary's CurrentSchemaVersion.
        c. Mark host state = "active" (peers stop suppressing fence).
        d. Resume serving gRPC.
        │
        ▼
5. CLI verifies the new daemon is healthy via Ping; moves to next host.
```

The connected host (the one `LV_HOST` points at) is upgraded **last** so
the operator's gRPC connection stays alive throughout the rolling
upgrade. The self-upgrade still works because the SSH session and the
daemon process are independent.

---

## Auto-rollback

### How it triggers

The systemd unit has:

```
[Unit]
StartLimitBurst=3
StartLimitIntervalSec=600
OnFailure=litevirt-rollback.service
```

If the new binary panics on startup, systemd restarts it (`Restart=on-failure,
RestartSec=5`). Three failures within 10 minutes trip `StartLimitBurst`,
the unit enters `failed` state, and `OnFailure=` fires the rollback
service.

### What the rollback service does

```
[Service]
ExecStart=/bin/sh -c '\
  if [ -f /usr/local/bin/litevirt.old ]; then \
    logger -t litevirt-rollback "RESTORING previous litevirt binary after failed upgrade"; \
    mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt; \
    systemctl reset-failed litevirt.service; \
    systemctl start litevirt.service; \
  else \
    logger -t litevirt-rollback "no .old binary to roll back to; leaving litevirt in failed state"; \
    exit 1; \
  fi'
```

### Verifying a rollback fired

```bash
journalctl -t litevirt-rollback         # rollback log entries
systemctl status litevirt                # should be active again, on the .old binary
litevirt --version                       # confirms the rolled-back version
```

### Limitations

The rollback handles the **panic-loop** case: a binary that crashes on
startup. It does NOT cover:

- A new binary that *starts* but doesn't *function* (e.g., hangs in
  `InitSchema`). systemd's `Restart=on-failure` doesn't fire because the
  process never exited. Operator must intervene.
- Subtle regressions that don't trip systemd's failure detection
  (e.g., wrong placement decisions). Catch these with metrics + alerts,
  not the rollback unit.

A health-check-after-restart watchdog is a planned follow-up for the
"starts but doesn't function" gap.

---

## What can go wrong (and how to recover)

### Pre-flight blocks the upgrade

```
$ lv host upgrade
Error: upgrade pre-flight blocked 1 condition(s); pass --force to override or address them first
```

Run `lv host preflight-upgrade <host>` to see the specific finding.
Common causes:

| Finding | Fix |
|---|---|
| `vm-transient` | Wait for the in-flight VM operation to complete |
| `migrate-incoming` | Wait for the migration; abort if stuck |
| `leader-with-pending-fence` | Resolve the fence (or wait for it to time out) |

### `KillMode` self-check refuses startup

```
preflight: unsafe systemd unit: KillMode="control-group" (want "process"); ...
```

The systemd unit was edited and `KillMode` is wrong. Fix:

```bash
sudo cp /etc/systemd/system/litevirt.service /tmp/litevirt.service.bak
# Edit /etc/systemd/system/litevirt.service so KillMode=process
sudo systemctl daemon-reload
sudo systemctl restart litevirt
```

Or override (development / non-systemd hosts only — VMs are at risk!):

```bash
LITEVIRT_UNSAFE_NO_KILLMODE_CHECK=1 systemctl restart litevirt
```

### Schema-version refusal

```
schema downgrade refused: DB schema version is 5, binary expects 1
```

Someone is starting an older binary against a DB that a newer binary
already migrated. Either run the matching binary version, or restore the
DB from a snapshot taken before the forward migration.

### Schema-skew refusal in replication

Peer logs:

```
pushMutations: schema skew too large; refusing
sender_schema=5 local_schema=1
```

This host is too far behind. Upgrade it, or temporarily isolate it
from CRDT replication while the gap is closed.

### Rollback didn't fire automatically

If 3 panics in 10 min didn't trigger `OnFailure`, check:

```bash
systemctl show litevirt -p StartLimitBurst -p OnFailure
```

If the values are wrong, the unit on disk has drifted from the canonical
template. Run a clean upgrade — `updateSystemdUnit` (in
`internal/grpcapi/upgrade.go`) writes the canonical unit file.

### Manual rollback (anytime)

```bash
ssh root@<host>
mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt
systemctl reset-failed litevirt
systemctl restart litevirt
```

---

## Operator playbook for cluster-wide upgrades

A typical rolling upgrade across, say, 5 hosts:

1. **Pre-check.** On a workstation:
   ```bash
   make build                            # produce the new binary
   for h in $(lv host ls --names); do
     lv host preflight-upgrade $h
   done
   ```
   Resolve any `block` findings before proceeding.

2. **Upgrade.**
   ```bash
   lv host upgrade --binary ./bin/litevirt
   # CLI sequences hosts; connected host last.
   # Each takes ~10 s + the time PreflightUpgrade waits.
   ```

3. **Verify.**
   ```bash
   lv host ls                  # all VERSION columns match
   journalctl -t litevirt-rollback   # should be empty
   ```

4. **Post-check.** Spot-check a VM lifecycle:
   ```bash
   lv restart <one-vm>
   ```

For larger fleets (50+ hosts), upgrade in waves of 10 with a verification
pass between waves. A daemon-side rolling-upgrade orchestrator is on
the roadmap; today the CLI does it serially.

### Seeding a rolling upgrade, and the bare-restart hazard

Two operational gotchas, both learned the hard way:

**1. `lv host upgrade` with no host args rolls the `--binary` to every host not
already on its version.** The "target version" is read from the binary itself
(it's probed with `litevirt --version`), so the common case — build a new
binary and roll it to a cluster that's currently uniform on the old version —
just works:

```bash
lv host upgrade --binary ./bin/litevirt --yes   # rolls to every outdated host
```

Naming hosts is still supported and **always (re)deploys** them regardless of
version — useful to re-seed the same version after a manual change, or to
control order:

```bash
lv host upgrade host-01 --binary ./bin/litevirt --yes
```

> Older builds compared each host to the *connected daemon's* version instead
> of the binary's, so the no-arg form no-op'd (`All hosts are up-to-date.`) on a
> version-uniform cluster and you had to seed a node by name first. That's
> fixed — it now probes the binary.

**2. NEVER seed by hand-restarting the daemon on a healthy host:**

```bash
# ☠️  DO NOT DO THIS on a live cluster:
cp litevirt.new /usr/local/bin/litevirt && systemctl restart litevirt
```

A bare `systemctl restart` bypasses the `upgrading` state that
`lv host upgrade` sets. The failover **leader** sees the host vanish for a
few seconds and opens a fence against it. The fence usually can't complete
(SSH-poweroff fails), so it lingers as a stale `partial` record — and a
stale fence record on the leader then *blocks the leader's own upgrade*
(`leader-with-pending-fence`). Always upgrade through `lv host upgrade`,
which marks the host `upgrading` (the coordinator skips `offline`,
`maintenance`, `fenced`, and `upgrading` hosts). If you must hand-restart a
host, put it in maintenance first (`lv host drain <host>`), restart, then
return it.

**Overriding a stale block.** `--force` is now sent to the daemon, so a
genuinely-stale server-side block can be overridden:

```bash
lv host preflight-upgrade <host>             # confirm the block is stale first
lv host upgrade <host> --binary <new> --force --yes
```

Only force after confirming the finding is a false positive (e.g. a fence
record from minutes ago for a host that's actually healthy).

## Schema upgrades: `litevirt schema-migrate`

The daemon refuses to start when its `CurrentSchemaVersion` is OLDER
than the cluster DB's version (downgrade guard), and aborts replication
batches that reference missing tables / columns (forward-skew guard).

**Schema changes are additive-only.** CRDT-replicated tables (everything in
`internal/corrosion/schema.go`) may only **grow**: a new `CREATE TABLE`, or an
`ALTER TABLE … ADD COLUMN` that is **nullable (implicit `NULL`) or has an
explicit `DEFAULT`**, so a row written by an older peer stays valid. **Never rename a column, drop a column, change a column's
type, or change a primary key** on a replicated table. Crescent's
last-writer-wins apply path addresses columns *by name*, so in a mixed-version
cluster a renamed or dropped column is simply *missing* on the not-yet-upgraded
peers, and mutations that reference it are silently dropped or mis-applied
there. A rename is also invisible to the safety nets — it can leave the column
*count* unchanged, so it slips past both the forward-skew check and the
version-bump guard, which catch *growth* without a `CurrentSchemaVersion` bump,
not in-place edits.

To rename or retype a replicated column, do it as a multi-release dual-write
migration — never a single change:

1. `ADD COLUMN` the new column (with a default); bump `CurrentSchemaVersion` and
   add a `History:` line.
2. Dual-write old + new, and read new-with-fallback-to-old. Roll that out to
   **every** node.
3. In a *later* release — after every supported version is past step 2 —
   backfill and stop writing the old column. Leave the dead column in place;
   dropping it is itself a non-additive change and rarely worth the risk.

**`lv host upgrade` handles this for you.** Before swapping any binary it
runs a **pre-stage pass**: it streams the new binary to every target and
runs that binary's `schema-migrate` against the live `state.db` (idempotent,
WAL + busy-timeout — safe while the old daemon is up). Only after every node's
schema is forward-staged does it begin the rolling restart, so a freshly-
upgraded node can never write a column a not-yet-upgraded peer is missing.
If pre-staging fails on any host the upgrade aborts **before** any binary is
swapped, so you can fix it and re-run. Daemons too old to support the
pre-stage RPC report `Unimplemented` and are skipped (they migrate themselves
on restart; a single-version skew self-heals) — so the very upgrade that
introduces this feature still works as a plain rolling restart. Pass
`--no-prestage` to skip the pass (not recommended for multi-version jumps).

You generally do **not** need to run `schema-migrate` by hand anymore. It
remains available for manual control or recovery — e.g. forward-staging a
long-offline node that's ≥2 versions behind before it rejoins:

```bash
make build                                   # produces bin/litevirt

# On a host, pointed at the cluster DB (safe to run while the daemon is up):
sudo litevirt schema-migrate /var/lib/litevirt/state.db
sudo litevirt schema-migrate --dry-run /var/lib/litevirt/state.db   # preview only

# Read-only validator that reports what's missing on the cluster:
scripts/upgrade-validate.sh
```

If you skip pre-staging entirely (`--no-prestage`, or a manual binary swap),
a node running the OLD binary silently drops cross-node mutations referencing
schema the NEW binary added until it's restarted. The drop shows up in
metrics — a growing `litevirt_mutation_log_rows` on the sender and a stalled
`litevirt_replication_min_watermark_seq`.

The migrate tool's safety net is a CI guardrail (`internal/corrosion/
migrate_tool_test.go`) that every entry in `schemaDDL` / `schemaMigrations`
must be parseable by the same DDL parser the tool uses — so a future
schema change can't silently make the migration tool lie.

### CI guardrails

Three checks run on every push and pull request (`.github/workflows/ci.yml`)
to keep the invariants above from rotting. Run them locally with
`make ci-guards`.

1. **Schema growth requires a version bump.** If a CREATE TABLE / ALTER /
   index is added to `internal/corrosion/schema.go` without bumping
   `CurrentSchemaVersion`, the forward-skew guard above goes blind to it and
   peers silently drop the new rows. The `schema-guard` job diffs the schema
   arrays between the base and head revisions with an AST-based tool
   (`scripts/ci/schemacheck`, driven by `scripts/ci/check-schema-bump.sh`) and
   fails on growth-without-bump. Counting is by AST element, so reformatting or
   reordering an array never trips it.

2. **History stays in lockstep with the version.** A unit test
   (`TestSchemaHistoryDocumentsCurrentVersion`) asserts the `History:` comment
   block documents every version `v1..CurrentSchemaVersion` — the audit trail
   operators read before a staged rollout.

3. **Docs don't reference commands or metrics that don't exist.** A
   claim-vs-code triangulation test (`cmd/litevirt/docs_triangulation_test.go`)
   walks every `lv`/`litevirt` invocation and every `` `litevirt_*` `` metric
   in `README.md` + `docs/*.md` and fails if one doesn't resolve in the cobra
   tree or appear as a string literal in the code. Intentional exceptions use
   a `ci:skip-cmd` / `ci:skip-metric` line marker or the `knownAbsentIdentifiers`
   allowlist (for documented-but-roadmap metrics).

## See also

- [installation.md](installation.md) — base upgrade scenarios + apt
  packaging
- [operating-model.md](operating-model.md) — what the cluster guarantees;
  recovery playbook
