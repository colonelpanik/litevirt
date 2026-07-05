package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// CurrentSchemaVersion is the schema version this binary expects. Bump this
// every time `schemaMigrations` grows. The daemon refuses to start if the
// local DB's persisted schema_version is HIGHER than this — that means
// someone is trying to downgrade onto a forward-migrated DB, which produces
// silent corruption (new columns the old binary doesn't know about, indexes
// it doesn't maintain, etc.).
//
// Schema versions are NOT replicated via CRDT — each host's local
// schema_state.version reflects its own binary's view.
//
// History:
//
//	v1: initial baseline
//	v2: auth — roles, role_bindings, sessions, user_2fa,
//	    recovery_codes; tokens scope columns; users.realm column
//	v3: distributed firewall — security_groups, sg_rules tables.
//	v4: per-NIC SG binding — vm_interfaces.security_groups
//	    column.
//	v5: containers — containers cluster-state table.
//	v6: federation — hosts.region column, service_endpoints
//	    table.
//	v7: snapshot scheduler — backup_schedules table.
//	v8: tamper-evident audit log — audit_log.prev_hash +
//	    audit_log.content_hash columns.
//	v9:  tenancy core — projects + project_quotas tables;
//	     vms.project column.
//	v10: pool-level schedules — backup_schedules.pool_name
//	     column.
//	v11: pool CRUD — storage_pools.options column (JSON
//	     blob of driver-specific key/value flags so operators can
//	     register a pool at runtime without editing config.yaml).
//	v12: backup-schedule scopes — backup_schedules.scope +
//	     project_name columns. A schedule now targets a VM, a storage
//	     pool, all VMs (cluster), or a tenancy project; the scheduler
//	     fans the non-vm scopes out per host at tick time. vm_name
//	     holds a sentinel key for non-vm scopes (@pool:X / @project:Y /
//	     @cluster) so multiple scopes can share a repo under the
//	     (vm_name, repo) primary key.
//	v13: per-VM event store — vm_events table (durable, CRDT-replicated,
//	     append-only, prunable operational activity history; distinct
//	     from the tamper-evident audit_log hash chain). New CREATE TABLE
//	     only — schemaMigrations does not grow.
//	v14: tenancy backup_gib aggregation — vm_backups table indexing the
//	     latest backup size per (vm, disk, repo), upserted on each backup
//	     push so SumProjectUsage can gate the backup_gib quota on live usage.
//	     New CREATE TABLE only — schemaMigrations does not grow.
//	v16: VM templates + clones — vms.is_template (a VM that can't start;
//	     its disks are immutable clone sources) + vm_disks.backing_disk
//	     (linked-clone lineage, for the refcount + host-pin guards). Additive.
//	v15: TOTP replay protection — user_2fa.last_step column (highest
//	     consumed TOTP time-step). VerifyTOTP ratchets this forward and
//	     rejects any code at or below it, so a captured code can't be
//	     replayed inside its ±30s validity window. Additive; old rows
//	     default to 0 and accept their first code.
//
// IMPORTANT: bump this in lockstep with any addition to schemaDDL or
// schemaMigrations. Without the bump the cross-version replication
// skew check in internal/grpcapi/sync.go can't tell that a peer is
// missing newly-added tables/columns, and ApplyRemoteMutations will
// silently drop rows that reference them (see replicator.go ~L608).
//
//	v17: scheduled replication — backup_schedules gains type ('backup' |
//	     'replication'), target_pool, target_host, keep_replicas, so the
//	     existing scheduler can drive volume replication alongside backups.
//	     Additive; old rows default type='backup'. gap-1 from v16, auto-prestaged.
//	v18: replication follow-ups B + C — backup_schedules gains incremental
//	     (transfer only dirty extents into raw replicas; full-copy fallback),
//	     auto_promote (failover may promote the freshest replica on host loss),
//	     and last_checkpoint (the per-schedule dirty-bitmap chain anchor for the
//	     incremental path). Additive; old rows default incremental=0,
//	     auto_promote=0, last_checkpoint=''.
//	v19: VM features & data safety (Proxmox-gap MR1) — snapshots gains type
//	     ('disk'|'memory'), vmstate_path, vmstate_size_bytes for live/RAM
//	     snapshots (#3); new resource_mappings table for cluster-wide passthrough
//	     device aliases (#14). Memory ballooning (#4) and boot ordering (#10) live
//	     in the VMSpec JSON, so they need no columns. Additive throughout.
//	v20: notifications (Proxmox-gap MR2 #5) — new notification_targets +
//	     notification_routes tables (webhook/slack targets + event-pattern routes).
//	     New CREATE TABLE only — schemaMigrations does not grow. ACME (#13) is
//	     config-only, no schema.
//	v21: distributed-firewall wire-up — the renderer already supported cluster/host
//	     tiers, default-deny, and ipsets, but nothing persisted them. New tables:
//	     ip_sets (named CIDR lists), cluster_firewall_rules + host_firewall_rules
//	     (the two non-NIC tiers), firewall_defaults (per-scope default-deny policy,
//	     scope = 'cluster' or a host name). Compose security-groups/ipsets/firewall
//	     blocks and per-NIC bindings now feed these. Also adds backup_repos
//	     (logical name → path) so a compose `backup-repos:` block can register a
//	     repo cluster-wide (previously repos came only from daemon config). New
//	     CREATE TABLE only — schemaMigrations does not grow.
//	v22: per-VM replication checkpoints — new replication_checkpoints table keyed
//	     by (vm_name, repo). Incremental replication's dirty-bitmap anchor used to
//	     live in backup_schedules.last_checkpoint, but for fan-out (pool/cluster/
//	     project) schedules that row's vm_name is a sentinel, so per-VM checkpoint
//	     writes matched zero rows and incremental silently degraded to full copies.
//	     Keying by the real VM fixes both per-VM and fan-out scopes. New CREATE
//	     TABLE only — schemaMigrations does not grow.
//	v23: registry credentials — new registry_credentials table holding per-user
//	     (scope='user', owner=<username>) and global (scope='global') OCI/Docker
//	     registry logins, used to authenticate `lv ct pull` / PullOCIImage against
//	     private registries. New CREATE TABLE (+ one partial unique index) only —
//	     schemaMigrations does not grow. SECURITY: the `secret` column is stored
//	     PLAINTEXT (matching the current user_2fa TOTP convention) and replicates
//	     cluster-wide via Corrosion; AES-GCM sealing is future work, gated on
//	     cluster-master-key infrastructure that does not yet exist.
//	v24: container restart policy — containers gains restart_policy (JSON:
//	     condition/delay/max_attempts/window) + state_detail (the stop-cause /
//	     intent channel, mirroring vms.state_detail: 'operator-stop' etc.) so the
//	     new container reconciler can auto-restart a container that stopped
//	     unexpectedly while leaving an operator-stopped one alone. New
//	     container_restarts table (mirrors vm_restarts) tracks attempts within a
//	     sliding window. Additive: the two columns get ALTERs in schemaMigrations
//	     and CREATE-TABLE columns; old rows default restart_policy='' (treated as
//	     'none') and state_detail=''. gap-1 from v23, auto-prestaged.
//	v25: containers.project — a tenancy project bucket on the containers table,
//	     mirroring vms.project. ADD COLUMN in schemaMigrations + CREATE-TABLE
//	     column; old rows default project='_default'. Unblocks container quota
//	     admission, audit-actor, and per-project RBAC (paths were hardcoded to
//	     /projects/_default/containers/). gap-1 from v24, auto-prestaged.
//	v26: container_backups — indexes the latest full-backup size per (container,
//	     repo), mirroring vm_backups, so the tenancy backup_gib quota sums
//	     container footprints alongside VMs. New table in schemaDDL only (no
//	     ALTER — CREATE TABLE IF NOT EXISTS covers fresh + existing DBs). Unblocks
//	     container backup/restore (full tar → pbsstore). gap-1 from v25.
//	v27: container_snapshots — per-container point-in-time snapshots (freeze+tar
//	     of the container dir under {dataDir}/ct-snapshots), the container analogue
//	     of the snapshots table. New table in schemaDDL only (no ALTER). Unblocks
//	     `lv ct snapshot create|ls|revert|rm`. gap-1 from v26.
//	v28: containers.is_template + containers.on_host_failure — clone-source
//	     template flag (mirrors vms.is_template) and host-loss relocation policy.
//	     Two ADD COLUMNs in schemaMigrations + CREATE-TABLE columns; old rows
//	     default is_template=0, on_host_failure=NULL (treated as 'none'). Unblocks
//	     container templates/clones (B4) + failover relocation (B5). gap-1 from v27.
//	v29: delete-safety — tokens.updated_at + lb_backends.deleted_at. Anti-entropy is
//	     a union merge that can't propagate hard deletes, so full-state tables must
//	     soft-delete (deleted_at) and arbitrate by updated_at. tokens had deleted_at
//	     but no updated_at, so a stale peer's live row blind-replaced a revocation;
//	     lb_backends had neither and was hard-deleted. Two ADD COLUMNs; old tokens
//	     rows default updated_at='' (a revoke's timestamp then wins LWW). gap-1 from v28.
//	v30: hosts.schema_version — each host's running-binary supported schema (the
//	     value Ping returns, i.e. that binary's CurrentSchemaVersion; NOT the
//	     DB-applied EffectiveDBSchema). Persisted so the self-upgrade watcher reads
//	     peer (version, schema) from the replicated hosts table instead of an
//	     O(N^2) live-Ping fan-out. Additive INTEGER DEFAULT 0; old rows read 0
//	     (unknown → never an upgrade source) until the peer writes its own at boot.
//	     gap-1 from v29.
//	v31: lb_configs.generation + lb_backends.generation — a per-incarnation token
//	     (minted on create/recreate, preserved on edit). Readers render only the
//	     backends whose generation matches their lb_config's, so a stale backend a
//	     partitioned peer held (and this node never saw) can merge under anti-entropy
//	     but never renders — closing the LB OR-set edge. Additive TEXT DEFAULT '';
//	     pre-migration rows match '' = '' and keep rendering. gap-1 from v30.
//	v32: make 2FA/recovery peer-repairable so they can join the sensitive
//	     anti-entropy lane, each gated by a per-user active-set pointer so a stale
//	     row a partitioned peer resurrects can never validate (the soft-delete
//	     tombstone alone can't cover a factor/code this node never saw):
//	       - user_2fa.deleted_at + user_2fa.epoch, with a new
//	         user_2fa_sets(username PK, active_epoch, updated_at, deleted_at). A
//	         factor renders only when its epoch == the pointer's active_epoch;
//	         DeleteUser tombstones the pointer, so delete→recreate can't resurrect.
//	       - recovery_codes.set_id + updated_at + deleted_at, with a new
//	         recovery_code_sets(username PK, active_set_id, updated_at, deleted_at).
//	         A code is valid only when its set_id == active_set_id.
//	     Both pointers converge by ordinary updated_at LWW (no numeric/MAX
//	     generation ordering, which per-node-monotonic NowTS would make unsafe).
//	     Five ADD COLUMNs + two CREATE TABLEs; gap-1 from v31. InitSchema runs
//	     idempotent post-migration data fixes (user_2fa NULL→'' label; legacy
//	     2FA/recovery pointer backfill) via raw SQL, not replicated mutations.
//	v33: host_runtime_usage(host_name PK, disk_iops, net_mbps, updated_at,
//	     deleted_at) — a per-host runtime-telemetry row the placement engine reads
//	     to score the DiskIOPS/NetBW dimensions. Kept OUT of the full-state
//	     anti-entropy set (antiEntropyExcluded): it replicates via mutation_log but
//	     stale telemetry self-corrects on the next sample (cf. vm_events), so it
//	     needn't be full-state-repaired and must not bloat the digest/dump or churn
//	     durable host metadata. One CREATE TABLE; gap-1 from v32.
//	v34: containers.create_spec — JSON of a container's create-time intent
//	     (template/distro/release/arch + litevirt-managed networks) that the other
//	     columns don't capture. Lets host-loss relocation and restore rebuild a
//	     container faithfully (networking included) instead of a bare image
//	     recreate. Forward-only: rows/manifests from before v34 have an empty spec;
//	     readers tolerate that and fall back to image-recreate. Plus
//	     containers.relocate_token: an attempt token a restore-relocation stamps on
//	     the target row so the coordinator can PROVE a (target,name) row is its own
//	     restore (names aren't cluster-unique) before tombstoning the source. Two
//	     ADD COLUMNs; gap-1 from v33.
//	v35: container_interfaces(host_name, ct_name, network_name, ordinal, mac, ip,
//	     veth_device, security_groups, updated_at, deleted_at; PK
//	     (host_name,ct_name,ordinal)) — the container analogue of vm_interfaces,
//	     giving every litevirt-managed container NIC a cluster row + a stable,
//	     deterministic host veth device so IPAM/DNS/security-groups can apply to
//	     containers like VMs. PK keyed by ordinal (not network) to allow multiple
//	     NICs on one network. One CREATE TABLE; gap-1 from v34.
//	v36: ip_allocations.owner_kind ('vm'|'ct', DEFAULT 'vm') + owner_host
//	     (DEFAULT '') — generalize IPAM ownership beyond VMs. Leases now key on
//	     (network, owner_kind, owner_host, vm_name): VMs keep an empty owner_host
//	     (names are cluster-global), containers use their host (CT names are
//	     per-host), so a VM and a CT — or two same-named CTs on different hosts —
//	     can't alias to one lease. Old rows default to owner_kind='vm'/owner_host=''
//	     preserving VM behavior. Two ADD COLUMNs; gap-1 from v35.
//	v37: project-scoped isolation — networks.project, storage_pools.project,
//	     volumes.project (all TEXT NOT NULL DEFAULT ''). EMPTY = global/shared
//	     (usable by every project — the deliberate admin escape hatch); a non-empty
//	     value means owned + isolated, so a workload may only attach to a network/
//	     pool that is global OR owned by its own project. DEFAULT '' makes every
//	     pre-v37 network/pool/volume global, so no existing workload is suddenly
//	     denied (a '_default' default would have done exactly that). Three ADD
//	     COLUMNs; gap-1 from v36.
//	v38: split-brain hardening (Phase 1) — new table runtime_action_proofs (durable
//	     single-use runtime-ownership authorization with a monotone action lifecycle;
//	     NON-LWW merge, kept off replication until split_brain_gate_v1 is cluster-wide)
//	     + vms.pending_action_id (TEXT NOT NULL DEFAULT '') linking a pending start to
//	     its proof. One CREATE TABLE + one ADD COLUMN; gap-1 from v37.
//	v39: request idempotency — new table idempotency_keys(key PK, claim_id, method,
//	     request_hash, response, status, expires_at, …) recording a mutating RPC so a
//	     lost-response retry to the SAME entry node replays the original result
//	     instead of executing twice. LOCAL-only (execLocal, never replicated) and
//	     TTL-reaped (ephemeral); cross-node retries fall back to resource-name
//	     uniqueness. One CREATE TABLE; gap-1 from v38.
const CurrentSchemaVersion = 39

// appliedMigrationsDDL is the per-migration ledger. It is created by the
// framework itself (not part of schemaDDL) so it doesn't trip the CI growth
// guard and there's no chicken-and-egg (we read it right after creating it).
// It is LOCAL-ONLY: every write goes through execLocal/execBatchLocal (no
// mutation_log row) and the table is deliberately absent from the full-state
// sync list (sync.go tableNames), so peers never replicate it.
const appliedMigrationsDDL = `CREATE TABLE IF NOT EXISTS applied_migrations (
	id         TEXT PRIMARY KEY,
	applied_at TEXT NOT NULL,
	checksum   TEXT NOT NULL
)`

// InitSchema brings the local SQLite DB up to this binary's schema. DDL is not
// broadcast — each node migrates its own DB on startup.
//
// Authoritative per-migration ledger: instead of replaying every ALTER and
// swallowing "already exists" errors (which hid real corruption and made
// "DB is at vN" an assertion, not a fact), we track each migration UNIT by a
// stable ID in applied_migrations. For each unit not yet recorded we run its
// PRESENCE PREDICATE against the live DB (PRAGMA table_info / sqlite_master):
//   - present  → record it (mark-only; the ALTER/CREATE already happened)
//   - missing  → apply its SQL + record it in ONE local transaction (heal)
//
// A real apply error aborts LOUDLY (no benign swallowing). Mark-applied is
// gated on the presence predicate, NEVER on the version number, so a silent
// gap from the old swallow-benign loop is healed rather than falsely claimed.
func InitSchema(ctx context.Context, c *Client) error {
	slog.Info("initializing schema")

	// Tables first (CREATE TABLE IF NOT EXISTS — genuinely idempotent, and it
	// guarantees every table exists before the ledger's presence checks run).
	for _, ddl := range schemaDDL {
		if err := c.execLocal(ctx, ddl); err != nil {
			return fmt.Errorf("schema init: %w", err)
		}
	}

	// The ledger meta-table itself.
	if err := c.execLocal(ctx, appliedMigrationsDDL); err != nil {
		return fmt.Errorf("create applied_migrations: %w", err)
	}
	applied, err := loadAppliedMigrations(ctx, c)
	if err != nil {
		return fmt.Errorf("load applied_migrations: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	healed := 0
	for _, m := range schemaMigrationLedger {
		sum := sha256hex(m.SQL)
		if stored, ok := applied[m.ID]; ok {
			// Already applied — a changed checksum means the migration's SQL was
			// edited after it shipped, which would silently diverge DBs across the
			// fleet. Refuse loudly.
			if stored != sum {
				return fmt.Errorf("schema ledger: migration %q checksum drift "+
					"(stored %s, code %s) — never edit an applied migration's SQL; add a new one",
					m.ID, stored, sum)
			}
			continue
		}
		present, err := m.present(ctx, c)
		if err != nil {
			return fmt.Errorf("schema ledger: presence check for %q: %w", m.ID, err)
		}
		if present {
			if err := c.execLocal(ctx,
				`INSERT OR IGNORE INTO applied_migrations (id, applied_at, checksum) VALUES (?, ?, ?)`,
				m.ID, now, sum); err != nil {
				return fmt.Errorf("schema ledger: record %q: %w", m.ID, err)
			}
			continue
		}
		// Missing: heal. Only addColumn units carry heal SQL — createTable units
		// are always present here (schemaDDL ran above), so this is unreachable
		// for them; guard anyway.
		if m.SQL == "" {
			return fmt.Errorf("schema ledger: %q (%s) reported missing but has no heal SQL", m.ID, m.Target)
		}
		if err := c.execBatchLocal(ctx, []Statement{
			{SQL: m.SQL},
			{SQL: `INSERT INTO applied_migrations (id, applied_at, checksum) VALUES (?, ?, ?)`,
				Params: []interface{}{m.ID, now, sum}},
		}); err != nil {
			return fmt.Errorf("schema migration %q: %w", m.ID, err)
		}
		slog.Warn("schema ledger: healed a missing migration (silent gap from a prior daemon)",
			"id", m.ID, "target", m.Target)
		healed++
	}

	// v32 post-migration data fixes (idempotent, LOCAL-only — schema-init data
	// repair must not emit replication mutations). Runs after the ledger loop so
	// the v32 columns + recovery_code_sets are guaranteed present.
	if err := applyV32DataFixes(ctx, c, now); err != nil {
		return fmt.Errorf("schema init: v32 data fixes: %w", err)
	}

	for _, idx := range schemaIndexes {
		if err := c.execLocal(ctx, idx); err != nil {
			slog.Warn("index creation failed (non-fatal)", "error", err)
		}
	}

	if err := reconcileSchemaVersion(ctx, c); err != nil {
		return err
	}

	// Seed the effective DB-applied schema cache (handshake source of truth).
	eff := c.RefreshDBSchemaVersion(ctx)
	slog.Info("schema initialized",
		"version", eff, "ledger", len(schemaMigrationLedger), "healed", healed)
	return nil
}

// applyV32DataFixes runs the idempotent, LOCAL-only data repairs the v32
// migration needs but that schemaMigrations (ADD COLUMN only) can't express:
//
//   - Normalize user_2fa.label NULL → ” so the composite PK never carries a NULL
//     component — a NULL-label row and an ”-label row are distinct, which would
//     let the sensitive merge duplicate a factor or skip a tombstone.
//   - Backfill recovery-code sets: give every pre-v32 user an active-set pointer
//     (active_set_id=”) and stamp legacy codes' LWW key (updated_at=created_at),
//     so existing unused codes (set_id=”) keep validating until the next
//     re-enroll mints a real set and supersedes them.
//
// Every statement is a no-op on a fresh or already-fixed DB, and the pointer
// insert is INSERT-ONLY so a re-run never resets a user who has since re-enrolled
// (their pointer already holds a real active_set_id). The column stays physically
// nullable (additive-only — no ALTER COLUMN); normalized write paths keep it ”
// going forward.
func applyV32DataFixes(ctx context.Context, c *Client, now string) error {
	type stmt struct {
		sql    string
		params []interface{}
	}
	for _, s := range []stmt{
		{`UPDATE user_2fa SET label = '' WHERE label IS NULL`, nil},
		// Pointer backfill. The pointer is born TOMBSTONED for a user whose account
		// is already deleted (deleted_at inherited from the users row): a pre-v32
		// DeleteUser did NOT cascade auth rows, so a deleted user can still hold
		// live orphan factors/codes that a LIVE pointer would revive on reactivation.
		// A user with no users row (external realm) inherits NULL -> a live pointer.
		{`INSERT INTO user_2fa_sets (username, active_epoch, updated_at, deleted_at)
		  SELECT f.username, '', COALESCE(MAX(f.updated_at), ?),
		         (SELECT u.deleted_at FROM users u WHERE u.username = f.username)
		  FROM user_2fa f GROUP BY f.username
		  ON CONFLICT(username) DO NOTHING`, []interface{}{now}},
		{`INSERT INTO recovery_code_sets (username, active_set_id, updated_at, deleted_at)
		  SELECT r.username, '', COALESCE(MAX(r.created_at), ?),
		         (SELECT u.deleted_at FROM users u WHERE u.username = r.username)
		  FROM recovery_codes r GROUP BY r.username
		  ON CONFLICT(username) DO NOTHING`, []interface{}{now}},
		{`UPDATE recovery_codes SET updated_at = created_at WHERE updated_at = ''`, nil},
		// Tombstone the orphan factor/code rows of already-deleted users (pre-v32
		// delete left them live) so no live secret rows linger behind the tombstoned
		// pointer. Idempotent: only touches still-live rows.
		{`UPDATE user_2fa SET deleted_at = ?, updated_at = ?
		  WHERE deleted_at IS NULL AND username IN (SELECT username FROM users WHERE deleted_at IS NOT NULL)`, []interface{}{now, now}},
		{`UPDATE recovery_codes SET deleted_at = ?, updated_at = ?
		  WHERE deleted_at IS NULL AND username IN (SELECT username FROM users WHERE deleted_at IS NOT NULL)`, []interface{}{now, now}},
	} {
		if err := c.execLocal(ctx, s.sql, s.params...); err != nil {
			return err
		}
	}
	return nil
}

// reconcileSchemaVersion keeps the legacy schema_state.version row in sync with
// the ledger-DERIVED version (max Version over applied migration IDs) — produced
// from verified reality, not asserted.
//
// A DB forward-migrated past this binary (stored > CurrentSchemaVersion) is now
// ALLOWED (it used to refuse): the schema is additive-only (CI-enforced), so an
// old binary tolerates a newer DB's extra columns. This is the steady mid-
// rolling-upgrade state and makes a bump reversible. See EffectiveDBSchema.
func reconcileSchemaVersion(ctx context.Context, c *Client) error {
	derived := derivedSchemaVersion(ctx, c)

	rows, err := c.Query(ctx, `SELECT version FROM schema_state WHERE id = 1`)
	if err != nil || len(rows) == 0 {
		return c.execLocal(ctx,
			`INSERT OR IGNORE INTO schema_state (id, version, updated_at) VALUES (1, ?, ?)`,
			derived, time.Now().UTC().Format(time.RFC3339))
	}
	stored := rows[0].Int("version")
	if stored > CurrentSchemaVersion {
		// Forward-migrated DB + older binary: warn, do NOT regress the stored
		// version (the newer binary recorded the true level), keep running.
		// EffectiveDBSchema() = max(derived, stored) so we still advertise the
		// DB's real schema to peers.
		slog.Warn("schema: DB is forward of this binary (additive — starting anyway)",
			"db_version", stored, "binary_version", CurrentSchemaVersion)
		return nil
	}
	return c.execLocal(ctx,
		`UPDATE schema_state SET version = ?, updated_at = ? WHERE id = 1`,
		derived, time.Now().UTC().Format(time.RFC3339))
}

// RefreshDBSchemaVersion recomputes and caches this node's effective DB-applied
// schema version: max(ledger-derived, stored schema_state.version). The stored
// term covers the "old binary on a newer DB" case — an old binary can't
// enumerate ledger IDs it doesn't know (derived under-reports), but the newer
// binary that forward-migrated the DB recorded the true level in schema_state,
// and additive-only makes trusting it safe. Call at the end of InitSchema and
// after a pre-stage migrate (the still-running old daemon must see its DB's
// freshly-staged schema). Returns the new effective value.
func (c *Client) RefreshDBSchemaVersion(ctx context.Context) int {
	eff := derivedSchemaVersion(ctx, c)
	if rows, err := c.Query(ctx, `SELECT version FROM schema_state WHERE id = 1`); err == nil && len(rows) > 0 {
		if stored := rows[0].Int("version"); stored > eff {
			eff = stored
		}
	}
	c.effectiveDBSchema.Store(int32(eff))
	return eff
}

// EffectiveDBSchema returns the cached effective DB-applied schema version (the
// single source for the replication handshake). Falls back to the binary const
// if not yet seeded (e.g. before InitSchema), preserving pre-ledger behavior.
func (c *Client) EffectiveDBSchema() int {
	if v := c.effectiveDBSchema.Load(); v > 0 {
		return int(v)
	}
	return CurrentSchemaVersion
}

// SetEffectiveDBSchemaForTest overrides the cached effective schema version.
// Test seam only: the binary const can't vary within one test binary, so
// fleet/unit tests use this to model per-node schema during a rolling window.
func (c *Client) SetEffectiveDBSchemaForTest(n int) { c.effectiveDBSchema.Store(int32(n)) }

// loadAppliedMigrations returns id→checksum for every recorded migration.
func loadAppliedMigrations(ctx context.Context, c *Client) (map[string]string, error) {
	rows, err := c.Query(ctx, `SELECT id, checksum FROM applied_migrations`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.String("id")] = r.String("checksum")
	}
	return out, nil
}

// derivedSchemaVersion is the highest schema Version among ledger migrations
// recorded as applied — the DB's schema level derived from verified reality.
// Only IDs this binary knows contribute (an older binary on a newer DB will
// under-report; the multi-version follow-up reconciles that against the stored
// forward version).
func derivedSchemaVersion(ctx context.Context, c *Client) int {
	applied, err := loadAppliedMigrations(ctx, c)
	if err != nil {
		return 1
	}
	byID := make(map[string]int, len(schemaMigrationLedger))
	for _, m := range schemaMigrationLedger {
		byID[m.ID] = m.Version
	}
	max := 1
	for id := range applied {
		if v, ok := byID[id]; ok && v > max {
			max = v
		}
	}
	return max
}

// sha256hex is the checksum of a migration's SQL (catches an applied migration
// being edited in place).
func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// tableExists reports whether a table is present (createTable presence check).
func tableExists(ctx context.Context, c *Client, name string) (bool, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?`, name)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), nil
}

// containsFold is a tiny case-insensitive substring helper — kept local so
// schema.go doesn't grow a strings dependency.
func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

var schemaDDL = []string{
	// ═══════════ CLUSTER ═══════════
	`CREATE TABLE IF NOT EXISTS cluster (
		id           TEXT PRIMARY KEY DEFAULT 'default',
		name         TEXT NOT NULL,
		domain       TEXT NOT NULL,
		ca_cert      TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL
	)`,

	// ═══════════ HOSTS ═══════════
	`CREATE TABLE IF NOT EXISTS hosts (
		name         TEXT PRIMARY KEY,
		address      TEXT NOT NULL,
		ssh_user     TEXT NOT NULL,
		ssh_port     INTEGER DEFAULT 22,
		grpc_port    INTEGER DEFAULT 7443,
		state        TEXT NOT NULL DEFAULT 'active',
		cert_serial  TEXT NOT NULL,
		cpu_total    INTEGER,
		mem_total    INTEGER,
		disk_total   INTEGER,
		ipmi_address TEXT,
		ipmi_user    TEXT,
		ipmi_pass    TEXT,
		watchdog_dev TEXT,
		fence_strategy TEXT DEFAULT 'best-effort',
		labels       TEXT,
		role         TEXT NOT NULL DEFAULT 'worker',
		schema_version INTEGER NOT NULL DEFAULT 0,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	`CREATE TABLE IF NOT EXISTS host_labels (
		host_name    TEXT NOT NULL,
		key          TEXT NOT NULL,
		value        TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (host_name, key)
	)`,

	`CREATE TABLE IF NOT EXISTS host_health (
		observer     TEXT NOT NULL,
		target       TEXT NOT NULL,
		status       TEXT NOT NULL,
		consecutive_failures INTEGER DEFAULT 0,
		last_seen    TEXT,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (observer, target)
	)`,

	`CREATE TABLE IF NOT EXISTS clock_skew (
		observer     TEXT NOT NULL,
		target       TEXT NOT NULL,
		skew_seconds REAL NOT NULL,
		updated_at   TEXT NOT NULL,
		PRIMARY KEY (observer, target)
	)`,

	// Per-host runtime telemetry the placement engine reads for the DiskIOPS/NetBW
	// dimensions (v33). Each host writes only its own row. Anti-entropy-excluded
	// (replicates via mutation_log; stale telemetry self-corrects on the next sample).
	`CREATE TABLE IF NOT EXISTS host_runtime_usage (
		host_name    TEXT PRIMARY KEY,
		disk_iops    INTEGER NOT NULL DEFAULT 0,
		net_mbps     INTEGER NOT NULL DEFAULT 0,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	`CREATE TABLE IF NOT EXISTS crl_versions (
		host         TEXT PRIMARY KEY,
		version      INTEGER NOT NULL,
		updated_at   TEXT NOT NULL
	)`,

	// Local schema version pin. NOT CRDT-replicated — each host's row
	// reflects only its local binary. Singleton row (id=1).
	`CREATE TABLE IF NOT EXISTS schema_state (
		id         INTEGER PRIMARY KEY,
		version    INTEGER NOT NULL,
		updated_at TEXT NOT NULL
	)`,

	// Cluster-wide leader leases (failover coordinator, etc.).
	// Holders renew before expires_at; an empty/expired row may be claimed by anyone.
	// Replicated via CRDT — readers must verify lease freshness against local time.
	`CREATE TABLE IF NOT EXISTS leader_election (
		key        TEXT PRIMARY KEY,
		holder     TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,

	// Per-VM startup leases held by health.reconciler so that during a failover
	// race only one host actually issues libvirt.Start for a given VM.
	`CREATE TABLE IF NOT EXISTS vm_locks (
		vm_name    TEXT PRIMARY KEY,
		holder     TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`,

	// runtime_action_proofs (v38, split-brain hardening) — the durable, single-use
	// authorization a coordinator (holding the failover lease + local quorum) writes
	// BEFORE a dangerous runtime-ownership action, so the executing host (which does
	// not hold the lease) can validate it. Carries a full action lifecycle with a
	// monotone state lattice (the merge lives in sync.go — proofRank /
	// proofMergeKeepLocal(Row), a dedicated customMergeTables bucket, NOT resolver.go):
	// rows are immutable except forward status transitions (prepared→in_progress→
	// completed/failed); terminal beats non-terminal and never regresses regardless of
	// updated_at; a completed⊕failed disagreement is left unresolved (a safety fault).
	// SECURITY-CRITICAL, NON-LWW merge. Replication (see sync.go, authoritative): WAL
	// relay is receiver-capability-gated (suppressed to peers lacking split_brain_gate_v1)
	// and anti-entropy carries it on the peer-mTLS SENSITIVE lane UNCONDITIONALLY — safe
	// because the merging node always runs the v38 monotone resolver and proof rows are
	// only ever written once the gate is cluster-wide. VMs bind via (target_name +
	// vms.pending_action_id); containers bind via relocation_token (their PK row is
	// tombstoned+reinserted on re-key, so a column on it would not survive).
	`CREATE TABLE IF NOT EXISTS runtime_action_proofs (
		id                TEXT PRIMARY KEY,
		action            TEXT NOT NULL,           -- reschedule | promote | relocate | lb_apply | owner_assert
		target_kind       TEXT NOT NULL,           -- vm | container | lb
		target_name       TEXT NOT NULL,
		dest_host         TEXT NOT NULL,
		coordinator       TEXT NOT NULL,
		lease_holder      TEXT NOT NULL DEFAULT '',
		lease_expires_at  TEXT NOT NULL DEFAULT '',
		quorum_live       INTEGER NOT NULL DEFAULT 0,
		quorum_needed     INTEGER NOT NULL DEFAULT 0,
		owner_epoch       TEXT NOT NULL DEFAULT '', -- superseded owner epoch (Phase 4/5); '' pre-epoch
		fence_epoch       TEXT NOT NULL DEFAULT '', -- fence proof reference (Phase 5); '' pre-epoch
		relocation_token  TEXT NOT NULL DEFAULT '', -- container binding key; '' for VMs
		status            TEXT NOT NULL DEFAULT 'prepared', -- prepared | in_progress | completed | failed
		step_state        TEXT NOT NULL DEFAULT '', -- forward-only step checkpoints for multi-step resume
		result_code       TEXT NOT NULL DEFAULT '',
		result_detail     TEXT NOT NULL DEFAULT '',
		started_at        TEXT NOT NULL DEFAULT '',
		completed_at      TEXT NOT NULL DEFAULT '',
		executor_host     TEXT NOT NULL DEFAULT '',
		created_at        TEXT NOT NULL,
		updated_at        TEXT NOT NULL,
		deleted_at        TEXT
	)`,

	// Rebalancer proposals. One row per (vm, generation). Pending
	// rows expire if not approved/applied within the proposal TTL.
	`CREATE TABLE IF NOT EXISTS rebalance_proposals (
		id            TEXT PRIMARY KEY,
		vm_name       TEXT NOT NULL,
		src_host      TEXT NOT NULL,
		dst_host      TEXT NOT NULL,
		policy        TEXT NOT NULL,
		expected_gain REAL NOT NULL,
		status        TEXT NOT NULL,  -- pending | approved | applied | rejected | expired
		proposed_at   TEXT NOT NULL,
		applied_at    TEXT,
		expires_at    TEXT NOT NULL,
		detail        TEXT,
		updated_at    TEXT NOT NULL
	)`,

	// ═══════════ PCI DEVICES ═══════════
	`CREATE TABLE IF NOT EXISTS host_pci_devices (
		host_name       TEXT NOT NULL,
		address         TEXT NOT NULL,
		vendor_id       TEXT NOT NULL,
		device_id       TEXT NOT NULL,
		vendor_name     TEXT,
		device_name     TEXT,
		type            TEXT NOT NULL,
		iommu_group     INTEGER,
		sriov_capable   BOOLEAN DEFAULT 0,
		sriov_vfs_total INTEGER DEFAULT 0,
		sriov_vfs_free  INTEGER DEFAULT 0,
		driver          TEXT,
		vm_name         TEXT,
		numa_node       INTEGER,
		pcie_root_port  TEXT,
		pcie_bridge     TEXT,
		link_clique     TEXT,
		link_peers      TEXT,
		updated_at      TEXT NOT NULL,
		deleted_at      TEXT,
		PRIMARY KEY (host_name, address)
	)`,

	// ═══════════ IMAGES ═══════════
	`CREATE TABLE IF NOT EXISTS images (
		name         TEXT PRIMARY KEY,
		format       TEXT NOT NULL,
		source_url   TEXT,
		checksum     TEXT,
		size_bytes   INTEGER,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	`CREATE TABLE IF NOT EXISTS image_hosts (
		image_name   TEXT NOT NULL,
		host_name    TEXT NOT NULL,
		path         TEXT NOT NULL,
		status       TEXT NOT NULL DEFAULT 'ready',
		pulled_at    TEXT,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (image_name, host_name)
	)`,

	// ═══════════ NETWORKS ═══════════
	`CREATE TABLE IF NOT EXISTS networks (
		name         TEXT PRIMARY KEY,
		stack_name   TEXT,
		type         TEXT NOT NULL,
		config       TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// ═══════════ VOLUMES ═══════════
	`CREATE TABLE IF NOT EXISTS volumes (
		name         TEXT PRIMARY KEY,
		stack_name   TEXT,
		type         TEXT NOT NULL,
		config       TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// ═══════════ STACKS ═══════════
	`CREATE TABLE IF NOT EXISTS stacks (
		name         TEXT PRIMARY KEY,
		compose_hash TEXT NOT NULL,
		compose_yaml TEXT NOT NULL,
		state        TEXT NOT NULL DEFAULT 'active',
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// ═══════════ VMS ═══════════
	`CREATE TABLE IF NOT EXISTS vms (
		name              TEXT PRIMARY KEY,
		stack_name        TEXT,
		host_name         TEXT NOT NULL,
		spec              TEXT NOT NULL,
		state             TEXT NOT NULL DEFAULT 'creating',
		state_detail      TEXT,
		cpu_actual        INTEGER,
		mem_actual        INTEGER,
		created_at        TEXT NOT NULL,
		updated_at        TEXT NOT NULL,
		deleted_at        TEXT,
		-- v38 (split-brain hardening): control-plane pointer linking a state='pending'
		-- transition to the runtime_action_proofs row that authorizes the start. Set once
		-- with the pending transition, cleared in the same mutation that exits pending.
		-- '' = no in-flight proof-gated action. Carved out of LWW (ruleColUnresolved).
		pending_action_id TEXT NOT NULL DEFAULT ''
	)`,

	`CREATE TABLE IF NOT EXISTS vm_interfaces (
		vm_name         TEXT NOT NULL,
		network_name    TEXT NOT NULL,
		ordinal         INTEGER NOT NULL,
		mac             TEXT NOT NULL,
		ip              TEXT,
		tap_device      TEXT,
		security_groups TEXT,                    -- : JSON []string of SG names; NULL = none
		updated_at      TEXT NOT NULL,
		deleted_at      TEXT,
		PRIMARY KEY (vm_name, network_name)
	)`,

	// container_interfaces is the container analogue of vm_interfaces (v35): one
	// row per litevirt-MANAGED container NIC. veth_device is the deterministic
	// host-side veth the firewall reconciler binds security groups to (the CT
	// equivalent of vm_interfaces.tap_device). PK is (host_name, ct_name, ordinal)
	// — ordinal, not network_name, so a container can hold multiple NICs on one
	// network. Raw/unmanaged bridge NICs get NO row (this table is the managed-NIC
	// source of truth).
	`CREATE TABLE IF NOT EXISTS container_interfaces (
		host_name       TEXT NOT NULL,
		ct_name         TEXT NOT NULL,
		network_name    TEXT NOT NULL,
		ordinal         INTEGER NOT NULL,
		mac             TEXT NOT NULL,
		ip              TEXT,
		veth_device     TEXT,
		security_groups TEXT,                    -- JSON []string of SG names; NULL = none
		updated_at      TEXT NOT NULL,
		deleted_at      TEXT,
		PRIMARY KEY (host_name, ct_name, ordinal)
	)`,

	`CREATE TABLE IF NOT EXISTS vm_disks (
		vm_name      TEXT NOT NULL,
		disk_name    TEXT NOT NULL,
		host_name    TEXT NOT NULL,
		path         TEXT NOT NULL,
		size_bytes   INTEGER,
		backing_image TEXT,
		storage_type TEXT NOT NULL DEFAULT 'local',
		storage_volume TEXT,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (vm_name, disk_name)
	)`,

	// ═══════════ SNAPSHOTS ═══════════
	`CREATE TABLE IF NOT EXISTS snapshots (
		id                 TEXT PRIMARY KEY,
		vm_name            TEXT NOT NULL,
		host_name          TEXT NOT NULL,
		name               TEXT NOT NULL,
		state              TEXT NOT NULL,
		size_bytes         INTEGER,
		parent_id          TEXT,
		type               TEXT NOT NULL DEFAULT 'disk',
		vmstate_path       TEXT,
		vmstate_size_bytes INTEGER NOT NULL DEFAULT 0,
		created_at         TEXT NOT NULL,
		updated_at         TEXT NOT NULL,
		deleted_at         TEXT,
		UNIQUE(vm_name, name)
	)`,

	// ═══════════ RESOURCE MAPPINGS (#14) ═══════════
	// Cluster-wide aliases for equivalent passthrough devices. One row per
	// (mapping name, host, address); a VM requesting a device by mapping name
	// can be placed on / migrated to any host with a matching row.
	`CREATE TABLE IF NOT EXISTS resource_mappings (
		name        TEXT NOT NULL,
		host_name   TEXT NOT NULL,
		address     TEXT NOT NULL,
		vendor      TEXT,
		device      TEXT,
		description TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT,
		PRIMARY KEY (name, host_name, address)
	)`,

	// ═══════════ NOTIFICATIONS (#5) ═══════════
	// Operator notification targets (webhook/slack/…) and the routes that select
	// which event patterns at which min-severity go to each target. CRDT-
	// replicated so every daemon notifies consistently.
	`CREATE TABLE IF NOT EXISTS notification_targets (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		type       TEXT NOT NULL,            -- webhook | slack
		config     TEXT NOT NULL,            -- JSON (url, …)
		enabled    INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS notification_routes (
		id            TEXT PRIMARY KEY,
		event_pattern TEXT NOT NULL,         -- glob, e.g. "backup.*", "*"
		target_id     TEXT NOT NULL,
		min_severity  TEXT NOT NULL DEFAULT 'info', -- info | warn | error
		enabled       INTEGER NOT NULL DEFAULT 1,
		created_at    TEXT NOT NULL,
		updated_at    TEXT NOT NULL,
		deleted_at    TEXT
	)`,

	// ═══════════ LOAD BALANCERS ═══════════
	`CREATE TABLE IF NOT EXISTS lb_configs (
		name         TEXT PRIMARY KEY,
		stack_name   TEXT,
		vip          TEXT NOT NULL,
		algorithm    TEXT NOT NULL DEFAULT 'roundrobin',
		hosts        TEXT NOT NULL DEFAULT '',
		ports        TEXT NOT NULL DEFAULT '[]',
		enabled      INTEGER NOT NULL DEFAULT 1,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		generation   TEXT NOT NULL DEFAULT ''
	)`,

	`CREATE TABLE IF NOT EXISTS lb_backends (
		lb_name      TEXT NOT NULL,
		name         TEXT NOT NULL,
		address      TEXT NOT NULL,
		is_vm        INTEGER NOT NULL DEFAULT 0,
		vm_name      TEXT,
		enabled      INTEGER NOT NULL DEFAULT 1,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		generation   TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (lb_name, name)
	)`,

	// ═══════════ USERS & AUTH ═══════════
	`CREATE TABLE IF NOT EXISTS users (
		username      TEXT PRIMARY KEY,
		role          TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		realm         TEXT NOT NULL DEFAULT 'local',
		display_name  TEXT,
		email         TEXT,
		created_at    TEXT NOT NULL,
		updated_at    TEXT NOT NULL,
		deleted_at    TEXT
	)`,

	`CREATE TABLE IF NOT EXISTS tokens (
		id           TEXT PRIMARY KEY,
		username     TEXT NOT NULL,
		name         TEXT NOT NULL,
		token_hash   TEXT NOT NULL,
		expires_at   TEXT,
		last_used_at TEXT,
		scope_paths  TEXT,                -- JSON []string of allowed path prefixes; empty/NULL = inherit user's full perms
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL DEFAULT '', -- bumped on create + revoke (not on last_used_at) so a revoke wins LWW
		deleted_at   TEXT
	)`,

	// Custom roles. Built-in roles are seeded on startup with
	// built_in=1 and CANNOT be modified or deleted via gRPC.
	`CREATE TABLE IF NOT EXISTS roles (
		name         TEXT PRIMARY KEY,
		verbs        TEXT NOT NULL,        -- JSON array of verb strings, e.g. ["vm.*", "lb.read"]
		description  TEXT,
		built_in     BOOLEAN NOT NULL DEFAULT 0,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// Path × role × principal bindings. principal is one of:
	//   user:<username>           — direct user binding
	//   group:<group>@<realm>     — group binding from realm sync
	`CREATE TABLE IF NOT EXISTS role_bindings (
		id           TEXT PRIMARY KEY,
		path         TEXT NOT NULL,
		role         TEXT NOT NULL,
		principal    TEXT NOT NULL,
		propagate    BOOLEAN NOT NULL DEFAULT 1,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// Sessions. Opaque IDs replace JWT-only auth; revoke is
	// immediate (vs waiting for token expiry). Idle timeout is enforced
	// at every RPC by the auth interceptor.
	`CREATE TABLE IF NOT EXISTS sessions (
		id            TEXT PRIMARY KEY,
		username      TEXT NOT NULL,
		realm         TEXT NOT NULL,
		ip            TEXT,
		user_agent    TEXT,
		created_at    TEXT NOT NULL,
		last_used_at  TEXT NOT NULL,
		expires_at    TEXT NOT NULL,
		revoked_at    TEXT
	)`,

	// 2FA enrollments per (user, method).
	//
	//   TOTP: secret is the base32-encoded shared secret. TOTP verification
	//     requires the raw secret to recompute HMAC, so bcrypt is not an
	//     option. Secrets are stored in cluster DB at rest; in
	//     they will be AES-256-GCM-sealed by the cluster master key.
	//   WebAuthn: secret is the credential blob (public key + signCount).
	//     This is non-sensitive; storage is plaintext in both phases.
	//
	// Recovery codes (separate table) ARE bcrypt-hashed because the verifier
	// receives a candidate plaintext and only needs constant-time match.
	`CREATE TABLE IF NOT EXISTS user_2fa (
		username      TEXT NOT NULL,
		method        TEXT NOT NULL,        -- totp | webauthn
		secret        TEXT NOT NULL,
		label         TEXT,                 -- user-supplied label (e.g. "phone"); normalized to '' on write, never NULL
		enrolled_at   TEXT NOT NULL,
		last_used_at  TEXT,
		updated_at    TEXT NOT NULL,
		last_step     INTEGER NOT NULL DEFAULT 0, -- highest consumed TOTP time-step (replay guard)
		deleted_at    TEXT,                 -- soft-delete tombstone (sensitive anti-entropy lane)
		epoch         TEXT NOT NULL DEFAULT '', -- active-factor-set this row belongs to; valid only if == user_2fa_sets.active_epoch
		PRIMARY KEY (username, method, label)
	)`,
	// user_2fa_sets is the per-user active-factor-set pointer. A factor renders
	// only when its epoch matches active_epoch; DeleteUser tombstones the pointer,
	// so a factor a partitioned peer resurrects (one this node never saw, hence
	// could not tombstone) still cannot validate. Re-enroll after a delete mints a
	// fresh epoch. Converges by ordinary updated_at LWW.
	`CREATE TABLE IF NOT EXISTS user_2fa_sets (
		username     TEXT PRIMARY KEY,
		active_epoch TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// Recovery codes (single-use). Used codes have used_at set
	// rather than being deleted, so reuse is detectable. set_id ties a code to
	// its enrollment set; a code validates only when set_id == the user's
	// active_set_id (recovery_code_sets), so a resurrected old-set code can't
	// be accepted after re-enroll. updated_at/deleted_at make it LWW-repairable.
	`CREATE TABLE IF NOT EXISTS recovery_codes (
		username   TEXT NOT NULL,
		code_hash  TEXT NOT NULL,           -- bcrypt of code
		used_at    TEXT,
		created_at TEXT NOT NULL,
		set_id     TEXT NOT NULL DEFAULT '', -- enrollment set; valid only if == active_set_id
		updated_at TEXT NOT NULL DEFAULT '', -- LWW key for the sensitive anti-entropy lane
		deleted_at TEXT,                      -- soft-delete tombstone
		PRIMARY KEY (username, code_hash)
	)`,

	// recovery_code_sets is the per-user active recovery-code pointer. Re-enroll
	// mints a random active_set_id and LWW-upserts this row; verification matches
	// a code's set_id against active_set_id. Converges by ordinary updated_at LWW
	// (no numeric/MAX generation ordering, which per-node-monotonic NowTS makes
	// unsafe across nodes).
	`CREATE TABLE IF NOT EXISTS recovery_code_sets (
		username      TEXT PRIMARY KEY,
		active_set_id TEXT NOT NULL,
		updated_at    TEXT NOT NULL,
		deleted_at    TEXT
	)`,

	// ═══════════ DNS ═══════════
	`CREATE TABLE IF NOT EXISTS dns_records (
		name         TEXT PRIMARY KEY,
		type         TEXT NOT NULL DEFAULT 'A',
		value        TEXT NOT NULL,
		source       TEXT NOT NULL DEFAULT 'auto',
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// ═══════════ FENCING LOG ═══════════
	`CREATE TABLE IF NOT EXISTS fencing_log (
		id           TEXT PRIMARY KEY,
		host_name    TEXT NOT NULL,
		method       TEXT NOT NULL,
		result       TEXT NOT NULL,
		timestamp    TEXT NOT NULL,
		detail       TEXT
	)`,

	// ═══════════ AUDIT LOG ═══════════
	`CREATE TABLE IF NOT EXISTS audit_log (
		id           TEXT PRIMARY KEY,
		timestamp    TEXT NOT NULL,
		username     TEXT,
		host_name    TEXT,
		action       TEXT NOT NULL,
		target       TEXT NOT NULL,
		detail       TEXT,
		result       TEXT NOT NULL,
		-- tamper-evidence: each row's content_hash =
		-- SHA-256(prev_hash || canonical(this row)). Operators
		-- detect tampering by replaying the chain via the
		-- VerifyAuditLog RPC. Both columns are nullable for
		-- pre-3.4 rows; the verifier treats absent values as a
		-- chain reset point.
		prev_hash    TEXT,
		content_hash TEXT
	)`,

	// Per-VM operational event store (v13). Durable, CRDT-replicated,
	// append-only, and PRUNABLE — distinct from the tamper-evident
	// audit_log hash chain. Holds VM lifecycle + backup outcomes
	// (incl. per-VM attribution for fan-out backup schedules) so
	// operators can see, e.g., when a VM failed to back up. Replicated
	// via the append-only branch in replicator.go (INSERT OR IGNORE on
	// id) — no updated_at, no LWW.
	`CREATE TABLE IF NOT EXISTS vm_events (
		id         TEXT PRIMARY KEY,
		vm_name    TEXT NOT NULL,
		host_name  TEXT,
		type       TEXT NOT NULL,                 -- e.g. "backup.started" / "backup.failed" / "vm.started"
		result     TEXT NOT NULL DEFAULT 'ok',    -- "ok" | "error"
		severity   TEXT NOT NULL DEFAULT 'info',  -- "info" | "warn" | "error"
		detail     TEXT,
		username   TEXT,
		ts         TEXT NOT NULL                  -- RFC3339Nano UTC (stable ordering, like audit_log.timestamp)
	)`,

	// vm_backups indexes the latest backup size per (vm, disk, repo) so the
	// tenancy admission path can sum a project's backup footprint cheaply
	// (manifests themselves live on-disk in pbsstore repos, not in Corrosion).
	// Upserted on every successful backup push; total_bytes is the latest
	// manifest's logical size for that disk in that repo.
	`CREATE TABLE IF NOT EXISTS vm_backups (
		vm_name     TEXT NOT NULL,
		disk_name   TEXT NOT NULL,
		repo        TEXT NOT NULL,
		total_bytes INTEGER NOT NULL DEFAULT 0,
		updated_at  TEXT NOT NULL,
		PRIMARY KEY (vm_name, disk_name, repo)
	)`,

	// container_backups is the container analogue of vm_backups (v26): the
	// latest full-backup size per (container, repo), so the tenancy backup_gib
	// quota can sum container footprints alongside VMs. A container has one
	// logical "disk" (its rootfs), so there's no disk_name dimension.
	`CREATE TABLE IF NOT EXISTS container_backups (
		ct_name     TEXT NOT NULL,
		repo        TEXT NOT NULL,
		total_bytes INTEGER NOT NULL DEFAULT 0,
		updated_at  TEXT NOT NULL,
		PRIMARY KEY (ct_name, repo)
	)`,

	// container_snapshots is the container analogue of the snapshots table
	// (v27): per-container point-in-time snapshots. A snapshot is a freeze+tar
	// of the container's on-disk dir stored host-local at `path` (type='tar';
	// COW variants may be added later). host-local like the container itself.
	`CREATE TABLE IF NOT EXISTS container_snapshots (
		id          TEXT PRIMARY KEY,
		ct_name     TEXT NOT NULL,
		host_name   TEXT NOT NULL,
		name        TEXT NOT NULL,
		state       TEXT NOT NULL,
		size_bytes  INTEGER NOT NULL DEFAULT 0,
		type        TEXT NOT NULL DEFAULT 'tar',
		path        TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT,
		UNIQUE(host_name, ct_name, name)
	)`,

	// ═══════════ OVERLAY NETWORKING ═══════════
	`CREATE TABLE IF NOT EXISTS network_vteps (
		network_name  TEXT NOT NULL,
		host_name     TEXT NOT NULL,
		vtep_ip       TEXT NOT NULL,
		vni           INTEGER NOT NULL,
		updated_at    TEXT NOT NULL,
		deleted_at    TEXT,
		PRIMARY KEY (network_name, host_name)
	)`,

	`CREATE TABLE IF NOT EXISTS bgp_peers (
		host_name   TEXT PRIMARY KEY,
		asn         INTEGER NOT NULL,
		vtep_ip     TEXT NOT NULL,
		router_id   TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	`CREATE TABLE IF NOT EXISTS ip_allocations (
		network      TEXT NOT NULL,
		ip           TEXT NOT NULL,
		mac          TEXT NOT NULL,
		vm_name      TEXT NOT NULL,        -- the owner NAME (legacy column name); see owner_kind
		owner_kind   TEXT NOT NULL DEFAULT 'vm',  -- 'vm' | 'ct' (v36)
		owner_host   TEXT NOT NULL DEFAULT '',    -- '' for VMs (cluster-global names); host for CTs (v36)
		allocated_at TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (network, ip)
	)`,

	// ═══════════ VM RESTART TRACKING ═══════════
	`CREATE TABLE IF NOT EXISTS vm_restarts (
		vm_name       TEXT PRIMARY KEY,
		attempt_count INTEGER DEFAULT 0,
		window_start  TEXT NOT NULL,
		last_restart  TEXT,
		updated_at    TEXT NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS security_groups (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		stack_name  TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// idempotency_keys (v39): records a mutating RPC keyed by a client-supplied
	// idempotency key. It is claimed in_progress (with an opaque claim_id owner
	// token) BEFORE side effects, then completed with the response, so a
	// lost-response retry to the SAME entry node replays the stored response instead
	// of executing twice. claim_id gates complete/release/extend so a stale owner
	// whose claim was stolen after its lease lapsed can't mutate the newer claim.
	// request_hash detects key reuse with a different payload (→ 409). This table is
	// LOCAL-only (written via execLocal, never replicated): the create RPCs own the
	// claim on the entry node and strip the key before forwarding, so a mutable
	// in_progress row never replicates to lose an LWW race against a completed row.
	// Cross-node dedup falls back to the create name-uniqueness constraint. Records
	// are ephemeral and TTL-reaped via expires_at.
	`CREATE TABLE IF NOT EXISTS idempotency_keys (
		key          TEXT PRIMARY KEY,
		claim_id     TEXT NOT NULL DEFAULT '',
		method       TEXT NOT NULL,
		request_hash TEXT NOT NULL,
		response     TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL DEFAULT 'completed',
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		expires_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// containers cluster state. One row per LXC/OCI
	// container; aggregated by `lv ct ls` cluster-wide. Lifecycle
	// transitions are written by the daemon owning the container.
	`CREATE TABLE IF NOT EXISTS containers (
		host_name      TEXT NOT NULL,
		name           TEXT NOT NULL,
		state          TEXT NOT NULL DEFAULT 'stopped',
		image          TEXT,
		cpu_limit      INTEGER NOT NULL DEFAULT 0,
		memory_mib     INTEGER NOT NULL DEFAULT 0,
		labels         TEXT,                  -- JSON {key:value}
		restart_policy TEXT,                  -- JSON {condition,delay,max_attempts,window}; '' = none (v24)
		state_detail   TEXT,                  -- stop cause / intent, e.g. 'operator-stop' (v24)
		project        TEXT NOT NULL DEFAULT '_default', -- tenancy bucket, mirrors vms.project (v25)
		is_template     INTEGER NOT NULL DEFAULT 0,       -- clone-source template, mirrors vms.is_template (v28)
		on_host_failure TEXT,                             -- host-loss policy: ''/'none' | 'image-recreate' (v28); v34 prefers restore-from-backup, then image-recreate
		create_spec     TEXT,                             -- JSON create-time intent (template/distro/release/arch/networks) for faithful relocation/restore (v34)
		relocate_token  TEXT,                             -- attempt token a restore-relocation stamps so the coordinator can prove a target row is ITS restore (v34)
		created_at     TEXT NOT NULL,
		updated_at     TEXT NOT NULL,
		deleted_at     TEXT,
		PRIMARY KEY (host_name, name)
	)`,

	// container_restarts mirrors vm_restarts: per-container attempt counter within
	// a sliding window, used by the container reconciler to enforce
	// max_attempts/window/delay (v24).
	`CREATE TABLE IF NOT EXISTS container_restarts (
		host_name     TEXT NOT NULL,
		name          TEXT NOT NULL,
		attempt_count INTEGER DEFAULT 0,
		window_start  TEXT NOT NULL,
		last_restart  TEXT,
		updated_at    TEXT NOT NULL,
		PRIMARY KEY (host_name, name)
	)`,

	`CREATE TABLE IF NOT EXISTS sg_rules (
		id          TEXT PRIMARY KEY,
		sg_id       TEXT NOT NULL,
		direction   TEXT NOT NULL,
		proto       TEXT NOT NULL DEFAULT 'all',
		port_range  TEXT,
		cidr        TEXT,
		action      TEXT NOT NULL DEFAULT 'accept',
		priority    INTEGER NOT NULL DEFAULT 100,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// ═══════════ DISTRIBUTED FIREWALL — non-NIC tiers + ipsets (v21) ═══════════
	// The renderer (internal/firewall) already consumes ip sets, the cluster /
	// host rule tiers, and a per-scope default-deny policy; these tables are the
	// authoritative source the CorrosionPlanLoader reads. security_groups +
	// sg_rules (above) cover the per-NIC tier; vm_interfaces.security_groups binds
	// NICs to SGs. stack_name is set when a row originated from a compose file so
	// `compose down` can tombstone exactly the stack's firewall state.

	// Named CIDR lists. Rules reference one with cidr = "@<name>".
	`CREATE TABLE IF NOT EXISTS ip_sets (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		cidrs       TEXT NOT NULL DEFAULT '[]', -- JSON []string of CIDRs
		stack_name  TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// Cluster-tier rules apply to every NIC on every host (the cluster_default
	// chain). Use for blanket allow/deny that should never be overridden.
	`CREATE TABLE IF NOT EXISTS cluster_firewall_rules (
		id          TEXT PRIMARY KEY,
		direction   TEXT NOT NULL,
		proto       TEXT NOT NULL DEFAULT 'all',
		port_range  TEXT,
		cidr        TEXT,
		action      TEXT NOT NULL DEFAULT 'accept',
		priority    INTEGER NOT NULL DEFAULT 100,
		comment     TEXT,
		stack_name  TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// Host-tier rules apply to every NIC on one host (the host_overrides chain),
	// selected by host_name.
	`CREATE TABLE IF NOT EXISTS host_firewall_rules (
		id          TEXT PRIMARY KEY,
		host_name   TEXT NOT NULL,
		direction   TEXT NOT NULL,
		proto       TEXT NOT NULL DEFAULT 'all',
		port_range  TEXT,
		cidr        TEXT,
		action      TEXT NOT NULL DEFAULT 'accept',
		priority    INTEGER NOT NULL DEFAULT 100,
		comment     TEXT,
		stack_name  TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// Per-scope default-deny policy. scope = 'cluster' (the cluster-wide default)
	// or a host name (overrides the cluster default on that host only). When a
	// host has no row, the cluster row applies; when neither is set, policy is
	// accept (the unchanged pre-v21 behaviour).
	`CREATE TABLE IF NOT EXISTS firewall_defaults (
		scope        TEXT PRIMARY KEY,          -- 'cluster' | <host name>
		default_deny INTEGER NOT NULL DEFAULT 0,
		stack_name   TEXT,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT
	)`,

	// ═══════════ STORAGE POOLS ═══════════
	`CREATE TABLE IF NOT EXISTS storage_pools (
		host_name    TEXT NOT NULL,
		name         TEXT NOT NULL,
		driver       TEXT NOT NULL DEFAULT 'local',
		source       TEXT,
		target       TEXT,
		total_bytes  INTEGER DEFAULT 0,
		used_bytes   INTEGER DEFAULT 0,
		state        TEXT NOT NULL DEFAULT 'active',
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (host_name, name)
	)`,

	// Backup repos registered at runtime — a logical name → on-disk path map,
	// CRDT-replicated so a compose `backup-repos:` block makes a repo resolvable
	// cluster-wide. Daemon config `backup_repos:` still works and takes
	// precedence; this table is the fallback the scheduler runner consults.
	// stack_name is set for compose-defined repos so `compose down` removes them.
	`CREATE TABLE IF NOT EXISTS backup_repos (
		name        TEXT PRIMARY KEY,
		path        TEXT NOT NULL,
		stack_name  TEXT,
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// Per-VM incremental-replication dirty-bitmap anchor (v22), keyed by the
	// REAL vm + target repo. Replaces backup_schedules.last_checkpoint for
	// replication, which broke fan-out schedules (their row's vm_name is a
	// sentinel, so per-VM writes matched no row → always-full copies).
	`CREATE TABLE IF NOT EXISTS replication_checkpoints (
		vm_name    TEXT NOT NULL,
		repo       TEXT NOT NULL,
		checkpoint TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT,
		PRIMARY KEY (vm_name, repo)
	)`,

	// ═══════════ REPLICATION ═══════════
	`CREATE TABLE IF NOT EXISTS mutation_log (
		seq        INTEGER PRIMARY KEY AUTOINCREMENT,
		hlc        TEXT NOT NULL,
		origin     TEXT NOT NULL,
		stmts      TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS replication_watermarks (
		peer_name  TEXT PRIMARY KEY,
		last_seq   INTEGER NOT NULL DEFAULT 0,
		updated_at TEXT NOT NULL
	)`,

	// Crescent protocol: deduplication table for relay fan-out.
	// Tracks (origin, hlc) pairs already applied to prevent double-processing
	// when a leaf receives the same mutation from multiple relays.
	`CREATE TABLE IF NOT EXISTS mutation_seen (
		origin TEXT NOT NULL,
		hlc    TEXT NOT NULL,
		PRIMARY KEY (origin, hlc)
	) WITHOUT ROWID`,

	// federation anycast service endpoints. A "service" is
	// a logical name (e.g. "api.litevirt.local") that may resolve to
	// any number of (ip, region) pairs. DNS round-robins among the
	// non-deleted rows on every query. Used to expose a multi-region
	// frontend behind one anycast/RR record.
	`CREATE TABLE IF NOT EXISTS service_endpoints (
		service_name TEXT NOT NULL,
		ip           TEXT NOT NULL,
		region       TEXT NOT NULL DEFAULT 'default',
		weight       INTEGER NOT NULL DEFAULT 1,
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		PRIMARY KEY (service_name, ip)
	)`,

	// tenancy core. Projects are a hierarchical bucket
	// for VMs / volumes / LBs / etc. The default project "_default"
	// is implicit — single-tenant clusters never need to interact
	// with this table.
	`CREATE TABLE IF NOT EXISTS projects (
		name        TEXT PRIMARY KEY,        -- canonical path, e.g. "/acme/team-foo"
		display     TEXT,                    -- human-readable label
		parent_name TEXT,                    -- parent project's name; NULL for root
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,

	// project_quotas is the admission-control gate. Each row caps
	// one resource dimension for one project. Zero = unbounded.
	`CREATE TABLE IF NOT EXISTS project_quotas (
		project_name      TEXT PRIMARY KEY,
		vcpu_limit        INTEGER NOT NULL DEFAULT 0,
		mem_mib_limit     INTEGER NOT NULL DEFAULT 0,
		disk_gib_limit    INTEGER NOT NULL DEFAULT 0,
		nic_limit         INTEGER NOT NULL DEFAULT 0,
		public_ip_limit   INTEGER NOT NULL DEFAULT 0,
		backup_gib_limit  INTEGER NOT NULL DEFAULT 0,
		updated_at        TEXT NOT NULL
	)`,

	// snapshot scheduler. One row per (vm, repo) pair; the
	// scheduler ticks once per minute on the leader, evaluates each
	// row's cron, fires BackupSnapshot, and records last_run_at on
	// success. Retention runs after each successful push.
	`CREATE TABLE IF NOT EXISTS backup_schedules (
		vm_name      TEXT NOT NULL,
		repo         TEXT NOT NULL,                    -- logical repo name resolved via daemon config.backup_repos
		cron         TEXT NOT NULL,                    -- 5-field cron, e.g. "0 2 * * *"
		keep_last    INTEGER NOT NULL DEFAULT 0,
		keep_daily   INTEGER NOT NULL DEFAULT 0,
		keep_weekly  INTEGER NOT NULL DEFAULT 0,
		keep_monthly INTEGER NOT NULL DEFAULT 0,
		keep_yearly  INTEGER NOT NULL DEFAULT 0,
		enabled      BOOLEAN NOT NULL DEFAULT 1,
		last_run_at  TEXT,
		last_run_err TEXT,
		updated_at   TEXT NOT NULL,
		deleted_at   TEXT,
		pool_name    TEXT,                            -- set when scope = "pool"
		scope        TEXT NOT NULL DEFAULT 'vm',      -- vm | pool | cluster | project
		project_name TEXT,                            -- set when scope = "project"
		PRIMARY KEY (vm_name, repo)
	)`,

	// Registry credentials (v23) — OCI/Docker registry logins for private
	// image pulls (lv ct pull → PullOCIImage → skopeo). A row is per-user
	// (scope='user', owner=<username>) or global (scope='global', owner='').
	// Resolution at pull time: the caller's row for the image's registry wins,
	// else the global row, else anonymous. CRDT-replicated, so secrets
	// propagate cluster-wide (see the v23 security note in the History block).
	`CREATE TABLE IF NOT EXISTS registry_credentials (
		id          TEXT PRIMARY KEY,
		scope       TEXT NOT NULL DEFAULT 'user',     -- 'user' | 'global'
		owner       TEXT NOT NULL DEFAULT '',         -- username for scope='user'; '' for global
		registry    TEXT NOT NULL,                    -- normalized host: docker.io | ghcr.io | registry:5000
		username    TEXT NOT NULL,
		secret      TEXT NOT NULL,                    -- registry password/token (plaintext — see v23 note)
		created_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		deleted_at  TEXT
	)`,
}

// schemaIndexes are CREATE INDEX IF NOT EXISTS statements added after table creation.
// These accelerate the most common query patterns (ListVMs by host, interfaces by VM, etc.).
var schemaIndexes = []string{
	// vm_events: per-VM timeline (newest-first list + per-VM prune cap) and the
	// cross-host live-stream poll (ts cursor).
	`CREATE INDEX IF NOT EXISTS idx_vm_events_vm_ts ON vm_events(vm_name, ts)`,
	`CREATE INDEX IF NOT EXISTS idx_vm_events_ts ON vm_events(ts)`,

	// VMs: filtered by host_name and stack_name in nearly every list/count query.
	`CREATE INDEX IF NOT EXISTS idx_vms_host ON vms(host_name) WHERE deleted_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_vms_stack ON vms(stack_name) WHERE deleted_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_vms_state ON vms(state) WHERE deleted_at IS NULL`,

	// VM interfaces: joined/filtered by vm_name on every VM list and inspect.
	`CREATE INDEX IF NOT EXISTS idx_vm_ifaces_vm ON vm_interfaces(vm_name) WHERE deleted_at IS NULL`,
	// VM interfaces: counted by network_name for ListNetworks VM count.
	`CREATE INDEX IF NOT EXISTS idx_vm_ifaces_net ON vm_interfaces(network_name) WHERE deleted_at IS NULL`,

	// VM disks: joined/filtered by vm_name for inspect and migration.
	`CREATE INDEX IF NOT EXISTS idx_vm_disks_vm ON vm_disks(vm_name) WHERE deleted_at IS NULL`,

	// Snapshots: listed by vm_name.
	`CREATE INDEX IF NOT EXISTS idx_snapshots_vm ON snapshots(vm_name) WHERE deleted_at IS NULL`,

	// Host health: queried by target for failover quorum and by observer for sweeps.
	`CREATE INDEX IF NOT EXISTS idx_health_target ON host_health(target)`,

	// PCI devices: filtered by host_name for placement and inspection.
	`CREATE INDEX IF NOT EXISTS idx_pci_host ON host_pci_devices(host_name) WHERE deleted_at IS NULL`,
	// PCI devices: filtered by vm_name for passthrough tracking.
	`CREATE INDEX IF NOT EXISTS idx_pci_vm ON host_pci_devices(vm_name) WHERE deleted_at IS NULL AND vm_name IS NOT NULL`,

	// Audit log: ordered by timestamp DESC for the UI audit page.
	`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)`,

	// Image hosts: filtered by host_name for per-host image availability.
	`CREATE INDEX IF NOT EXISTS idx_img_hosts_host ON image_hosts(host_name) WHERE deleted_at IS NULL`,

	// Tokens: filtered by username for auth lookups.
	`CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(username) WHERE deleted_at IS NULL`,

	// auth queries hit role_bindings by both path (longest-prefix
	// match) and principal (per-user permission resolution). Index both.
	`CREATE INDEX IF NOT EXISTS idx_role_bindings_path ON role_bindings(path) WHERE deleted_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_role_bindings_principal ON role_bindings(principal) WHERE deleted_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username) WHERE revoked_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_user_2fa_user ON user_2fa(username)`,

	// IP allocations: filtered by network for subnet management.
	`CREATE INDEX IF NOT EXISTS idx_ip_alloc_net ON ip_allocations(network) WHERE deleted_at IS NULL`,

	// Storage pools: filtered by host_name for per-host pool listing.
	`CREATE INDEX IF NOT EXISTS idx_storage_pools_host ON storage_pools(host_name) WHERE deleted_at IS NULL`,

	// Mutation log: queried by HLC for replication.
	`CREATE INDEX IF NOT EXISTS idx_mutation_log_hlc ON mutation_log(hlc)`,

	// Registry credentials: one LIVE credential per (scope, owner, registry).
	// Partial-on-live so a logout (soft-delete) never blocks a subsequent login
	// for the same triple; also backs the pull-time resolution lookup.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_registry_creds_triple ON registry_credentials(scope, owner, registry) WHERE deleted_at IS NULL`,
}

// tablePrimaryKeys maps table names to their primary key column(s).
// Used by LWW conflict resolution during replication to look up local rows.
var tablePrimaryKeys = map[string][]string{
	"cluster":                {"id"},
	"hosts":                  {"name"},
	"host_labels":            {"host_name", "key"},
	"host_health":            {"observer", "target"},
	"host_runtime_usage":     {"host_name"},
	"clock_skew":             {"observer", "target"},
	"crl_versions":           {"host"},
	"leader_election":        {"key"},
	"vm_locks":               {"vm_name"},
	"runtime_action_proofs":  {"id"},
	"idempotency_keys":       {"key"},
	"rebalance_proposals":    {"id"},
	"host_pci_devices":       {"host_name", "address"},
	"images":                 {"name"},
	"image_hosts":            {"image_name", "host_name"},
	"networks":               {"name"},
	"volumes":                {"name"},
	"stacks":                 {"name"},
	"vms":                    {"name"},
	"vm_interfaces":          {"vm_name", "network_name"},
	"container_interfaces":   {"host_name", "ct_name", "ordinal"},
	"vm_disks":               {"vm_name", "disk_name"},
	"snapshots":              {"id"},
	"lb_configs":             {"name"},
	"lb_backends":            {"lb_name", "name"},
	"users":                  {"username"},
	"tokens":                 {"id"},
	"roles":                  {"name"},
	"role_bindings":          {"id"},
	"sessions":               {"id"},
	"user_2fa":               {"username", "method", "label"},
	"user_2fa_sets":          {"username"},
	"recovery_codes":         {"username", "code_hash"},
	"recovery_code_sets":     {"username"},
	"dns_records":            {"name"},
	"fencing_log":            {"id"},
	"audit_log":              {"id"},
	"vm_events":              {"id"},
	"network_vteps":          {"network_name", "host_name"},
	"bgp_peers":              {"host_name"},
	"ip_allocations":         {"network", "ip"},
	"vm_restarts":            {"vm_name"},
	"security_groups":        {"id"},
	"sg_rules":               {"id"},
	"containers":             {"host_name", "name"},
	"storage_pools":          {"host_name", "name"},
	"mutation_log":           {"seq"},
	"replication_watermarks": {"peer_name"},
	"backup_schedules":       {"vm_name", "repo"},
	"service_endpoints":      {"service_name", "ip"},
	"projects":               {"name"},
	"project_quotas":         {"project_name"},
	"resource_mappings":      {"name", "host_name", "address"},
	"notification_targets":   {"id"},
	"notification_routes":    {"id"},
	"registry_credentials":   {"id"},
	// Replicated tables with updated_at that previously lacked an entry, so LWW
	// was silently skipped in both the merge and the Crescent apply path.
	"vm_backups":              {"vm_name", "disk_name", "repo"},
	"container_backups":       {"ct_name", "repo"},
	"container_snapshots":     {"id"},
	"container_restarts":      {"host_name", "name"},
	"ip_sets":                 {"id"},
	"cluster_firewall_rules":  {"id"},
	"host_firewall_rules":     {"id"},
	"firewall_defaults":       {"scope"},
	"backup_repos":            {"name"},
	"replication_checkpoints": {"vm_name", "repo"},
}

// schemaMigrations contains ALTER TABLE statements for upgrading existing databases.
// Errors are ignored since columns may already exist.
var schemaMigrations = []string{
	// PCIe topology columns on host_pci_devices.
	`ALTER TABLE host_pci_devices ADD COLUMN pcie_root_port TEXT`,
	`ALTER TABLE host_pci_devices ADD COLUMN pcie_bridge TEXT`,
	`ALTER TABLE host_pci_devices ADD COLUMN link_clique TEXT`,
	`ALTER TABLE host_pci_devices ADD COLUMN link_peers TEXT`,

	// Target device name for hot-plug disk detach.
	`ALTER TABLE vm_disks ADD COLUMN target_dev TEXT`,

	// Progress tracking for image pulls.
	`ALTER TABLE image_hosts ADD COLUMN progress_pct REAL DEFAULT 0`,

	// Host version tracking for rolling upgrades.
	`ALTER TABLE hosts ADD COLUMN version TEXT DEFAULT ''`,

	// LB ports column and stack_name (added for standalone LB support).
	`ALTER TABLE lb_configs ADD COLUMN ports TEXT NOT NULL DEFAULT '[]'`,
	`ALTER TABLE lb_configs ADD COLUMN stack_name TEXT`,

	// Witness/tiebreaker host role. Workers run VMs; witnesses
	// participate in quorum only.
	`ALTER TABLE hosts ADD COLUMN role TEXT NOT NULL DEFAULT 'worker'`,

	// auth: realm + display fields on users; scope JSON on tokens.
	`ALTER TABLE users ADD COLUMN realm TEXT NOT NULL DEFAULT 'local'`,
	`ALTER TABLE users ADD COLUMN display_name TEXT`,
	`ALTER TABLE users ADD COLUMN email TEXT`,
	`ALTER TABLE tokens ADD COLUMN scope_paths TEXT`,

	// distributed firewall: per-NIC security-group binding.
	// JSON-encoded []string of SG names (must match security_groups.name);
	// empty / NULL = no SGs bound on this NIC, only cluster + host tier
	// rules apply.
	`ALTER TABLE vm_interfaces ADD COLUMN security_groups TEXT`,

	// federation: hosts get a region label. A region is a
	// failure domain (DC, rack, AZ) used by ListRegions / RegionStatus
	// and as the source/target of CrossRegionMigrate. Default "default"
	// keeps single-region clusters working unchanged.
	`ALTER TABLE hosts ADD COLUMN region TEXT NOT NULL DEFAULT 'default'`,

	// tamper-evidence: audit_log rows carry a chained hash
	// so post-hoc tampering can be detected by replaying SHA-256
	// from row 1. Both columns nullable; rows from pre-3.4 daemons
	// have NULL values and the verifier treats those as chain-
	// reset points (the alternative — refusing to start until every
	// existing row is rehashed — would be operationally hostile).
	`ALTER TABLE audit_log ADD COLUMN prev_hash TEXT`,
	`ALTER TABLE audit_log ADD COLUMN content_hash TEXT`,

	// tenancy: VMs get a project label. Defaults to
	// "_default" so existing single-tenant clusters keep working.
	`ALTER TABLE vms ADD COLUMN project TEXT NOT NULL DEFAULT '_default'`,

	// pool-level schedules: a single backup_schedules row
	// with non-empty pool_name fans out to every VM whose disks
	// live on that pool. Per-VM rows (vm_name set, pool_name NULL)
	// keep working unchanged.
	`ALTER TABLE backup_schedules ADD COLUMN pool_name TEXT`,

	// pool CRUD: a JSON-encoded map of driver-specific
	// options (e.g. NFS mount flags, Ceph keyring path) so operators
	// can register a pool at runtime without editing config.yaml.
	// Old rows have NULL = no options, indistinguishable from "{}".
	`ALTER TABLE storage_pools ADD COLUMN options TEXT`,

	// backup-schedule scopes: a schedule targets a VM (default), a
	// storage pool, all VMs (cluster), or a tenancy project. scope
	// discriminates; project_name carries the project-scope target.
	// Existing rows default to scope='vm' (or pool, via pool_name).
	`ALTER TABLE backup_schedules ADD COLUMN scope TEXT NOT NULL DEFAULT 'vm'`,
	`ALTER TABLE backup_schedules ADD COLUMN project_name TEXT`,

	// TOTP replay protection: the highest TOTP time-step a factor has
	// successfully consumed. VerifyTOTP rejects a code whose step is <= this,
	// closing the window where a captured 6-digit code is replayed within its
	// ±30s validity. Defaults to 0 (no code consumed yet); old rows accept any
	// first code, then ratchet forward.
	`ALTER TABLE user_2fa ADD COLUMN last_step INTEGER NOT NULL DEFAULT 0`,

	// VM templates + clones (v16). is_template marks a VM that can't start
	// and whose disks are immutable golden images (clone source). backing_disk
	// records a linked clone's source disk path so we can (a) refuse to delete
	// a template/snapshot still backing live linked clones, and (b) host-pin a
	// linked clone to where its local-storage backing file actually lives.
	// Both additive; old binaries ignore them — gap-1 from v15, auto-prestaged.
	`ALTER TABLE vms ADD COLUMN is_template INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE vm_disks ADD COLUMN backing_disk TEXT`,

	// Scheduled replication (v17). The existing scheduler drives both backups
	// and replication; type discriminates. target_pool/target_host say where
	// the replica lands; keep_replicas caps point-in-time copies. Additive;
	// existing rows default to type='backup'.
	`ALTER TABLE backup_schedules ADD COLUMN type TEXT NOT NULL DEFAULT 'backup'`,
	`ALTER TABLE backup_schedules ADD COLUMN target_pool TEXT`,
	`ALTER TABLE backup_schedules ADD COLUMN target_host TEXT`,
	`ALTER TABLE backup_schedules ADD COLUMN keep_replicas INTEGER NOT NULL DEFAULT 0`,

	// Replication follow-ups B + C (v18). incremental drives the dirty-extent
	// transfer (raw replicas); auto_promote lets failover bring up the freshest
	// replica on host loss; last_checkpoint anchors the per-schedule dirty-bitmap
	// chain for incremental. Additive; existing rows default to off / ''.
	`ALTER TABLE backup_schedules ADD COLUMN incremental INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE backup_schedules ADD COLUMN auto_promote INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE backup_schedules ADD COLUMN last_checkpoint TEXT`,

	// Live/RAM snapshots (v19, #3). type discriminates disk-only ('disk',
	// default) from a memory snapshot ('memory') that also captured guest RAM;
	// vmstate_path points at the saved RAM image under {dataDir}/vmstate and
	// vmstate_size_bytes its size. Additive; old rows default type='disk'.
	// (resource_mappings is a new table added to schemaDDL — no ALTER needed.)
	`ALTER TABLE snapshots ADD COLUMN type TEXT NOT NULL DEFAULT 'disk'`,
	`ALTER TABLE snapshots ADD COLUMN vmstate_path TEXT`,
	`ALTER TABLE snapshots ADD COLUMN vmstate_size_bytes INTEGER NOT NULL DEFAULT 0`,

	// Container restart policy (v24). restart_policy holds the JSON RestartPolicy
	// (condition/delay/max_attempts/window); state_detail carries the stop cause /
	// intent ('operator-stop' etc.), the container analogue of vms.state_detail.
	// Additive; existing rows default to NULL (treated as 'none' / no recorded
	// intent). container_restarts is a new table in schemaDDL — no ALTER needed.
	`ALTER TABLE containers ADD COLUMN restart_policy TEXT`,
	`ALTER TABLE containers ADD COLUMN state_detail TEXT`,

	// containers.project — tenancy bucket (v25), mirrors vms.project.
	`ALTER TABLE containers ADD COLUMN project TEXT NOT NULL DEFAULT '_default'`,

	// Container templates/clones + host-loss relocation (v28). is_template
	// mirrors vms.is_template (a clone-source that can't start); on_host_failure
	// is the relocation policy the failover coordinator reads when a host is
	// fenced. Both additive; old rows default is_template=0, on_host_failure=NULL.
	`ALTER TABLE containers ADD COLUMN is_template INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE containers ADD COLUMN on_host_failure TEXT`,

	// v29: delete-safety — tombstone-arbitration timestamp on tokens + tombstone
	// column on lb_backends (see History v29).
	`ALTER TABLE tokens ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE lb_backends ADD COLUMN deleted_at TEXT`,

	// v30: persist each host's running-binary schema for the self-upgrade watcher.
	`ALTER TABLE hosts ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 0`,

	// v31: per-incarnation LB generation token (render only current-incarnation backends).
	`ALTER TABLE lb_configs ADD COLUMN generation TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE lb_backends ADD COLUMN generation TEXT NOT NULL DEFAULT ''`,

	// v32: make 2FA/recovery peer-repairable (sensitive anti-entropy lane).
	`ALTER TABLE user_2fa ADD COLUMN deleted_at TEXT`,
	`ALTER TABLE user_2fa ADD COLUMN epoch TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE recovery_codes ADD COLUMN set_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE recovery_codes ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE recovery_codes ADD COLUMN deleted_at TEXT`,

	// v34: persist a container's create-time spec (template/distro/release/arch/
	// networks) so host-loss relocation + restore can faithfully rebuild it,
	// including litevirt-managed networking the other columns don't capture; and
	// an attempt token a restore-relocation stamps on the target row so the
	// coordinator can prove a (target,name) row is ITS restore (names aren't
	// cluster-unique) before tombstoning the source.
	`ALTER TABLE containers ADD COLUMN create_spec TEXT`,
	`ALTER TABLE containers ADD COLUMN relocate_token TEXT`,
	// v36: generalize IPAM ownership beyond VMs (see History v36).
	`ALTER TABLE ip_allocations ADD COLUMN owner_kind TEXT NOT NULL DEFAULT 'vm'`,
	`ALTER TABLE ip_allocations ADD COLUMN owner_host TEXT NOT NULL DEFAULT ''`,
	// v37: project-scoped isolation (see History v37). '' = global/shared.
	`ALTER TABLE networks ADD COLUMN project TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE storage_pools ADD COLUMN project TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE volumes ADD COLUMN project TEXT NOT NULL DEFAULT ''`,
	// v38: split-brain hardening (see History v38). Links a pending start to its
	// runtime_action_proofs row; '' = no in-flight proof-gated action.
	`ALTER TABLE vms ADD COLUMN pending_action_id TEXT NOT NULL DEFAULT ''`,
}

// ───────────────────────── per-migration ledger ─────────────────────────
//
// The ledger gives every schema change a stable ID so applied_migrations can
// record, by verified reality, exactly what each DB has. It must cover EVERY
// schema version 1..CurrentSchemaVersion (enforced by a test) so the derived
// version advances even for table-only versions that add no ALTER.

type migKind int

const (
	kindAddColumn   migKind = iota // ALTER TABLE … ADD COLUMN; presence = column exists
	kindCreateTable                // new table; presence = table exists (created by schemaDDL)
)

// migration is one ledgered schema unit.
type migration struct {
	ID      string // stable, frozen once shipped; never reorder/edit
	Version int    // schema version this unit belongs to (feeds derivedSchemaVersion)
	Kind    migKind
	Target  string // "table.col" (addColumn) or "table" (createTable) — for the presence check
	SQL     string // heal statement (the ALTER for addColumn; "" for createTable — schemaDDL creates it)
}

// present runs the unit's presence predicate against the live DB.
func (m migration) present(ctx context.Context, c *Client) (bool, error) {
	switch m.Kind {
	case kindAddColumn:
		table, col := parseAddColumn(m.SQL)
		if table == "" || col == "" {
			return false, fmt.Errorf("addColumn migration %q: unparseable SQL %q", m.ID, m.SQL)
		}
		return columnExists(ctx, c.db, table, col)
	case kindCreateTable:
		return tableExists(ctx, c, m.Target)
	default:
		return false, fmt.Errorf("migration %q: unknown kind %d", m.ID, m.Kind)
	}
}

// alterVersions maps schemaMigrations[i] → its schema version (authored from the
// History block). MUST stay the same length as schemaMigrations (test-enforced).
var alterVersions = []int{
	1, 1, 1, 1, // host_pci_devices pcie_*/link_*
	1,    // vm_disks.target_dev
	1,    // image_hosts.progress_pct
	1,    // hosts.version
	1, 1, // lb_configs.ports/stack_name
	1,          // hosts.role
	2, 2, 2, 2, // users.realm/display_name/email, tokens.scope_paths
	4,    // vm_interfaces.security_groups
	6,    // hosts.region
	8, 8, // audit_log.prev_hash/content_hash
	9,      // vms.project
	10,     // backup_schedules.pool_name
	11,     // storage_pools.options
	12, 12, // backup_schedules.scope/project_name
	15,     // user_2fa.last_step
	16, 16, // vms.is_template, vm_disks.backing_disk
	17, 17, 17, 17, // backup_schedules type/target_pool/target_host/keep_replicas
	18, 18, 18, // backup_schedules incremental/auto_promote/last_checkpoint
	19, 19, 19, // snapshots type/vmstate_path/vmstate_size_bytes
	24, 24, // containers.restart_policy/state_detail
	25,     // containers.project
	28, 28, // containers.is_template/on_host_failure
	29, 29, // tokens.updated_at, lb_backends.deleted_at
	30,     // hosts.schema_version
	31, 31, // lb_configs.generation, lb_backends.generation
	32, 32, 32, 32, 32, // user_2fa.deleted_at/epoch; recovery_codes.set_id/updated_at/deleted_at
	34, 34, // containers.create_spec, containers.relocate_token
	36, 36, // ip_allocations.owner_kind, ip_allocations.owner_host
	37, 37, 37, // networks.project, storage_pools.project, volumes.project
	38, // vms.pending_action_id
}

// createTableUnits cover the table-only versions (no ALTER) so every schema
// version has ≥1 ledger entry. The representative table is one introduced at
// that version; schemaDDL actually creates it, so these are presence/version
// markers (their heal path is unreachable).
var createTableUnits = []struct {
	version int
	table   string
}{
	{3, "security_groups"}, {5, "containers"}, {7, "backup_schedules"},
	{13, "vm_events"}, {14, "vm_backups"}, {20, "notification_targets"},
	{21, "ip_sets"}, {22, "replication_checkpoints"}, {23, "registry_credentials"},
	{26, "container_backups"}, {27, "container_snapshots"},
	{32, "recovery_code_sets"}, {32, "user_2fa_sets"},
	{33, "host_runtime_usage"},
	{35, "container_interfaces"},
	{38, "runtime_action_proofs"},
	{39, "idempotency_keys"},
}

// schemaMigrationLedger is built once at init from schemaMigrations (addColumn
// units, 1:1) + createTableUnits. Built rather than hand-written so the SQL
// stays DRY with schemaMigrations and can't drift.
var schemaMigrationLedger []migration

func init() {
	if len(alterVersions) != len(schemaMigrations) {
		panic(fmt.Sprintf("alterVersions (%d) must match schemaMigrations (%d) — update the version map",
			len(alterVersions), len(schemaMigrations)))
	}
	for i, sql := range schemaMigrations {
		table, col := parseAddColumn(sql)
		if table == "" || col == "" {
			panic(fmt.Sprintf("schemaMigrations[%d] is not a parseable ADD COLUMN: %q", i, sql))
		}
		schemaMigrationLedger = append(schemaMigrationLedger, migration{
			ID:      fmt.Sprintf("a%03d_%s_%s", i, table, col),
			Version: alterVersions[i],
			Kind:    kindAddColumn,
			Target:  table + "." + col,
			SQL:     sql,
		})
	}
	for _, ct := range createTableUnits {
		schemaMigrationLedger = append(schemaMigrationLedger, migration{
			ID:      "t_" + ct.table,
			Version: ct.version,
			Kind:    kindCreateTable,
			Target:  ct.table,
		})
	}
}
