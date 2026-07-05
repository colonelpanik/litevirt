package corrosion

import (
	"context"
	"fmt"
)

// LBConfigRecord mirrors the lb_configs table.
type LBConfigRecord struct {
	Name      string
	StackName string // empty for standalone LBs
	VIP       string
	Algorithm string
	Hosts     string // JSON array
	Ports     string // JSON array of port mappings
	Enabled   bool
	// Generation is the per-incarnation token (schema v31). Minted on
	// create/recreate, preserved on edit. Readers render only backends whose
	// generation matches their config's, so a stale backend a partitioned peer
	// held (and this node never saw) can merge under anti-entropy but never
	// renders. '' = a legacy/unstamped row (matches other '' rows).
	Generation string
}

// lbConfigUpsertStmt builds the lb_configs upsert sharing an explicit timestamp.
// On conflict, generation is COALESCE(NULLIF(excluded.generation,”), existing):
// a caller that forgets to pass a token (passes ”) can NEVER blank a live
// generation and orphan its backends — only a deliberate non-empty token
// re-stamps the incarnation.
func lbConfigUpsertStmt(r LBConfigRecord, now string) Statement {
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	if r.Ports == "" {
		r.Ports = "[]"
	}
	return Statement{
		SQL: `INSERT INTO lb_configs (name, stack_name, vip, algorithm, hosts, ports, enabled, updated_at, generation)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(name) DO UPDATE SET
			   stack_name = excluded.stack_name,
			   vip = excluded.vip,
			   algorithm = excluded.algorithm,
			   hosts = excluded.hosts,
			   ports = excluded.ports,
			   enabled = excluded.enabled,
			   updated_at = excluded.updated_at,
			   generation = COALESCE(NULLIF(excluded.generation, ''), lb_configs.generation),
			   deleted_at = NULL`, // (re-)creating clears any prior tombstone
		Params: []interface{}{r.Name, r.StackName, r.VIP, r.Algorithm, r.Hosts, r.Ports, enabled, now, r.Generation},
	}
}

// UpsertLBConfig inserts or replaces an LB config record.
func UpsertLBConfig(ctx context.Context, c *Client, r LBConfigRecord) error {
	return c.ExecuteBatch(ctx, []Statement{lbConfigUpsertStmt(r, c.NowTS())})
}

// ListLBConfigs returns all active LB config records.
func ListLBConfigs(ctx context.Context, c *Client) ([]LBConfigRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, vip, algorithm, hosts, ports, enabled, generation
		 FROM lb_configs WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	records := make([]LBConfigRecord, 0, len(rows))
	for _, r := range rows {
		records = append(records, LBConfigRecord{
			Name:       r.String("name"),
			StackName:  r.String("stack_name"),
			VIP:        r.String("vip"),
			Algorithm:  r.String("algorithm"),
			Hosts:      r.String("hosts"),
			Ports:      r.String("ports"),
			Enabled:    r.Int("enabled") == 1,
			Generation: r.String("generation"),
		})
	}
	return records, nil
}

// ClaimLBHolderIfUnowned records hostsJSON as an LB's holder set ONLY while it
// currently has none (hosts '' or '[]'), returning whether THIS call wrote it.
// It's the migration write for explicit LBs persisted before durable holders; the
// CALLER decides the correct holder (via the cluster-wide participant probe) — this
// guard only avoids clobbering a holder that another node already established.
//
// NOTE: the guard is atomic within local SQLite, not cluster-wide. lb_configs is a
// CRDT/LWW table, so two nodes writing during a partition can both succeed locally
// and converge by last-writer-wins. That's why callers must resolve a single
// proven participant BEFORE calling this, rather than relying on the write to
// arbitrate a contested holder.
func ClaimLBHolderIfUnowned(ctx context.Context, c *Client, name, hostsJSON string) (bool, error) {
	n, err := c.ExecuteRows(ctx,
		`UPDATE lb_configs SET hosts = ?, updated_at = ?
		 WHERE name = ? AND deleted_at IS NULL AND (hosts = '' OR hosts = '[]')`,
		hostsJSON, c.NowTS(), name)
	return n > 0, err
}

// SoftDeleteLBConfig tombstones an LB config (UPDATE-only — a no-op when the row
// doesn't exist locally, so cleanup paths can't manufacture a tombstone for an LB
// that never existed). The tombstone (newer updated_at) is what propagates the
// delete under anti-entropy; a hard DELETE could be resurrected by a peer that
// missed it. enabled=0 belt-and-suspenders so any `enabled = 1` reader skips it.
// This is the only delete primitive for lb_configs — there is no hard delete.
func SoftDeleteLBConfig(ctx context.Context, c *Client, name string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE lb_configs SET deleted_at = ?, updated_at = ?, enabled = 0 WHERE name = ?`,
		now, now, name)
}

// ── LB Backends ──────────────────────────────────────────────────────────────

// LBBackendRecord mirrors the lb_backends table.
type LBBackendRecord struct {
	LBName     string
	Name       string
	Address    string
	IsVM       bool
	VMName     string
	Enabled    bool
	Generation string // matches the owning lb_config's generation (schema v31)
}

// lbBackendUpsertStmt builds the lb_backends upsert sharing an explicit
// timestamp. generation is COALESCE-defended like lbConfigUpsertStmt: passing ”
// preserves an existing token; only a deliberate non-empty token re-stamps.
func lbBackendUpsertStmt(r LBBackendRecord, now string) Statement {
	isVM := 0
	if r.IsVM {
		isVM = 1
	}
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	return Statement{
		SQL: `INSERT INTO lb_backends (lb_name, name, address, is_vm, vm_name, enabled, updated_at, generation)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(lb_name, name) DO UPDATE SET
			   address = excluded.address,
			   is_vm = excluded.is_vm,
			   vm_name = excluded.vm_name,
			   enabled = excluded.enabled,
			   updated_at = excluded.updated_at,
			   generation = COALESCE(NULLIF(excluded.generation, ''), lb_backends.generation),
			   deleted_at = NULL`, // (re-)adding clears any prior tombstone
		Params: []interface{}{r.LBName, r.Name, r.Address, isVM, r.VMName, enabled, now, r.Generation},
	}
}

// UpsertLBBackend inserts or replaces an LB backend record.
func UpsertLBBackend(ctx context.Context, c *Client, r LBBackendRecord) error {
	return c.ExecuteBatch(ctx, []Statement{lbBackendUpsertStmt(r, c.NowTS())})
}

// lbBackendTombstoneStmt builds a single-backend soft-delete sharing an explicit
// timestamp. It UPSERTS the tombstone (not a bare UPDATE): if this node never saw
// the backend's create, an UPDATE would hit zero rows and leave no tombstone, so
// a peer that still has it live would reintroduce it under anti-entropy. The
// blank address is only the INSERT-branch placeholder for the NOT NULL column.
func lbBackendTombstoneStmt(lbName, backendName, now string) Statement {
	return Statement{
		SQL: `INSERT INTO lb_backends (lb_name, name, address, enabled, updated_at, deleted_at)
			 VALUES (?, ?, '', 0, ?, ?)
			 ON CONFLICT(lb_name, name) DO UPDATE SET
			   deleted_at = excluded.deleted_at,
			   updated_at = excluded.updated_at,
			   enabled = 0`,
		Params: []interface{}{lbName, backendName, now, now},
	}
}

// TombstoneLBBackend soft-deletes a single backend (see lbBackendTombstoneStmt
// for why this UPSERTS rather than UPDATEs).
func TombstoneLBBackend(ctx context.Context, c *Client, lbName, backendName string) error {
	return c.ExecuteBatch(ctx, []Statement{lbBackendTombstoneStmt(lbName, backendName, c.NowTS())})
}

// SoftDeleteLBBackends tombstones all locally-known backends for an LB (bulk
// UPDATE-only — see TombstoneLBBackend for the single-backend, missed-create case).
func SoftDeleteLBBackends(ctx context.Context, c *Client, lbName string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE lb_backends SET deleted_at = ?, updated_at = ?, enabled = 0 WHERE lb_name = ?`,
		now, now, lbName)
}

// PersistLBFull writes an LB config plus its COMPLETE backend set as ONE
// replicated batch (a single updated_at). It first bulk-tombstones every
// locally-known live backend for the LB, then upserts the config and the given
// backends — all stamped with cfg.Generation. So a recreate (a fresh generation)
// can't leave a stale local row live, and the operation is atomic: a partial
// failure leaves the prior persistent model untouched rather than a half-written
// LB that the DB-render reapply would later act on. Used by the create/recreate
// path (full replace).
func PersistLBFull(ctx context.Context, c *Client, cfg LBConfigRecord, backends []LBBackendRecord) error {
	now := c.NowTS()
	stmts := make([]Statement, 0, 2+len(backends))
	// Clear all locally-known live backends first; a re-added name (also in
	// backends) is un-tombstoned by its upsert below (later stmt wins in-tx).
	stmts = append(stmts, Statement{
		SQL:    `UPDATE lb_backends SET deleted_at = ?, updated_at = ?, enabled = 0 WHERE lb_name = ? AND deleted_at IS NULL`,
		Params: []interface{}{now, now, cfg.Name},
	})
	stmts = append(stmts, lbConfigUpsertStmt(cfg, now))
	for _, b := range backends {
		b.LBName = cfg.Name
		b.Generation = cfg.Generation
		stmts = append(stmts, lbBackendUpsertStmt(b, now))
	}
	return c.ExecuteBatch(ctx, stmts)
}

// PersistLBIncremental writes a config edit plus explicit backend upserts and
// tombstones as ONE replicated batch (a single updated_at). The config and every
// upserted backend are stamped with cfg.Generation (the caller passes the
// PRESERVED existing generation so already-stored backends keep matching). Used
// by the update path (add/remove specific backends, never a full replace).
func PersistLBIncremental(ctx context.Context, c *Client, cfg LBConfigRecord, upserts []LBBackendRecord, tombstones []string) error {
	now := c.NowTS()
	stmts := make([]Statement, 0, 1+len(upserts)+len(tombstones))
	for _, name := range tombstones {
		stmts = append(stmts, lbBackendTombstoneStmt(cfg.Name, name, now))
	}
	stmts = append(stmts, lbConfigUpsertStmt(cfg, now))
	for _, b := range upserts {
		b.LBName = cfg.Name
		b.Generation = cfg.Generation
		stmts = append(stmts, lbBackendUpsertStmt(b, now))
	}
	return c.ExecuteBatch(ctx, stmts)
}

// ListLBBackends returns the live backends for an LB's CURRENT incarnation. A
// single join gates on the config: a backend renders only when a live lb_config
// exists and the two generations match. So a stale-generation backend (an unseen
// peer row, or a losing concurrent recreate) merges into the DB but never renders,
// and a missing/tombstoned config yields no rows (safe). Pre-migration rows where
// both generations are ” still match (” = ”).
func ListLBBackends(ctx context.Context, c *Client, lbName string) ([]LBBackendRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT b.lb_name, b.name, b.address, b.is_vm, b.vm_name, b.enabled, b.generation
		 FROM lb_backends b
		 JOIN lb_configs cfg ON cfg.name = b.lb_name AND cfg.deleted_at IS NULL
		 WHERE b.lb_name = ? AND b.deleted_at IS NULL AND b.generation = cfg.generation`,
		lbName)
	if err != nil {
		return nil, fmt.Errorf("query lb_backends: %w", err)
	}
	var result []LBBackendRecord
	for _, r := range rows {
		result = append(result, LBBackendRecord{
			LBName:     r.String("lb_name"),
			Name:       r.String("name"),
			Address:    r.String("address"),
			IsVM:       r.Int("is_vm") == 1,
			VMName:     r.String("vm_name"),
			Enabled:    r.Int("enabled") == 1,
			Generation: r.String("generation"),
		})
	}
	return result, nil
}
