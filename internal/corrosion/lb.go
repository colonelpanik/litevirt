package corrosion

import (
	"context"
	"fmt"
	"time"
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
}

// UpsertLBConfig inserts or replaces an LB config record.
func UpsertLBConfig(ctx context.Context, c *Client, r LBConfigRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	if r.Ports == "" {
		r.Ports = "[]"
	}
	return c.Execute(ctx,
		`INSERT INTO lb_configs (name, stack_name, vip, algorithm, hosts, ports, enabled, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   stack_name = excluded.stack_name,
		   vip = excluded.vip,
		   algorithm = excluded.algorithm,
		   hosts = excluded.hosts,
		   ports = excluded.ports,
		   enabled = excluded.enabled,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`, // (re-)creating clears any prior tombstone
		r.Name, r.StackName, r.VIP, r.Algorithm, r.Hosts, r.Ports, enabled, now,
	)
}

// ListLBConfigs returns all active LB config records.
func ListLBConfigs(ctx context.Context, c *Client) ([]LBConfigRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, vip, algorithm, hosts, ports, enabled
		 FROM lb_configs WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	records := make([]LBConfigRecord, 0, len(rows))
	for _, r := range rows {
		records = append(records, LBConfigRecord{
			Name:      r.String("name"),
			StackName: r.String("stack_name"),
			VIP:       r.String("vip"),
			Algorithm: r.String("algorithm"),
			Hosts:     r.String("hosts"),
			Ports:     r.String("ports"),
			Enabled:   r.Int("enabled") == 1,
		})
	}
	return records, nil
}

// SoftDeleteLBConfig tombstones an LB config (UPDATE-only — a no-op when the row
// doesn't exist locally, so cleanup paths can't manufacture a tombstone for an LB
// that never existed). The tombstone (newer updated_at) is what propagates the
// delete under anti-entropy; a hard DELETE could be resurrected by a peer that
// missed it. enabled=0 belt-and-suspenders so any `enabled = 1` reader skips it.
// This is the only delete primitive for lb_configs — there is no hard delete.
func SoftDeleteLBConfig(ctx context.Context, c *Client, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE lb_configs SET deleted_at = ?, updated_at = ?, enabled = 0 WHERE name = ?`,
		now, now, name)
}

// ── LB Backends ──────────────────────────────────────────────────────────────

// LBBackendRecord mirrors the lb_backends table.
type LBBackendRecord struct {
	LBName  string
	Name    string
	Address string
	IsVM    bool
	VMName  string
	Enabled bool
}

// UpsertLBBackend inserts or replaces an LB backend record.
func UpsertLBBackend(ctx context.Context, c *Client, r LBBackendRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	isVM := 0
	if r.IsVM {
		isVM = 1
	}
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	return c.Execute(ctx,
		`INSERT INTO lb_backends (lb_name, name, address, is_vm, vm_name, enabled, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(lb_name, name) DO UPDATE SET
		   address = excluded.address,
		   is_vm = excluded.is_vm,
		   vm_name = excluded.vm_name,
		   enabled = excluded.enabled,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`, // (re-)adding clears any prior tombstone
		r.LBName, r.Name, r.Address, isVM, r.VMName, enabled, now,
	)
}

// TombstoneLBBackend soft-deletes a single backend. It UPSERTS the tombstone (not
// a bare UPDATE): if this node never saw the backend's create, an UPDATE would
// hit zero rows and leave no tombstone, so a peer that still has it live would
// reintroduce it under anti-entropy. The blank address is only the INSERT-branch
// placeholder for the NOT NULL column; readers filter deleted_at IS NULL.
func TombstoneLBBackend(ctx context.Context, c *Client, lbName, backendName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT INTO lb_backends (lb_name, name, address, enabled, updated_at, deleted_at)
		 VALUES (?, ?, '', 0, ?, ?)
		 ON CONFLICT(lb_name, name) DO UPDATE SET
		   deleted_at = excluded.deleted_at,
		   updated_at = excluded.updated_at,
		   enabled = 0`,
		lbName, backendName, now, now)
}

// SoftDeleteLBBackends tombstones all locally-known backends for an LB (bulk
// UPDATE-only — see TombstoneLBBackend for the single-backend, missed-create case).
func SoftDeleteLBBackends(ctx context.Context, c *Client, lbName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE lb_backends SET deleted_at = ?, updated_at = ?, enabled = 0 WHERE lb_name = ?`,
		now, now, lbName)
}

// ListLBBackends returns all live backends for an LB.
func ListLBBackends(ctx context.Context, c *Client, lbName string) ([]LBBackendRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT lb_name, name, address, is_vm, vm_name, enabled FROM lb_backends WHERE lb_name = ? AND deleted_at IS NULL`,
		lbName)
	if err != nil {
		return nil, fmt.Errorf("query lb_backends: %w", err)
	}
	var result []LBBackendRecord
	for _, r := range rows {
		result = append(result, LBBackendRecord{
			LBName:  r.String("lb_name"),
			Name:    r.String("name"),
			Address: r.String("address"),
			IsVM:    r.Int("is_vm") == 1,
			VMName:  r.String("vm_name"),
			Enabled: r.Int("enabled") == 1,
		})
	}
	return result, nil
}
