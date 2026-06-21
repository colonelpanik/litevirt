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
		   updated_at = excluded.updated_at`,
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

// SoftDeleteLBConfig marks an LB config as deleted without removing the row.
// This prevents refreshLBForStack from re-applying the config mid-teardown.
func SoftDeleteLBConfig(ctx context.Context, c *Client, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE lb_configs SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		now, now, name)
}

// DeleteLBConfig removes an LB config row permanently.
func DeleteLBConfig(ctx context.Context, c *Client, name string) error {
	return c.Execute(ctx,
		`DELETE FROM lb_configs WHERE name = ?`, name)
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
		   updated_at = excluded.updated_at`,
		r.LBName, r.Name, r.Address, isVM, r.VMName, enabled, now,
	)
}

// DeleteLBBackend removes a single backend from an LB.
func DeleteLBBackend(ctx context.Context, c *Client, lbName, backendName string) error {
	return c.Execute(ctx,
		`DELETE FROM lb_backends WHERE lb_name = ? AND name = ?`,
		lbName, backendName)
}

// DeleteLBBackends removes all backends for an LB.
func DeleteLBBackends(ctx context.Context, c *Client, lbName string) error {
	return c.Execute(ctx,
		`DELETE FROM lb_backends WHERE lb_name = ?`, lbName)
}

// ListLBBackends returns all backends for an LB.
func ListLBBackends(ctx context.Context, c *Client, lbName string) ([]LBBackendRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT lb_name, name, address, is_vm, vm_name, enabled FROM lb_backends WHERE lb_name = ?`,
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
