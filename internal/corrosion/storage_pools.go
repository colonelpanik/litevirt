package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// StoragePoolRecord represents a storage pool on a host.
type StoragePoolRecord struct {
	HostName   string
	Name       string
	Driver     string
	Source     string
	Target     string
	Options    map[string]string
	TotalBytes int64
	UsedBytes  int64
	State      string
}

// UpsertStoragePool inserts or updates a storage pool record. Options are
// serialised as JSON; nil/empty maps round-trip as a JSON "{}" (sqlite
// treats NULL and "{}" the same after scanStoragePool decodes them).
func UpsertStoragePool(ctx context.Context, c *Client, p StoragePoolRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	optsJSON := "{}"
	if len(p.Options) > 0 {
		b, err := json.Marshal(p.Options)
		if err != nil {
			return fmt.Errorf("marshal options: %w", err)
		}
		optsJSON = string(b)
	}
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO storage_pools
			(host_name, name, driver, source, target, options, total_bytes, used_bytes, state, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		p.HostName, p.Name, p.Driver, p.Source, p.Target, optsJSON,
		p.TotalBytes, p.UsedBytes, p.State, now,
	)
}

// ListAllStoragePools returns all active storage pools across the cluster.
func ListAllStoragePools(ctx context.Context, c *Client) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, driver, source, target, options, total_bytes, used_bytes, state
		 FROM storage_pools WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	pools := make([]StoragePoolRecord, len(rows))
	for i, r := range rows {
		pools[i] = scanStoragePool(r)
	}
	return pools, nil
}

// ListStoragePoolsForHost returns all active storage pools for a specific host.
func ListStoragePoolsForHost(ctx context.Context, c *Client, hostName string) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, driver, source, target, options, total_bytes, used_bytes, state
		 FROM storage_pools WHERE host_name = ? AND deleted_at IS NULL`, hostName)
	if err != nil {
		return nil, err
	}
	pools := make([]StoragePoolRecord, len(rows))
	for i, r := range rows {
		pools[i] = scanStoragePool(r)
	}
	return pools, nil
}

// GetStoragePool fetches a single pool by (host, name). Returns ok=false
// when the row is absent or soft-deleted so callers don't need to
// distinguish "missing" from "error" — a NotFound RPC code is enough.
func GetStoragePool(ctx context.Context, c *Client, hostName, name string) (StoragePoolRecord, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, driver, source, target, options, total_bytes, used_bytes, state
		 FROM storage_pools WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		hostName, name)
	if err != nil {
		return StoragePoolRecord{}, false, err
	}
	if len(rows) == 0 {
		return StoragePoolRecord{}, false, nil
	}
	return scanStoragePool(rows[0]), true, nil
}

// HostsWithPool returns the names of ACTIVE hosts (other than excludeHost) that
// have a non-deleted pool of the given name — used to pick a healthy peer for
// cross-host replication when no target host was set explicitly.
func HostsWithPool(ctx context.Context, c *Client, poolName, excludeHost string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT sp.host_name
		 FROM storage_pools sp
		 JOIN hosts h ON h.name = sp.host_name
		 WHERE sp.name = ? AND sp.deleted_at IS NULL
		   AND h.state = 'active' AND h.name != ?
		 ORDER BY sp.host_name`, poolName, excludeHost)
	if err != nil {
		return nil, fmt.Errorf("hosts_with_pool: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("host_name"))
	}
	return out, nil
}

// MarkStoragePoolDeleted soft-deletes a pool row by stamping deleted_at.
// The corresponding driver teardown (unmount NFS, log out of iSCSI) is
// the caller's responsibility — we don't tear down here because the
// caller may want to keep the underlying mount around for a manual
// recovery. Schedule a real driver cleanup in the gRPC handler instead.
func MarkStoragePoolDeleted(ctx context.Context, c *Client, hostName, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE storage_pools SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		now, now, hostName, name)
}

func scanStoragePool(r Row) StoragePoolRecord {
	rec := StoragePoolRecord{
		HostName:   r.String("host_name"),
		Name:       r.String("name"),
		Driver:     r.String("driver"),
		Source:     r.String("source"),
		Target:     r.String("target"),
		TotalBytes: r.Int64("total_bytes"),
		UsedBytes:  r.Int64("used_bytes"),
		State:      r.String("state"),
	}
	if blob := r.String("options"); blob != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &rec.Options)
	}
	return rec
}
