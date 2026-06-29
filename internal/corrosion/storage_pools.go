package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// StoragePoolRecord represents a storage pool on a host.
type StoragePoolRecord struct {
	HostName string
	Name     string
	Driver   string
	Source   string
	Target   string
	Options  map[string]string
	// Project is the owning tenant. EMPTY means GLOBAL/shared — usable by every
	// project; a non-empty value means owned + isolated (only that project's
	// workloads may place disks on it).
	Project    string
	TotalBytes int64
	UsedBytes  int64
	State      string
}

// UpsertStoragePool inserts or updates a storage pool record. Options are
// serialised as JSON; nil/empty maps round-trip as a JSON "{}" (sqlite
// treats NULL and "{}" the same after scanStoragePool decodes them).
func UpsertStoragePool(ctx context.Context, c *Client, p StoragePoolRecord) error {
	now := c.NowTS()
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
			(host_name, name, driver, source, target, options, project, total_bytes, used_bytes, state, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		p.HostName, p.Name, p.Driver, p.Source, p.Target, optsJSON, p.Project,
		p.TotalBytes, p.UsedBytes, p.State, now,
	)
}

// ListAllStoragePools returns all active storage pools across the cluster.
func ListAllStoragePools(ctx context.Context, c *Client) ([]StoragePoolRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, driver, source, target, options, COALESCE(project, '') AS project, total_bytes, used_bytes, state
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
		`SELECT host_name, name, driver, source, target, options, COALESCE(project, '') AS project, total_bytes, used_bytes, state
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
		`SELECT host_name, name, driver, source, target, options, COALESCE(project, '') AS project, total_bytes, used_bytes, state
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

// CountDisksUsingPool counts live VM disks placed on (host, poolName). Pools are
// HOST-scoped, so the guard must scope by host too — a cluster-wide
// `storage_volume = ?` count would be both too broad (a same-named pool's disks on
// another host) and wrong. The pool delete refuses (without --force) when this is
// non-zero.
func CountDisksUsingPool(ctx context.Context, c *Client, host, poolName string) (int, error) {
	rows, err := c.Query(ctx,
		`SELECT COUNT(*) AS n FROM vm_disks
		 WHERE storage_volume = ? AND host_name = ? AND deleted_at IS NULL`,
		poolName, host)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("n"), nil
}

// CountPoolsSharingResource counts OTHER live pool rows on rec's host that would
// share the SAME host-level resource rec's teardown releases — the refcount that
// stops us tearing down a mount/session another pool still needs. The shared
// resource is DRIVER-SPECIFIC, not just "same source":
//
//   - nfs: the litevirt-DERIVED mountpoint, keyed by source. Only OTHER
//     litevirt-owned NFS pools (target='') with the same source mount it at the
//     same path; an operator-managed (targetOverride) pool mounts elsewhere and
//     is excluded — counting it would falsely block a derived-mount unmount.
//   - iscsi: the (target IQN, portal) session. Same source (IQN) AND same portal
//     (empty/absent normalizes to 127.0.0.1, matching the driver default) — two
//     pools on the same IQN via DIFFERENT portals are distinct sessions and must
//     not block each other.
//   - every other driver: no host-level resource to refcount → 0 (teardown is a
//     no-op for them anyway).
func CountPoolsSharingResource(ctx context.Context, c *Client, rec StoragePoolRecord) (int, error) {
	if rec.Source == "" {
		return 0, nil
	}
	switch strings.ToLower(rec.Driver) {
	case "nfs", "netfs":
		rows, err := c.Query(ctx,
			`SELECT COUNT(*) AS n FROM storage_pools
			 WHERE host_name = ? AND name != ? AND driver = ? AND source = ?
			   AND COALESCE(target, '') = '' AND deleted_at IS NULL`,
			rec.HostName, rec.Name, rec.Driver, rec.Source)
		return countN(rows, err)
	case "iscsi":
		portal := rec.Options["portal"]
		if portal == "" {
			portal = "127.0.0.1"
		}
		rows, err := c.Query(ctx,
			`SELECT COUNT(*) AS n FROM storage_pools
			 WHERE host_name = ? AND name != ? AND driver = 'iscsi' AND source = ? AND deleted_at IS NULL
			   AND CASE WHEN COALESCE(json_extract(options, '$.portal'), '') = ''
			            THEN '127.0.0.1' ELSE json_extract(options, '$.portal') END = ?`,
			rec.HostName, rec.Name, rec.Source, portal)
		return countN(rows, err)
	default:
		return 0, nil
	}
}

// countN reads a single COUNT(*) AS n result.
func countN(rows []Row, err error) (int, error) {
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("n"), nil
}

// MarkStoragePoolDeleted soft-deletes a pool row by stamping deleted_at.
// The corresponding driver teardown (unmount NFS, log out of iSCSI) is
// the caller's responsibility — we don't tear down here because the
// caller may want to keep the underlying mount around for a manual
// recovery. Schedule a real driver cleanup in the gRPC handler instead.
func MarkStoragePoolDeleted(ctx context.Context, c *Client, hostName, name string) error {
	now := c.NowTS()
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
		Project:    r.String("project"),
		TotalBytes: r.Int64("total_bytes"),
		UsedBytes:  r.Int64("used_bytes"),
		State:      r.String("state"),
	}
	if blob := r.String("options"); blob != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &rec.Options)
	}
	return rec
}
