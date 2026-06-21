package corrosion

import (
	"context"
	"sort"
	"time"
)

// MappingDevice is one host's concrete device under a named resource mapping.
type MappingDevice struct {
	HostName string
	Address  string
	Vendor   string
	Device   string
}

// ResourceMappingRecord is a cluster-wide alias (#14) for an equivalent
// passthrough device available on one or more hosts.
type ResourceMappingRecord struct {
	Name        string
	Description string
	Devices     []MappingDevice
}

// A mapping with a description but no devices is represented by a "header" row
// with empty host_name + address. Device rows have both set. This keeps the
// (name, host_name, address) primary key intact for an empty mapping.

// CreateResourceMapping inserts (or refreshes) the header row carrying the
// mapping's description. Idempotent.
func CreateResourceMapping(ctx context.Context, c *Client, name, description string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO resource_mappings (name, host_name, address, description, created_at, updated_at, deleted_at)
		 VALUES (?, '', '', ?, ?, ?, NULL)`,
		name, description, now, now,
	)
}

// AddMappingDevice registers one host's device under a mapping. Re-adding the
// same (name, host, address) updates the vendor/device fields.
func AddMappingDevice(ctx context.Context, c *Client, name, host, address, vendor, device string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO resource_mappings (name, host_name, address, vendor, device, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		name, host, address, vendor, device, now, now,
	)
}

// RemoveMappingDevice tombstones one device row from a mapping.
func RemoveMappingDevice(ctx context.Context, c *Client, name, host, address string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE resource_mappings SET deleted_at = ?, updated_at = ? WHERE name = ? AND host_name = ? AND address = ?`,
		now, now, name, host, address,
	)
}

// DeleteResourceMapping tombstones every row (header + devices) for a mapping.
func DeleteResourceMapping(ctx context.Context, c *Client, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE resource_mappings SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		now, now, name,
	)
}

// ListResourceMappings returns every mapping grouped by name, sorted by name.
func ListResourceMappings(ctx context.Context, c *Client) ([]ResourceMappingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, host_name, address, vendor, device, description
		 FROM resource_mappings WHERE deleted_at IS NULL ORDER BY name, host_name, address`)
	if err != nil {
		return nil, err
	}
	byName := map[string]*ResourceMappingRecord{}
	var order []string
	for _, r := range rows {
		name := r.String("name")
		m, ok := byName[name]
		if !ok {
			m = &ResourceMappingRecord{Name: name}
			byName[name] = m
			order = append(order, name)
		}
		if d := r.String("description"); d != "" {
			m.Description = d
		}
		host, addr := r.String("host_name"), r.String("address")
		if host != "" || addr != "" { // a real device row, not the header
			m.Devices = append(m.Devices, MappingDevice{
				HostName: host, Address: addr,
				Vendor: r.String("vendor"), Device: r.String("device"),
			})
		}
	}
	sort.Strings(order)
	out := make([]ResourceMappingRecord, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return out, nil
}

// GetResourceMapping returns a single mapping by name, or (nil, nil) if absent.
func GetResourceMapping(ctx context.Context, c *Client, name string) (*ResourceMappingRecord, error) {
	all, err := ListResourceMappings(ctx, c)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, nil
}

// ResolveMappingAddress returns the PCI address registered for a mapping on a
// specific host, or "" if the host has no device under that mapping.
func ResolveMappingAddress(ctx context.Context, c *Client, name, host string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT address FROM resource_mappings
		 WHERE name = ? AND host_name = ? AND address != '' AND deleted_at IS NULL
		 ORDER BY address LIMIT 1`,
		name, host)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("address"), nil
}

// HostsForMapping lists the hosts that have at least one device under a mapping
// (used for placement / migration eligibility).
func HostsForMapping(ctx context.Context, c *Client, name string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT host_name FROM resource_mappings
		 WHERE name = ? AND host_name != '' AND address != '' AND deleted_at IS NULL
		 ORDER BY host_name`,
		name)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(rows))
	for _, r := range rows {
		hosts = append(hosts, r.String("host_name"))
	}
	return hosts, nil
}
