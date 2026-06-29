package corrosion

import (
	"context"
	"log/slog"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
)

// NetworkRecord mirrors the networks table.
type NetworkRecord struct {
	Name      string
	StackName string
	Type      string
	Config    string // JSON blob of NetworkDef
	// Project is the owning tenant. EMPTY means GLOBAL/shared — usable by every
	// project (the admin escape hatch). A non-empty value means owned + isolated:
	// only a workload in the SAME project (or with root scope) may attach.
	Project   string
	CreatedAt string
	UpdatedAt string
}

// UpsertNetwork inserts or updates a network record.
func UpsertNetwork(ctx context.Context, c *Client, r NetworkRecord) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO networks (name, stack_name, type, config, project, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   stack_name = excluded.stack_name,
		   type = excluded.type,
		   config = excluded.config,
		   project = excluded.project,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		r.Name, r.StackName, r.Type, r.Config, r.Project, nowRFC3339(), now,
	)
}

// ListNetworks returns all active network records.
func ListNetworks(ctx context.Context, c *Client) ([]NetworkRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, type, config, COALESCE(project, '') AS project, created_at, updated_at
		 FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}

	records := make([]NetworkRecord, 0, len(rows))
	for _, r := range rows {
		records = append(records, scanNetwork(r))
	}
	return records, nil
}

// GetNetwork returns a single network by name, or nil if not found.
func GetNetwork(ctx context.Context, c *Client, name string) (*NetworkRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, type, config, COALESCE(project, '') AS project, created_at, updated_at
		 FROM networks WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rec := scanNetwork(rows[0])
	return &rec, nil
}

func scanNetwork(r Row) NetworkRecord {
	return NetworkRecord{
		Name:      r.String("name"),
		StackName: r.String("stack_name"),
		Type:      r.String("type"),
		Config:    r.String("config"),
		Project:   r.String("project"),
		CreatedAt: r.String("created_at"),
		UpdatedAt: r.String("updated_at"),
	}
}

// DeleteNetwork soft-deletes a network record.
func DeleteNetwork(ctx context.Context, c *Client, name string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE networks SET deleted_at = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, name,
	)
}

// CountVMsOnNetwork returns the number of VMs with interfaces on a given network.
func CountVMsOnNetwork(ctx context.Context, c *Client, networkName string) (int, error) {
	rows, err := c.Query(ctx,
		`SELECT COUNT(*) as cnt FROM vm_interfaces
		 WHERE network_name = ? AND deleted_at IS NULL`, networkName)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("cnt"), nil
}

// ListNetworksByHost returns networks relevant to a host — those with VTEPs
// on the host or VMs on the host attached to them.
func ListNetworksByHost(ctx context.Context, c *Client, hostName string) ([]NetworkRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT n.name, n.stack_name, n.type, n.config, COALESCE(n.project, '') AS project, n.created_at, n.updated_at
		 FROM networks n
		 WHERE n.deleted_at IS NULL AND (
		   EXISTS (SELECT 1 FROM network_vteps v
		           WHERE v.network_name = n.name AND v.host_name = ? AND v.deleted_at IS NULL)
		   OR EXISTS (SELECT 1 FROM vm_interfaces vi
		              JOIN vms vm ON vm.name = vi.vm_name AND vm.deleted_at IS NULL
		              WHERE vi.network_name = n.name AND vm.host_name = ? AND vi.deleted_at IS NULL)
		 )`, hostName, hostName)
	if err != nil {
		return nil, err
	}

	records := make([]NetworkRecord, 0, len(rows))
	for _, r := range rows {
		records = append(records, scanNetwork(r))
	}
	return records, nil
}

// MigrateLegacyNetworkNames renames unscoped network names to stack-scoped
// names ({stack}_{name}) across all tables. Networks with no stack are logged
// as warnings. This is idempotent — already-scoped names are skipped.
func MigrateLegacyNetworkNames(ctx context.Context, c *Client) error {
	nets, err := ListNetworks(ctx, c)
	if err != nil {
		return err
	}

	now := c.NowTS()

	for _, nr := range nets {
		if nr.StackName == "" {
			// Orphan / standalone network — try to infer ownership.
			stacks, _ := inferNetworkStack(ctx, c, nr.Name)
			if len(stacks) > 0 {
				slog.Warn("orphan network may belong to stack",
					"network", nr.Name, "inferred_stacks", strings.Join(stacks, ","))
			} else {
				cnt, _ := CountVMsOnNetwork(ctx, c, nr.Name)
				if cnt == 0 {
					slog.Warn("orphan network with no VMs found", "network", nr.Name)
				}
			}
			continue
		}

		// Already scoped — skip.
		if strings.HasPrefix(nr.Name, nr.StackName+"_") {
			continue
		}

		scopedName := compose.ScopedNetworkName(nr.StackName, nr.Name)
		slog.Info("migrating legacy network name", "old", nr.Name, "new", scopedName)

		// Rename across all four tables.
		_ = c.Execute(ctx,
			`UPDATE networks SET name = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
			scopedName, now, nr.Name)
		_ = c.Execute(ctx,
			`UPDATE network_vteps SET network_name = ?, updated_at = ? WHERE network_name = ? AND deleted_at IS NULL`,
			scopedName, now, nr.Name)
		_ = c.Execute(ctx,
			`UPDATE ip_allocations SET network = ?, updated_at = ? WHERE network = ? AND deleted_at IS NULL`,
			scopedName, now, nr.Name)
		_ = c.Execute(ctx,
			`UPDATE vm_interfaces SET network_name = ?, updated_at = ? WHERE network_name = ? AND deleted_at IS NULL`,
			scopedName, now, nr.Name)
	}

	// Migrate network names inside VM spec JSON.
	if err := migrateVMSpecNetworkNames(ctx, c); err != nil {
		slog.Warn("failed to migrate VM spec network names", "error", err)
	}

	return nil
}

// inferNetworkStack returns stack names of VMs that use the given network.
func inferNetworkStack(ctx context.Context, c *Client, networkName string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT v.stack_name FROM vm_interfaces vi
		 JOIN vms v ON vi.vm_name = v.name AND v.deleted_at IS NULL
		 WHERE vi.network_name = ? AND vi.deleted_at IS NULL AND v.stack_name != ''`,
		networkName)
	if err != nil {
		return nil, err
	}
	var stacks []string
	for _, r := range rows {
		stacks = append(stacks, r.String("stack_name"))
	}
	return stacks, nil
}

// migrateVMSpecNetworkNames updates network attachment names inside the
// stored VM spec JSON so they use scoped names.
func migrateVMSpecNetworkNames(ctx context.Context, c *Client) error {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, spec FROM vms
		 WHERE stack_name != '' AND deleted_at IS NULL`)
	if err != nil {
		return err
	}

	for _, r := range rows {
		vmName := r.String("name")
		stackName := r.String("stack_name")
		spec := r.String("spec")

		updated, changed := scopeSpecNetworkNames(spec, stackName)
		if !changed {
			continue
		}

		slog.Info("migrating VM spec network names", "vm", vmName)
		_ = c.Execute(ctx,
			`UPDATE vms SET spec = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
			updated, c.NowTS(), vmName)
	}
	return nil
}

// scopeSpecNetworkNames does a targeted update of the "name" fields inside
// the "network" array of a VMSpec JSON string. Returns the updated JSON and
// whether any changes were made.
func scopeSpecNetworkNames(specJSON, stackName string) (string, bool) {
	// Quick check: if no network field, nothing to do.
	if !strings.Contains(specJSON, `"network"`) {
		return specJSON, false
	}

	prefix := stackName + "_"
	changed := false
	result := specJSON

	// The spec JSON stores network attachments as:
	//   "network":[{"name":"LAN",...},...]
	// We need to find each "name":"X" inside network objects and prefix
	// those that aren't already scoped. Use simple string replacement
	// since the network names don't contain special characters.
	// We look for patterns like "name":"X" where X doesn't start with the prefix.
	//
	// A full JSON unmarshal/remarshal would be cleaner but risks reordering
	// fields and changing the spec hash. This targeted approach preserves
	// the exact JSON structure.

	// Find all network attachment name values. They appear as:
	//   "name":"<value>" inside the network array.
	// We iterate to find each occurrence after "network":[
	netIdx := strings.Index(result, `"network":[`)
	if netIdx == -1 {
		return specJSON, false
	}

	// Work within the network array portion.
	arrStart := netIdx + len(`"network":[`)
	// Find matching ]
	depth := 1
	arrEnd := arrStart
	for arrEnd < len(result) && depth > 0 {
		if result[arrEnd] == '[' {
			depth++
		} else if result[arrEnd] == ']' {
			depth--
		}
		arrEnd++
	}

	networkSection := result[arrStart : arrEnd-1]
	updatedSection := networkSection

	// Replace "name":"X" patterns where X doesn't have the prefix.
	nameTag := `"name":"`
	offset := 0
	for {
		idx := strings.Index(updatedSection[offset:], nameTag)
		if idx == -1 {
			break
		}
		valueStart := offset + idx + len(nameTag)
		valueEnd := strings.Index(updatedSection[valueStart:], `"`)
		if valueEnd == -1 {
			break
		}
		value := updatedSection[valueStart : valueStart+valueEnd]

		if !strings.HasPrefix(value, prefix) && value != "" {
			scopedValue := prefix + value
			updatedSection = updatedSection[:valueStart] + scopedValue + updatedSection[valueStart+valueEnd:]
			changed = true
			offset = valueStart + len(scopedValue) + 1
		} else {
			offset = valueStart + valueEnd + 1
		}
	}

	if !changed {
		return specJSON, false
	}

	result = result[:arrStart] + updatedSection + result[arrEnd-1:]
	return result, true
}
