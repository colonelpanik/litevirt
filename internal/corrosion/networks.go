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
	// renamed maps each network name this pass actually rescopes to its new
	// name; existing is the set of network names that exist once the pass is
	// done. Both drive the spec-blob rewrite below, which must follow REAL
	// renames only.
	renamed := map[string]string{}
	existing := make(map[string]bool, len(nets))
	for _, nr := range nets {
		existing[nr.Name] = true
	}

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
		renamed[nr.Name] = scopedName
		delete(existing, nr.Name)
		existing[scopedName] = true
		slog.Info("migrating legacy network name", "old", nr.Name, "new", scopedName)

		// networks.name is the single primary key, so this rename is a full-PK LWW update.
		_ = c.Execute(ctx,
			`UPDATE networks SET name = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
			scopedName, now, nr.Name)
		// The other three tables key on a COMPOSITE PK whose network component is being
		// rekeyed; a bulk `WHERE network_name = ?` update can't be per-row LWW-gated on a
		// peer, so enumerate the matching rows locally and emit one full-PK statement each
		// (a rekey that collides with an existing row on a peer then fails closed).
		rescope := func(sel string, exec func(pk string)) {
			rows, err := c.Query(ctx, sel, nr.Name)
			if err != nil {
				return
			}
			for _, row := range rows {
				exec(row.String("pk"))
			}
		}
		rescope(`SELECT host_name AS pk FROM network_vteps WHERE network_name = ? AND deleted_at IS NULL`,
			func(pk string) {
				_ = c.Execute(ctx, `UPDATE network_vteps SET network_name = ?, updated_at = ? WHERE network_name = ? AND host_name = ? AND deleted_at IS NULL`, scopedName, now, nr.Name, pk)
			})
		rescope(`SELECT ip AS pk FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`,
			func(pk string) {
				_ = c.Execute(ctx, `UPDATE ip_allocations SET network = ?, updated_at = ? WHERE network = ? AND ip = ? AND deleted_at IS NULL`, scopedName, now, nr.Name, pk)
			})
		rescope(`SELECT vm_name AS pk FROM vm_interfaces WHERE network_name = ? AND deleted_at IS NULL`,
			func(pk string) {
				_ = c.Execute(ctx, `UPDATE vm_interfaces SET network_name = ?, updated_at = ? WHERE vm_name = ? AND network_name = ? AND deleted_at IS NULL`, scopedName, now, pk, nr.Name)
			})
	}

	// Migrate network names inside VM spec JSON.
	if err := migrateVMSpecNetworkNames(ctx, c, renamed, existing); err != nil {
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

// migrateVMSpecNetworkNames updates the network attachment names inside the
// stored VM spec JSON to follow the networks this pass renamed, and heals a
// name an earlier pass mis-prefixed. renamed is old name → scoped name for
// the networks actually rescoped; existing is the set of network names that
// exist afterwards.
//
// An earlier version prefixed EVERY attachment name with the VM's stack,
// including an external network attached under its plain, unscoped name. The
// blob then pointed at a network that did not exist, while the NIC rows (which
// are only rescoped for the renamed networks) kept the real name — so an
// unchanged compose attachment compared against the blob as a network-topology
// change, which the default update strategy executes as delete + recreate.
func migrateVMSpecNetworkNames(ctx context.Context, c *Client, renamed map[string]string, existing map[string]bool) error {
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

		updated, changed := rescopeSpecNetworkNames(spec, stackName, renamed, existing)
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

// rescopeSpecNetworkNames does a targeted rewrite of the "name" fields inside
// the "network" array of a VMSpec JSON string, returning the updated JSON and
// whether anything changed. A name is rewritten in exactly two cases:
//
//   - it is a key of renamed: the network it refers to was rescoped by this
//     pass, so the attachment follows it;
//   - it carries the VM's stack prefix, no network of that name exists, and
//     the plain name does: an earlier pass mis-prefixed an attachment to an
//     unscoped network, and the blob is healed back to the real name.
//
// Every other name — in particular an external network attached under its
// plain name — is left exactly as it is. The rewrite works on the JSON text
// rather than unmarshal/remarshal so no other field is dropped or reordered.
func rescopeSpecNetworkNames(specJSON, stackName string, renamed map[string]string, existing map[string]bool) (string, bool) {
	netIdx := strings.Index(specJSON, `"network":[`)
	if netIdx == -1 {
		return specJSON, false
	}
	prefix := stackName + "_"

	// Work within the network array portion.
	arrStart := netIdx + len(`"network":[`)
	depth := 1
	arrEnd := arrStart
	for arrEnd < len(specJSON) && depth > 0 {
		if specJSON[arrEnd] == '[' {
			depth++
		} else if specJSON[arrEnd] == ']' {
			depth--
		}
		arrEnd++
	}
	section := specJSON[arrStart : arrEnd-1]
	changed := false

	nameTag := `"name":"`
	offset := 0
	for {
		idx := strings.Index(section[offset:], nameTag)
		if idx == -1 {
			break
		}
		valueStart := offset + idx + len(nameTag)
		valueEnd := strings.Index(section[valueStart:], `"`)
		if valueEnd == -1 {
			break
		}
		value := section[valueStart : valueStart+valueEnd]

		replacement := ""
		if to, ok := renamed[value]; ok && to != value {
			replacement = to
		} else if plain := strings.TrimPrefix(value, prefix); plain != value && !existing[value] && existing[plain] {
			replacement = plain
		}
		if replacement != "" {
			section = section[:valueStart] + replacement + section[valueStart+valueEnd:]
			changed = true
			offset = valueStart + len(replacement) + 1
		} else {
			offset = valueStart + valueEnd + 1
		}
	}

	if !changed {
		return specJSON, false
	}
	return specJSON[:arrStart] + section + specJSON[arrEnd-1:], true
}
