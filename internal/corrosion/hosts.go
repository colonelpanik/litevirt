package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// HostRecord represents a host in the cluster.
type HostRecord struct {
	Name          string
	Address       string
	SSHUser       string
	SSHPort       int
	GRPCPort      int
	State         string
	CertSerial    string
	CPUTotal      int
	MemTotal      int
	DiskTotal     int
	FenceStrategy string
	// IPMI fields — optional; only used when fence_strategy = "ipmi"
	IPMIAddress string
	IPMIUser    string
	IPMIPass    string
	WatchdogDev string
	Labels      map[string]string // decoded from JSON column
	Version     string
	// Role distinguishes "worker" hosts (run VMs, vote in quorum) from
	// "witness" hosts (vote only, never host workloads). Default "worker".
	// See docs/operating-model.md for guidance on even-N deployments.
	Role string
	// Region is the host's failure-domain label (DC, rack, AZ). Used
	// by ListRegions / RegionStatus / CrossRegionMigrate. Hosts in the
	// same region share fate at the network/power level; cross-region
	// migration is the multi-DC handoff. Default "default" — single-
	// region clusters are unaffected.
	Region    string
	CreatedAt string
	UpdatedAt string
}

// IsWitness returns true if the host is a tiebreaker/witness, not a worker.
func (h HostRecord) IsWitness() bool { return h.Role == "witness" }

// InsertHost creates a new host record.
func InsertHost(ctx context.Context, c *Client, h HostRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	role := h.Role
	if role == "" {
		role = "worker"
	}
	return c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
			cpu_total, mem_total, disk_total, fence_strategy, version, role, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.Name, h.Address, h.SSHUser, h.SSHPort, h.GRPCPort, h.State, h.CertSerial,
		h.CPUTotal, h.MemTotal, h.DiskTotal, h.FenceStrategy, h.Version, role, now, c.NowTS(),
	)
}

// ListHosts returns all active hosts.
func ListHosts(ctx context.Context, c *Client) ([]HostRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
			cpu_total, mem_total, disk_total, fence_strategy,
			ipmi_address, ipmi_user, ipmi_pass, watchdog_dev,
			labels, version, role, region, created_at, updated_at
		 FROM hosts WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}

	hosts := make([]HostRecord, len(rows))
	for i, r := range rows {
		hosts[i] = scanHost(r)
	}
	return hosts, nil
}

// GetHost returns a single host by name.
func GetHost(ctx context.Context, c *Client, name string) (*HostRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
			cpu_total, mem_total, disk_total, fence_strategy,
			ipmi_address, ipmi_user, ipmi_pass, watchdog_dev,
			labels, version, role, region, created_at, updated_at
		 FROM hosts WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	h := scanHost(rows[0])
	return &h, nil
}

func scanHost(r Row) HostRecord {
	return HostRecord{
		Name:          r.String("name"),
		Address:       r.String("address"),
		SSHUser:       r.String("ssh_user"),
		SSHPort:       r.Int("ssh_port"),
		GRPCPort:      r.Int("grpc_port"),
		State:         r.String("state"),
		CertSerial:    r.String("cert_serial"),
		CPUTotal:      r.Int("cpu_total"),
		MemTotal:      r.Int("mem_total"),
		DiskTotal:     r.Int("disk_total"),
		FenceStrategy: r.String("fence_strategy"),
		IPMIAddress:   r.String("ipmi_address"),
		IPMIUser:      r.String("ipmi_user"),
		IPMIPass:      r.String("ipmi_pass"),
		WatchdogDev:   r.String("watchdog_dev"),
		Labels:        decodeLabels(r.String("labels")),
		Version:       r.String("version"),
		Role:          roleOrDefault(r.String("role")),
		Region:        regionOrDefault(r.String("region")),
		CreatedAt:     r.String("created_at"),
		UpdatedAt:     r.String("updated_at"),
	}
}

func regionOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func roleOrDefault(s string) string {
	if s == "" {
		return "worker"
	}
	return s
}

// SetHostLabel merges a single key=value into a host's labels (the hosts.labels
// JSON column that placement reads). A no-op when the value is unchanged, so a
// caller that re-asserts the same label every daemon start (e.g. LXC capability)
// doesn't churn replication. Use the empty host row gracefully — if the host
// isn't registered yet the UPDATE simply matches nothing.
func SetHostLabel(ctx context.Context, c *Client, host, key, value string) error {
	h, err := GetHost(ctx, c, host)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	if h != nil {
		for k, v := range h.Labels {
			labels[k] = v
		}
	}
	if labels[key] == value {
		return nil // unchanged — avoid replication churn
	}
	labels[key] = value
	b, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	return c.Execute(ctx,
		`UPDATE hosts SET labels = ?, updated_at = ? WHERE name = ?`,
		string(b), c.NowTS(), host)
}

func decodeLabels(raw string) map[string]string {
	m := map[string]string{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// UpdateHostState changes a host's state.
func UpdateHostState(ctx context.Context, c *Client, name, state string) error {
	return c.Execute(ctx,
		`UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`,
		state, c.NowTS(), name,
	)
}

// UpdateHostRole flips a host between "worker" and "witness". Use this to
// promote a worker to tiebreaker (must drain VMs first) or to demote a
// witness back to a worker.
func UpdateHostRole(ctx context.Context, c *Client, name, role string) error {
	if role != "worker" && role != "witness" {
		return fmt.Errorf("invalid host role %q (want worker|witness)", role)
	}
	return c.Execute(ctx,
		`UPDATE hosts SET role = ?, updated_at = ? WHERE name = ?`,
		role, c.NowTS(), name,
	)
}

// UpdateHostRegion sets a host's region label. federation —
// the region is a failure-domain tag (DC, rack, AZ) used by ListRegions
// / RegionStatus / CrossRegionMigrate. Empty region is normalised to
// "default" so existing single-region clusters never accidentally end
// up with an empty-string region.
func UpdateHostRegion(ctx context.Context, c *Client, name, region string) error {
	if region == "" {
		region = "default"
	}
	return c.Execute(ctx,
		`UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`,
		region, c.NowTS(), name,
	)
}

// DeleteHost soft-deletes a host and cleans up related records.
func DeleteHost(ctx context.Context, c *Client, name string) error {
	now := time.Now().UTC().Format(time.RFC3339) // deleted_at marker (bare)
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: `UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			Params: []interface{}{now, c.NowTS(), name}},
		{SQL: `UPDATE host_health SET deleted_at = ?, updated_at = ? WHERE observer = ? OR target = ?`,
			Params: []interface{}{now, c.NowTS(), name, name}},
		{SQL: `UPDATE network_vteps SET deleted_at = ?, updated_at = ? WHERE host_name = ?`,
			Params: []interface{}{now, c.NowTS(), name}},
	})
}

// UpdateHostVersion updates a host's reported version.
func UpdateHostVersion(ctx context.Context, c *Client, name, version string) error {
	return c.Execute(ctx,
		`UPDATE hosts SET version = ?, updated_at = ? WHERE name = ?`,
		version, c.NowTS(), name,
	)
}

// UpdateHostStartup writes a host's boot-time state in a SINGLE batched mutation:
// always state + version + updated_at (one HLC, one NowTS), and the resource
// counts only when hasResources is true (a failed NodeInfo() probe must not split
// the write into separate same-second mutations — that is exactly the race that
// strands the version on peers). version is written from the running daemon
// whenever available, including the fresh-insert case, so startup state is
// single-source rather than relying on a later write.
func UpdateHostStartup(ctx context.Context, c *Client, name, state, version string, cpu, mem, disk int, hasResources bool) error {
	uts := c.NowTS()
	// COALESCE(NULLIF(?, ''), version) keeps the existing version when the daemon
	// reports an empty one (dev builds), so a blank version can't clobber a good one.
	if hasResources {
		return c.Execute(ctx,
			`UPDATE hosts SET state = ?, version = COALESCE(NULLIF(?, ''), version),
				cpu_total = ?, mem_total = ?, disk_total = ?, updated_at = ? WHERE name = ?`,
			state, version, cpu, mem, disk, uts, name,
		)
	}
	return c.Execute(ctx,
		`UPDATE hosts SET state = ?, version = COALESCE(NULLIF(?, ''), version), updated_at = ? WHERE name = ?`,
		state, version, uts, name,
	)
}

// UpdateHostResources updates a host's resource counts.
func UpdateHostResources(ctx context.Context, c *Client, name string, cpu, mem, disk int) error {
	return c.Execute(ctx,
		`UPDATE hosts SET cpu_total = ?, mem_total = ?, disk_total = ?, updated_at = ?
		 WHERE name = ?`,
		cpu, mem, disk, c.NowTS(), name,
	)
}
