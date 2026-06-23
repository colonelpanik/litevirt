package corrosion

import (
	"context"
	"encoding/json"
	"time"
)

// Reserved labels litevirt uses to manage compose-deployed containers. They
// live here (the lowest layer) so corrosion, compose, grpcapi, and the daemon
// can all reference them without an import cycle.
const (
	// LabelStack tags a container with the compose stack that created it. The
	// containers table has no stack_name column, so this label is the stack
	// association the deploy planner (current-state diff) and teardown use.
	LabelStack = "litevirt.stack"
	// LabelLXCCapable is the HOST label the daemon sets to advertise that the
	// container (LXC) runtime is available. Compose requires it when placing
	// container workloads so they never land on a non-LXC host.
	LabelLXCCapable = "litevirt.lxc"
	// LabelIP records a container's primary IPv4 so it can serve as a load
	// balancer backend cluster-wide (containers have no vm_interfaces table).
	// Set from a static compose NIC address at create; the LB host re-discovers
	// a DHCP address locally via lxc-info when this is empty.
	LabelIP = "litevirt.ip"
)

// ContainerRecord is one LXC/OCI container's cluster-state row.
// populated by the daemon owning the container; the
// `lv ct ls` query reads across the whole cluster.
type ContainerRecord struct {
	HostName string
	Name     string
	State    string
	Image    string
	CPULimit int
	MemMiB   int
	Labels   map[string]string
	// RestartPolicy is the JSON-encoded pb.RestartPolicy ('' = none). StateDetail
	// carries the stop cause / intent ('operator-stop' etc.), the container
	// analogue of vms.state_detail; both added in schema v24.
	RestartPolicy string
	StateDetail   string
	// Project is the tenancy bucket (mirrors vms.project); '' is normalized to
	// '_default' on write. Added in schema v25.
	Project   string
	CreatedAt string
	UpdatedAt string
}

// UpsertContainer creates or updates the cluster row for a container.
// Atomic: the (host_name, name) primary key plus a soft-delete-aware
// UPDATE keeps us from racing with concurrent List queries.
func UpsertContainer(ctx context.Context, c *Client, r ContainerRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	if r.Project == "" {
		r.Project = "_default"
	}
	labelsJSON := ""
	if len(r.Labels) > 0 {
		b, err := json.Marshal(r.Labels)
		if err != nil {
			return err
		}
		labelsJSON = string(b)
	}
	// SQLite's UPSERT (INSERT... ON CONFLICT) is the right tool here;
	// we keep created_at on update so the original timestamp survives.
	return c.Execute(ctx,
		`INSERT INTO containers (host_name, name, state, image, cpu_limit, memory_mib, labels, restart_policy, state_detail, project, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   state = excluded.state,
		   image = excluded.image,
		   cpu_limit = excluded.cpu_limit,
		   memory_mib = excluded.memory_mib,
		   labels = excluded.labels,
		   restart_policy = excluded.restart_policy,
		   state_detail = excluded.state_detail,
		   project = excluded.project,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		r.HostName, r.Name, r.State, r.Image, r.CPULimit, r.MemMiB,
		labelsJSON, r.RestartPolicy, r.StateDetail, r.Project, r.CreatedAt, now,
	)
}

// SetContainerState updates only the state + updated_at — used after
// Start/Stop calls so we don't have to round-trip the full record.
func SetContainerState(ctx context.Context, c *Client, hostName, name, state string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE containers SET state = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, now, hostName, name)
}

// SetContainerStateDetail updates state + state_detail together (leaving
// restart_policy untouched). Used by StopContainer to record operator intent
// ('operator-stop') and by the container reconciler to sync the cluster row to
// the runtime's reality with a stop-cause hint. The detail is the channel the
// restart engine reads to decide whether a stop was intentional.
func SetContainerStateDetail(ctx context.Context, c *Client, hostName, name, state, detail string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE containers SET state = ?, state_detail = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, detail, now, hostName, name)
}

// DeleteContainer soft-deletes the row. We don't physically delete so
// "container vanished from gossip" can be distinguished from "host
// crashed and we just haven't heard yet" in audit views.
func DeleteContainer(ctx context.Context, c *Client, hostName, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE containers SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ?`,
		now, now, hostName, name)
}

// GetContainer returns one container row (including soft-deleted, so
// audit tools can resurrect names).
func GetContainer(ctx context.Context, c *Client, hostName, name string) (*ContainerRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, name, state, COALESCE(image, '') AS image,
		        cpu_limit, memory_mib, COALESCE(labels, '') AS labels,
		        COALESCE(restart_policy, '') AS restart_policy,
		        COALESCE(state_detail, '') AS state_detail,
		        COALESCE(project, '_default') AS project,
		        created_at, updated_at
		 FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		hostName, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &ContainerRecord{
		HostName: r.String("host_name"), Name: r.String("name"),
		State: r.String("state"), Image: r.String("image"),
		CPULimit: r.Int("cpu_limit"), MemMiB: r.Int("memory_mib"),
		Labels:        decodeContainerLabels(r.String("labels")),
		RestartPolicy: r.String("restart_policy"), StateDetail: r.String("state_detail"),
		Project:   r.String("project"),
		CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at"),
	}, nil
}

// ListContainers returns every active container, optionally scoped to
// one host. Empty hostName = cluster-wide.
func ListContainers(ctx context.Context, c *Client, hostName string) ([]ContainerRecord, error) {
	sql := `SELECT host_name, name, state, COALESCE(image, '') AS image,
		   cpu_limit, memory_mib, COALESCE(labels, '') AS labels,
		   COALESCE(restart_policy, '') AS restart_policy,
		   COALESCE(state_detail, '') AS state_detail,
		   COALESCE(project, '_default') AS project,
		   created_at, updated_at
		FROM containers WHERE deleted_at IS NULL`
	var params []interface{}
	if hostName != "" {
		sql += " AND host_name = ?"
		params = append(params, hostName)
	}
	sql += " ORDER BY host_name, name"
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	out := make([]ContainerRecord, len(rows))
	for i, r := range rows {
		out[i] = ContainerRecord{
			HostName: r.String("host_name"), Name: r.String("name"),
			State: r.String("state"), Image: r.String("image"),
			CPULimit: r.Int("cpu_limit"), MemMiB: r.Int("memory_mib"),
			Labels:        decodeContainerLabels(r.String("labels")),
			RestartPolicy: r.String("restart_policy"), StateDetail: r.String("state_detail"),
			Project:   r.String("project"),
			CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at"),
		}
	}
	return out, nil
}

// ListContainersByStack returns active containers tagged with the given compose
// stack (via the LabelStack label set at deploy time). Compose uses this for
// idempotent re-apply (current state) and teardown — the containers table has
// no stack_name column, so the label is the association.
func ListContainersByStack(ctx context.Context, c *Client, stack string) ([]ContainerRecord, error) {
	all, err := ListContainers(ctx, c, "")
	if err != nil {
		return nil, err
	}
	out := make([]ContainerRecord, 0)
	for _, ct := range all {
		if ct.Labels[LabelStack] == stack {
			out = append(out, ct)
		}
	}
	return out, nil
}

// decodeContainerLabels parses the JSON labels column on the
// containers row. Distinct name from hosts.go's decodeLabels because
// they live in the same package.
func decodeContainerLabels(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
