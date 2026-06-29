package corrosion

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// DefaultProject is the implicit bucket every VM lands in when no
// project: tag is set in compose or the CLI. Single-tenant clusters
// never need to interact with the projects table.
const DefaultProject = "_default"

// ProjectRecord is one row in the projects table — a hierarchical
// path like "/acme/team-foo".
type ProjectRecord struct {
	Name       string // canonical path; PRIMARY KEY
	Display    string
	ParentName string // "" for root
	CreatedAt  string
	UpdatedAt  string
}

// ProjectQuotaRecord caps one project's resource usage. Zero = unbounded.
type ProjectQuotaRecord struct {
	ProjectName    string
	VCPULimit      int
	MemMiBLimit    int
	DiskGiBLimit   int
	NICLimit       int
	PublicIPLimit  int
	BackupGiBLimit int
}

// InsertProject creates a new project. Parent must already exist
// (or be empty for a root project). Use UpsertProjectQuota afterwards
// to set quotas; without quotas the project is unbounded.
func InsertProject(ctx context.Context, c *Client, p ProjectRecord) error {
	if p.Name == "" {
		return fmt.Errorf("project name required")
	}
	if p.ParentName != "" {
		existing, err := GetProject(ctx, c, p.ParentName)
		if err != nil {
			return fmt.Errorf("check parent: %w", err)
		}
		if existing == nil {
			return fmt.Errorf("parent project %q does not exist", p.ParentName)
		}
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO projects (name, display, parent_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		p.Name, p.Display, p.ParentName, nowRFC3339(), now)
}

// GetProject returns the project by name (canonical path) or nil if
// absent. Treats _default as always existing — never returns nil for it.
func GetProject(ctx context.Context, c *Client, name string) (*ProjectRecord, error) {
	if name == DefaultProject {
		return &ProjectRecord{Name: DefaultProject, Display: "default"}, nil
	}
	rows, err := c.Query(ctx,
		`SELECT name, display, parent_name, created_at, updated_at
		 FROM projects WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &ProjectRecord{
		Name:       r.String("name"),
		Display:    r.String("display"),
		ParentName: r.String("parent_name"),
		CreatedAt:  r.String("created_at"),
		UpdatedAt:  r.String("updated_at"),
	}, nil
}

// ListProjects returns every non-deleted project. _default is
// surfaced as the first entry even when no row exists for it.
func ListProjects(ctx context.Context, c *Client) ([]ProjectRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, display, parent_name, created_at, updated_at
		 FROM projects WHERE deleted_at IS NULL
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []ProjectRecord{{Name: DefaultProject, Display: "default"}}
	for _, r := range rows {
		out = append(out, ProjectRecord{
			Name:       r.String("name"),
			Display:    r.String("display"),
			ParentName: r.String("parent_name"),
			CreatedAt:  r.String("created_at"),
			UpdatedAt:  r.String("updated_at"),
		})
	}
	return out, nil
}

// DeleteProject soft-deletes a project. Refuses if any VM still
// carries the project label — admission would let resources leak
// otherwise. Children must be deleted first.
func DeleteProject(ctx context.Context, c *Client, name string) error {
	if name == DefaultProject {
		return fmt.Errorf("cannot delete the default project")
	}
	// Refuse if children exist.
	children, err := c.Query(ctx,
		`SELECT 1 FROM projects WHERE parent_name = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return fmt.Errorf("project %q has children; delete them first", name)
	}
	// Refuse if VMs still carry the label.
	vmRows, err := c.Query(ctx,
		`SELECT 1 FROM vms WHERE project = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(vmRows) > 0 {
		return fmt.Errorf("project %q still owns VMs; reassign or delete them first", name)
	}
	// Refuse if containers still carry the project — deleting the project would
	// orphan their project association (quota accounting + RBAC paths). Mirrors
	// the VM guard above; added when containers gained a project column (v25).
	ctRows, err := c.Query(ctx,
		`SELECT 1 FROM containers WHERE project = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(ctRows) > 0 {
		return fmt.Errorf("project %q still owns containers; reassign or delete them first", name)
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		nowRFC3339(), now, name)
}

// UpsertProjectQuota writes a quota row for the project. Zero in
// any field means "unbounded" — that's the default state for
// new projects.
func UpsertProjectQuota(ctx context.Context, c *Client, q ProjectQuotaRecord) error {
	if q.ProjectName == "" {
		return fmt.Errorf("project_name required")
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO project_quotas
		   (project_name, vcpu_limit, mem_mib_limit, disk_gib_limit,
		    nic_limit, public_ip_limit, backup_gib_limit, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project_name) DO UPDATE SET
		   vcpu_limit       = excluded.vcpu_limit,
		   mem_mib_limit    = excluded.mem_mib_limit,
		   disk_gib_limit   = excluded.disk_gib_limit,
		   nic_limit        = excluded.nic_limit,
		   public_ip_limit  = excluded.public_ip_limit,
		   backup_gib_limit = excluded.backup_gib_limit,
		   updated_at       = excluded.updated_at`,
		q.ProjectName, q.VCPULimit, q.MemMiBLimit, q.DiskGiBLimit,
		q.NICLimit, q.PublicIPLimit, q.BackupGiBLimit, now)
}

// GetProjectQuota returns the quota row or nil if unset. The default
// project has no quotas (every limit = 0 = unbounded) — returns nil.
func GetProjectQuota(ctx context.Context, c *Client, name string) (*ProjectQuotaRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT project_name, vcpu_limit, mem_mib_limit, disk_gib_limit,
		        nic_limit, public_ip_limit, backup_gib_limit
		 FROM project_quotas WHERE project_name = ?`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &ProjectQuotaRecord{
		ProjectName:    r.String("project_name"),
		VCPULimit:      r.Int("vcpu_limit"),
		MemMiBLimit:    r.Int("mem_mib_limit"),
		DiskGiBLimit:   r.Int("disk_gib_limit"),
		NICLimit:       r.Int("nic_limit"),
		PublicIPLimit:  r.Int("public_ip_limit"),
		BackupGiBLimit: r.Int("backup_gib_limit"),
	}, nil
}

// ProjectUsage is the live resource consumption of one project,
// computed by summing the VMs that carry the project label.
type ProjectUsage struct {
	ProjectName   string
	VCPUUsed      int
	MemMiBUsed    int
	DiskGiBUsed   int
	NICUsed       int
	VMCount       int
	PublicIPsUsed int // interfaces whose address is non-private (routable)
	BackupGiBUsed int // summed backup size across the project's VMs
}

// SumProjectUsage returns the current usage by walking vms +
// vm_disks + vm_interfaces. Cheap on small clusters; the admission
// path calls this on every CreateVM to gate against the quota.
func SumProjectUsage(ctx context.Context, c *Client, name string) (*ProjectUsage, error) {
	u := &ProjectUsage{ProjectName: name}

	// VM count + summed spec CPU/RAM via JSON extraction. We persist
	// VMSpec as a JSON blob in vms.spec — sqlite json_extract is
	// the cheapest path.
	rows, err := c.Query(ctx,
		`SELECT
		   COUNT(*)                                    AS vm_count,
		   COALESCE(SUM(json_extract(spec,'$.cpu')),0)        AS cpu,
		   COALESCE(SUM(json_extract(spec,'$.memory_mib')),0) AS mem
		 FROM vms WHERE project = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		u.VMCount = rows[0].Int("vm_count")
		u.VCPUUsed = rows[0].Int("cpu")
		u.MemMiBUsed = rows[0].Int("mem")
	}

	// Containers share the project's vCPU/Mem budget (one joint tenant limit).
	// They carry plain cpu_limit/memory_mib columns; an allocation counts whether
	// running or stopped (matching VMs). A container created with no explicit
	// --cpu/--memory (limit 0 = unbounded) contributes 0 to that dimension —
	// only declared limits are quota-accounted.
	ctRows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(cpu_limit),0)  AS cpu,
		        COALESCE(SUM(memory_mib),0) AS mem
		 FROM containers WHERE project = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(ctRows) > 0 {
		u.VCPUUsed += ctRows[0].Int("cpu")
		u.MemMiBUsed += ctRows[0].Int("mem")
	}

	diskRows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(vm_disks.size_bytes), 0) AS bytes
		 FROM vm_disks
		 JOIN vms ON vm_disks.vm_name = vms.name
		 WHERE vms.project = ? AND vms.deleted_at IS NULL AND vm_disks.deleted_at IS NULL`,
		name)
	if err == nil && len(diskRows) > 0 {
		bytes := diskRows[0].Int64("bytes")
		u.DiskGiBUsed = int(bytes / (1 << 30))
	}

	// NIC count + public-IP count from the same interface set. Public-IP
	// classification matches the admission path: any parseable, non-private
	// address counts (net.IP.IsPrivate covers RFC1918 + ULA).
	ipRows, err := c.Query(ctx,
		`SELECT vm_interfaces.ip AS ip
		 FROM vm_interfaces
		 JOIN vms ON vm_interfaces.vm_name = vms.name
		 WHERE vms.project = ? AND vms.deleted_at IS NULL AND vm_interfaces.deleted_at IS NULL`,
		name)
	if err == nil {
		u.NICUsed = len(ipRows)
		for _, r := range ipRows {
			if ip := net.ParseIP(r.String("ip")); ip != nil && !ip.IsPrivate() {
				u.PublicIPsUsed++
			}
		}
	}
	// Container NICs count toward the same NIC / public-IP budget (v35: containers
	// are now first-class network citizens via container_interfaces).
	ctIPRows, err := c.Query(ctx,
		`SELECT container_interfaces.ip AS ip
		 FROM container_interfaces
		 JOIN containers ON container_interfaces.host_name = containers.host_name
		                AND container_interfaces.ct_name = containers.name
		 WHERE containers.project = ? AND containers.deleted_at IS NULL AND container_interfaces.deleted_at IS NULL`,
		name)
	if err == nil {
		u.NICUsed += len(ctIPRows)
		for _, r := range ctIPRows {
			if ip := net.ParseIP(r.String("ip")); ip != nil && !ip.IsPrivate() {
				u.PublicIPsUsed++
			}
		}
	}

	// Backup footprint: VMs and containers draw down the SAME backup_gib budget.
	// Sum the latest backup size per (vm, disk, repo) from vm_backups and per
	// (container, repo) from container_backups (both populated on each push;
	// manifests themselves live on-disk in pbsstore repos, not in Corrosion).
	var backupBytes int64
	bkRows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(vm_backups.total_bytes), 0) AS bytes
		 FROM vm_backups
		 JOIN vms ON vm_backups.vm_name = vms.name
		 WHERE vms.project = ? AND vms.deleted_at IS NULL`,
		name)
	if err == nil && len(bkRows) > 0 {
		backupBytes += bkRows[0].Int64("bytes")
	}
	ctBkRows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(container_backups.total_bytes), 0) AS bytes
		 FROM container_backups
		 JOIN containers ON container_backups.ct_name = containers.name
		 WHERE containers.project = ? AND containers.deleted_at IS NULL`,
		name)
	if err == nil && len(ctBkRows) > 0 {
		backupBytes += ctBkRows[0].Int64("bytes")
	}
	u.BackupGiBUsed = int(backupBytes / (1 << 30))

	return u, nil
}

// UpsertVMBackup records the latest backup size for one (vm, disk, repo) into
// the vm_backups index, so the tenancy backup_gib quota can be summed cheaply
// (backup manifests live on-disk in pbsstore repos, not in Corrosion). Called
// after a successful backup push; total_bytes is the manifest's logical size.
// Replicated via the mutation log like other writes, so the footprint is
// visible cluster-wide for project-quota admission on any host.
func UpsertVMBackup(ctx context.Context, c *Client, vmName, diskName, repo string, totalBytes int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO vm_backups (vm_name, disk_name, repo, total_bytes, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(vm_name, disk_name, repo) DO UPDATE SET
		   total_bytes = excluded.total_bytes,
		   updated_at  = excluded.updated_at`,
		vmName, diskName, repo, totalBytes, now)
}

// UpsertContainerBackup records the latest backup size for one (container, repo)
// into the container_backups index — the container analogue of UpsertVMBackup,
// so the tenancy backup_gib quota sums container footprints alongside VMs.
func UpsertContainerBackup(ctx context.Context, c *Client, ctName, repo string, totalBytes int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO container_backups (ct_name, repo, total_bytes, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(ct_name, repo) DO UPDATE SET
		   total_bytes = excluded.total_bytes,
		   updated_at  = excluded.updated_at`,
		ctName, repo, totalBytes, now)
}

// QuotaCheck describes a proposed resource request. The admission
// path builds one from a CreateVM call and passes it to
// CheckProjectQuota; if any dimension would push the project over
// its quota, the call is rejected.
type QuotaCheck struct {
	VCPU    int
	MemMiB  int
	DiskGiB int
	NIC     int
}

// CheckProjectQuota returns nil if the proposed allocation would fit
// under the project's quotas, or a descriptive error otherwise.
// Empty/missing quota row means unbounded — admission passes.
func CheckProjectQuota(ctx context.Context, c *Client, projectName string, req QuotaCheck) error {
	q, err := GetProjectQuota(ctx, c, projectName)
	if err != nil {
		return fmt.Errorf("get quota: %w", err)
	}
	if q == nil {
		return nil // unbounded
	}
	u, err := SumProjectUsage(ctx, c, projectName)
	if err != nil {
		return fmt.Errorf("get usage: %w", err)
	}
	var violations []string
	if q.VCPULimit > 0 && u.VCPUUsed+req.VCPU > q.VCPULimit {
		violations = append(violations,
			fmt.Sprintf("vcpu (used %d + new %d > limit %d)",
				u.VCPUUsed, req.VCPU, q.VCPULimit))
	}
	if q.MemMiBLimit > 0 && u.MemMiBUsed+req.MemMiB > q.MemMiBLimit {
		violations = append(violations,
			fmt.Sprintf("mem_mib (used %d + new %d > limit %d)",
				u.MemMiBUsed, req.MemMiB, q.MemMiBLimit))
	}
	if q.DiskGiBLimit > 0 && u.DiskGiBUsed+req.DiskGiB > q.DiskGiBLimit {
		violations = append(violations,
			fmt.Sprintf("disk_gib (used %d + new %d > limit %d)",
				u.DiskGiBUsed, req.DiskGiB, q.DiskGiBLimit))
	}
	if q.NICLimit > 0 && u.NICUsed+req.NIC > q.NICLimit {
		violations = append(violations,
			fmt.Sprintf("nic (used %d + new %d > limit %d)",
				u.NICUsed, req.NIC, q.NICLimit))
	}
	if len(violations) > 0 {
		return fmt.Errorf("project %q quota exceeded: %s",
			projectName, strings.Join(violations, "; "))
	}
	return nil
}
