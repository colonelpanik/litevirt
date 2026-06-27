package corrosion

import (
	"context"
	"encoding/json"
	"time"
)

// encodeSGs turns a list of security-group names into JSON (or empty
// string when the list is nil/empty so SQLite stores NULL via the
// caller's COALESCE).
func encodeSGs(sgs []string) (string, error) {
	if len(sgs) == 0 {
		return "", nil
	}
	b, err := json.Marshal(sgs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeSGs is the inverse — empty string or invalid JSON returns nil.
func decodeSGs(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// VMRecord represents a VM in corrosion state.
type VMRecord struct {
	Name        string
	StackName   string
	HostName    string
	Spec        string // JSON blob
	State       string
	StateDetail string
	CPUActual   int
	MemActual   int
	// Project is the tenancy bucket. Empty → "_default".
	Project   string
	CreatedAt string
	UpdatedAt string
	// IsTemplate marks a VM that can't start; its disks are immutable clone
	// sources (Proxmox-style template).
	IsTemplate bool
}

// InterfaceRecord represents a VM network interface.
type InterfaceRecord struct {
	VMName      string
	NetworkName string
	Ordinal     int
	MAC         string
	IP          string
	TapDevice   string

	// SecurityGroups is the list of security-group names bound to this
	// NIC. distributed firewall — the firewall reconciler
	// uses these names to render per-NIC nftables chains.
	SecurityGroups []string
}

// DiskRecord represents a VM disk.
type DiskRecord struct {
	VMName        string
	DiskName      string
	HostName      string
	Path          string
	SizeBytes     int64
	BackingImage  string
	StorageType   string
	StorageVolume string
	TargetDev     string // libvirt target dev name (vdb, sdc, etc.)
	// BackingDisk is the source disk path this disk is a linked-clone overlay
	// of (empty for normal/full-clone disks). Used to refcount-guard the
	// source template/snapshot and host-pin local-storage linked clones.
	BackingDisk string
}

// projectOrDefault normalises an empty project string to "_default"
// so existing single-tenant callers don't carry a blank label.
func projectOrDefault(p string) string {
	if p == "" {
		return DefaultProject
	}
	return p
}

// InsertVM creates a new VM record with its interfaces and disks.
func InsertVM(ctx context.Context, c *Client, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)

	stmts := []Statement{
		// Purge any soft-deleted record with the same name so the INSERT succeeds.
		// full-state-delete-ok: these only drop an ALREADY-tombstoned row right
		// before re-inserting a fresh one — the new row's newer updated_at wins LWW,
		// so there is no cross-node resurrection window. (See the hard-delete guard
		// test; full-state tables must otherwise soft-delete.)
		{SQL: `DELETE FROM vm_disks WHERE vm_name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{vm.Name}},      // full-state-delete-ok
		{SQL: `DELETE FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{vm.Name}}, // full-state-delete-ok
		{SQL: `DELETE FROM vms WHERE name = ? AND deleted_at IS NOT NULL`, Params: []interface{}{vm.Name}},              // full-state-delete-ok
		{
			SQL: `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				vm.Name, vm.StackName, vm.HostName, vm.Spec, vm.State, vm.StateDetail,
				vm.CPUActual, vm.MemActual, projectOrDefault(vm.Project), boolToInt(vm.IsTemplate), now, now,
			},
		},
	}

	for _, iface := range ifaces {
		sgsJSON, err := encodeSGs(iface.SecurityGroups)
		if err != nil {
			return err
		}
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				iface.VMName, iface.NetworkName, iface.Ordinal, iface.MAC,
				iface.IP, iface.TapDevice, sgsJSON, now,
			},
		})
	}

	for _, disk := range disks {
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO vm_disks (vm_name, disk_name, host_name, path, size_bytes,
				backing_image, storage_type, storage_volume, target_dev, backing_disk, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{
				disk.VMName, disk.DiskName, disk.HostName, disk.Path, disk.SizeBytes,
				disk.BackingImage, disk.StorageType, disk.StorageVolume, disk.TargetDev, nullIfEmpty(disk.BackingDisk), now,
			},
		})
	}

	return c.ExecuteBatch(ctx, stmts)
}

// ListVMs returns VMs with optional filters.
func ListVMs(ctx context.Context, c *Client, stackName, hostName string) ([]VMRecord, error) {
	sql := `SELECT name, stack_name, host_name, spec, state, state_detail,
		cpu_actual, mem_actual, COALESCE(project, '_default') AS project,
		COALESCE(is_template, 0) AS is_template, created_at, updated_at
		FROM vms WHERE deleted_at IS NULL`
	var params []interface{}

	if stackName != "" {
		sql += " AND stack_name = ?"
		params = append(params, stackName)
	}
	if hostName != "" {
		sql += " AND host_name = ?"
		params = append(params, hostName)
	}

	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}

	vms := make([]VMRecord, len(rows))
	for i, r := range rows {
		vms[i] = VMRecord{
			Name:        r.String("name"),
			StackName:   r.String("stack_name"),
			HostName:    r.String("host_name"),
			Spec:        r.String("spec"),
			State:       r.String("state"),
			StateDetail: r.String("state_detail"),
			CPUActual:   r.Int("cpu_actual"),
			MemActual:   r.Int("mem_actual"),
			Project:     r.String("project"),
			IsTemplate:  r.Int("is_template") == 1,
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
		}
	}
	return vms, nil
}

// GetVM returns a single VM by name.
func GetVM(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, stack_name, host_name, spec, state, state_detail,
			cpu_actual, mem_actual, COALESCE(project, '_default') AS project,
			COALESCE(is_template, 0) AS is_template, created_at, updated_at
		 FROM vms WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	r := rows[0]
	return &VMRecord{
		Name:        r.String("name"),
		StackName:   r.String("stack_name"),
		HostName:    r.String("host_name"),
		Spec:        r.String("spec"),
		State:       r.String("state"),
		StateDetail: r.String("state_detail"),
		CPUActual:   r.Int("cpu_actual"),
		MemActual:   r.Int("mem_actual"),
		Project:     r.String("project"),
		IsTemplate:  r.Int("is_template") == 1,
		CreatedAt:   r.String("created_at"),
		UpdatedAt:   r.String("updated_at"),
	}, nil
}

// GetDeletedVM returns a soft-deleted VM by name, or nil if no deleted record exists.
func GetDeletedVM(ctx context.Context, c *Client, name string) (*VMRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, host_name, state FROM vms WHERE name = ? AND deleted_at IS NOT NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &VMRecord{
		Name:     r.String("name"),
		HostName: r.String("host_name"),
		State:    r.String("state"),
	}, nil
}

// GetVMInterfaces returns all interfaces for a VM.
func GetVMInterfaces(ctx context.Context, c *Client, vmName string) ([]InterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, network_name, ordinal, mac, ip, tap_device,
		        COALESCE(security_groups, '') AS security_groups
		 FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NULL
		 ORDER BY ordinal`, vmName)
	if err != nil {
		return nil, err
	}

	ifaces := make([]InterfaceRecord, len(rows))
	for i, r := range rows {
		ifaces[i] = InterfaceRecord{
			VMName:         r.String("vm_name"),
			NetworkName:    r.String("network_name"),
			Ordinal:        r.Int("ordinal"),
			MAC:            r.String("mac"),
			IP:             r.String("ip"),
			TapDevice:      r.String("tap_device"),
			SecurityGroups: decodeSGs(r.String("security_groups")),
		}
	}
	return ifaces, nil
}

// ListVMInterfacesByHost returns every active NIC on this host. Used
// by the firewall reconciler to bind security groups to taps; cheaper
// than walking VMs one by one.
func ListVMInterfacesByHost(ctx context.Context, c *Client, hostName string) ([]InterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT i.vm_name, i.network_name, i.ordinal, i.mac, i.ip, i.tap_device,
		        COALESCE(i.security_groups, '') AS security_groups
		 FROM vm_interfaces i
		 JOIN vms v ON v.name = i.vm_name
		 WHERE v.host_name = ? AND v.deleted_at IS NULL AND i.deleted_at IS NULL`,
		hostName)
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceRecord, len(rows))
	for i, r := range rows {
		out[i] = InterfaceRecord{
			VMName:         r.String("vm_name"),
			NetworkName:    r.String("network_name"),
			Ordinal:        r.Int("ordinal"),
			MAC:            r.String("mac"),
			IP:             r.String("ip"),
			TapDevice:      r.String("tap_device"),
			SecurityGroups: decodeSGs(r.String("security_groups")),
		}
	}
	return out, nil
}

// SetInterfaceSecurityGroups updates the SG binding on one VM NIC,
// keyed by (vm_name, network_name). Used by the BindSecurityGroups
// RPC for runtime mutations without redeploying the VM.
func SetInterfaceSecurityGroups(ctx context.Context, c *Client, vmName, networkName string, sgs []string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	sgsJSON, err := encodeSGs(sgs)
	if err != nil {
		return err
	}
	return c.Execute(ctx,
		`UPDATE vm_interfaces SET security_groups = ?, updated_at = ?
		 WHERE vm_name = ? AND network_name = ? AND deleted_at IS NULL`,
		sgsJSON, now, vmName, networkName)
}

// GetVMDisks returns all disks for a VM.
func GetVMDisks(ctx context.Context, c *Client, vmName string) ([]DiskRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, size_bytes,
			backing_image, storage_type, storage_volume, target_dev,
			COALESCE(backing_disk, '') AS backing_disk
		 FROM vm_disks WHERE vm_name = ? AND deleted_at IS NULL`, vmName)
	if err != nil {
		return nil, err
	}

	disks := make([]DiskRecord, len(rows))
	for i, r := range rows {
		disks[i] = DiskRecord{
			VMName:        r.String("vm_name"),
			DiskName:      r.String("disk_name"),
			HostName:      r.String("host_name"),
			Path:          r.String("path"),
			SizeBytes:     r.Int64("size_bytes"),
			BackingImage:  r.String("backing_image"),
			StorageType:   r.String("storage_type"),
			StorageVolume: r.String("storage_volume"),
			TargetDev:     r.String("target_dev"),
			BackingDisk:   r.String("backing_disk"),
		}
	}
	return disks, nil
}

// SetVMTemplate flips a VM's is_template flag (used by ConvertToTemplate and
// its revert).
func SetVMTemplate(ctx context.Context, c *Client, name string, isTemplate bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vms SET is_template = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		boolToInt(isTemplate), now, name)
}

// LinkedCloneNames returns the names of VMs that have a disk which is a
// linked-clone overlay backed by backingPath. Used to refuse deleting a
// template/snapshot disk that still backs live clones.
func LinkedCloneNames(ctx context.Context, c *Client, backingPath string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT vm_name FROM vm_disks WHERE backing_disk = ? AND deleted_at IS NULL`,
		backingPath)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("vm_name"))
	}
	return out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullIfEmpty returns nil for an empty string so the column stores SQL NULL
// (keeps COALESCE/refcount queries clean) rather than an empty string.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// DisksReferencingPath returns every non-deleted disk record that references
// path — either as its own disk file (path) or as a backing image
// (backing_image). It is used to guard a source-disk delete after a volume
// move: a file is safe to remove only if no other disk still depends on it
// (a shared disk file, or a base/backing image other overlays read from).
func DisksReferencingPath(ctx context.Context, c *Client, path string) ([]DiskRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, disk_name, host_name, path, size_bytes,
			backing_image, storage_type, storage_volume, target_dev
		 FROM vm_disks WHERE (path = ? OR backing_image = ?) AND deleted_at IS NULL`,
		path, path)
	if err != nil {
		return nil, err
	}
	disks := make([]DiskRecord, len(rows))
	for i, r := range rows {
		disks[i] = DiskRecord{
			VMName:        r.String("vm_name"),
			DiskName:      r.String("disk_name"),
			HostName:      r.String("host_name"),
			Path:          r.String("path"),
			SizeBytes:     r.Int64("size_bytes"),
			BackingImage:  r.String("backing_image"),
			StorageType:   r.String("storage_type"),
			StorageVolume: r.String("storage_volume"),
			TargetDev:     r.String("target_dev"),
		}
	}
	return disks, nil
}

// CountVMsByHost returns the number of active VMs per host in a single query.
func CountVMsByHost(ctx context.Context, c *Client) (map[string]int, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, COUNT(*) as cnt FROM vms WHERE deleted_at IS NULL GROUP BY host_name`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(rows))
	for _, r := range rows {
		m[r.String("host_name")] = r.Int("cnt")
	}
	return m, nil
}

// HostResourceUsage holds aggregated CPU, memory, and disk allocated to VMs on a host.
type HostResourceUsage struct {
	CpuUsed     int
	MemUsedMiB  int
	DiskUsedGiB int
}

// SumVMResourcesByHost returns per-host CPU, memory, and disk totals for running VMs.
func SumVMResourcesByHost(ctx context.Context, c *Client) (map[string]HostResourceUsage, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, COALESCE(SUM(cpu_actual),0) as cpu, COALESCE(SUM(mem_actual),0) as mem
		 FROM vms WHERE deleted_at IS NULL AND state = 'running' GROUP BY host_name`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]HostResourceUsage, len(rows))
	for _, r := range rows {
		m[r.String("host_name")] = HostResourceUsage{
			CpuUsed:    r.Int("cpu"),
			MemUsedMiB: r.Int("mem"),
		}
	}

	// Sum disk allocations per host (all VMs, not just running — disk is allocated regardless of state).
	diskRows, err := c.Query(ctx,
		`SELECT host_name, COALESCE(SUM(size_bytes),0) as disk_bytes
		 FROM vm_disks WHERE deleted_at IS NULL GROUP BY host_name`)
	if err == nil {
		for _, r := range diskRows {
			host := r.String("host_name")
			usage := m[host]
			usage.DiskUsedGiB = r.Int("disk_bytes") / (1024 * 1024 * 1024)
			m[host] = usage
		}
	}
	return m, nil
}

// VMStateCount holds per-state VM counts.
type VMStateCount struct {
	Total, Running, Stopped, Error int
}

// CountVMsByStack returns per-stack VM counts and state breakdown in a single query.
func CountVMsByStack(ctx context.Context, c *Client) (map[string]VMStateCount, error) {
	rows, err := c.Query(ctx,
		`SELECT stack_name, state, COUNT(*) as cnt FROM vms
		 WHERE deleted_at IS NULL AND stack_name != ''
		 GROUP BY stack_name, state`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]VMStateCount)
	for _, r := range rows {
		stack := r.String("stack_name")
		sc := m[stack]
		cnt := r.Int("cnt")
		sc.Total += cnt
		switch r.String("state") {
		case "running":
			sc.Running += cnt
		case "stopped":
			sc.Stopped += cnt
		case "error":
			sc.Error += cnt
		}
		m[stack] = sc
	}
	return m, nil
}

// BatchGetVMInterfaces returns interfaces for all active VMs in a single query,
// keyed by vm_name.
func BatchGetVMInterfaces(ctx context.Context, c *Client) (map[string][]InterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT i.vm_name, i.network_name, i.ordinal, i.mac, i.ip, i.tap_device
		 FROM vm_interfaces i
		 INNER JOIN vms v ON v.name = i.vm_name AND v.deleted_at IS NULL
		 WHERE i.deleted_at IS NULL
		 ORDER BY i.vm_name, i.ordinal`)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]InterfaceRecord)
	for _, r := range rows {
		vmName := r.String("vm_name")
		m[vmName] = append(m[vmName], InterfaceRecord{
			VMName:      vmName,
			NetworkName: r.String("network_name"),
			Ordinal:     r.Int("ordinal"),
			MAC:         r.String("mac"),
			IP:          r.String("ip"),
			TapDevice:   r.String("tap_device"),
		})
	}
	return m, nil
}

// CountVMsByNetwork returns the number of active VMs per network in a single query.
func CountVMsByNetwork(ctx context.Context, c *Client) (map[string]int, error) {
	rows, err := c.Query(ctx,
		`SELECT i.network_name, COUNT(DISTINCT i.vm_name) as cnt
		 FROM vm_interfaces i
		 INNER JOIN vms v ON v.name = i.vm_name AND v.deleted_at IS NULL
		 WHERE i.deleted_at IS NULL
		 GROUP BY i.network_name`)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(rows))
	for _, r := range rows {
		m[r.String("network_name")] = r.Int("cnt")
	}
	return m, nil
}

// UpdateVMState changes a VM's state.
func UpdateVMState(ctx context.Context, c *Client, name, state, detail string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vms SET state = ?, state_detail = ?, updated_at = ? WHERE name = ?`,
		state, detail, now, name,
	)
}

// UpdateVMHost moves a VM's host assignment and state after migration.
func UpdateVMHost(ctx context.Context, c *Client, name, hostName, state string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vms SET host_name = ?, state = ?, state_detail = '', updated_at = ? WHERE name = ?`,
		hostName, state, now, name,
	)
}

// DeleteVM tombstones a VM and its interfaces/disks.
func DeleteVM(ctx context.Context, c *Client, name string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: `UPDATE vms SET deleted_at = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{now, now, name}},
		{SQL: `UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`, Params: []interface{}{now, now, name}},
		{SQL: `UPDATE vm_disks SET deleted_at = ?, updated_at = ? WHERE vm_name = ?`, Params: []interface{}{now, now, name}},
	})
}

// RenameVM changes a VM's name across all tables, including the name embedded in
// the stored spec JSON — otherwise spec.name keeps the old name and later XML +
// firmware-path derivation (which use spec.Name) target the wrong VM (G1).
func RenameVM(ctx context.Context, c *Client, oldName, newName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// Patch the spec JSON's "name" via a generic map (keeps this layer pb-free).
	vmsUpdate := Statement{SQL: `UPDATE vms SET name = ?, updated_at = ? WHERE name = ?`,
		Params: []interface{}{newName, now, oldName}}
	if vm, err := GetVM(ctx, c, oldName); err == nil && vm != nil && vm.Spec != "" {
		var m map[string]interface{}
		if json.Unmarshal([]byte(vm.Spec), &m) == nil {
			m["name"] = newName
			if b, mErr := json.Marshal(m); mErr == nil {
				vmsUpdate = Statement{SQL: `UPDATE vms SET name = ?, spec = ?, updated_at = ? WHERE name = ?`,
					Params: []interface{}{newName, string(b), now, oldName}}
			}
		}
	}
	return c.ExecuteBatch(ctx, []Statement{
		vmsUpdate,
		{SQL: `UPDATE vm_interfaces SET vm_name = ?, updated_at = ? WHERE vm_name = ?`,
			Params: []interface{}{newName, now, oldName}},
		{SQL: `UPDATE vm_disks SET vm_name = ?, updated_at = ? WHERE vm_name = ?`,
			Params: []interface{}{newName, now, oldName}},
		{SQL: `UPDATE ip_allocations SET vm_name = ?, updated_at = ? WHERE vm_name = ?`,
			Params: []interface{}{newName, now, oldName}},
	})
}

// UpdateVMInterfaceIP sets the IP of a VM interface.
func UpdateVMInterfaceIP(ctx context.Context, c *Client, vmName, networkName, ip string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_interfaces SET ip = ?, updated_at = ? WHERE vm_name = ? AND network_name = ?`,
		ip, now, vmName, networkName,
	)
}

// InsertDisk adds a single disk record (used by hot-plug attach).
func InsertDisk(ctx context.Context, c *Client, d DiskRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_disks
		 (vm_name, disk_name, host_name, path, size_bytes, backing_image,
		  storage_type, storage_volume, target_dev, backing_disk, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		d.VMName, d.DiskName, d.HostName, d.Path, d.SizeBytes, d.BackingImage,
		d.StorageType, d.StorageVolume, d.TargetDev, d.BackingDisk, now)
}

// UpdateDiskHostAndPath updates the host and path for a disk after migration.
func UpdateDiskHostAndPath(ctx context.Context, c *Client, vmName, diskName, hostName, path string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_disks SET host_name = ?, path = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		hostName, path, now, vmName, diskName)
}

// UpdateDiskStorage updates storage_type and storage_volume after a
// MoveVolume operation. The path is updated separately via
// UpdateDiskHostAndPath since motion can land within the same host.
func UpdateDiskStorage(ctx context.Context, c *Client, vmName, diskName, storageType, storageVolume string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_disks SET storage_type = ?, storage_volume = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		storageType, storageVolume, now, vmName, diskName)
}

// UpdateDiskSize updates the size_bytes for a disk.
func UpdateDiskSize(ctx context.Context, c *Client, vmName, diskName string, sizeBytes int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_disks SET size_bytes = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		sizeBytes, now, vmName, diskName)
}

// UpdateVMDiskPath updates the on-disk path recorded for a disk. Used to
// reconcile the recorded path to the live domain's active disk source after a
// snapshot operation moves the domain onto an overlay (e.g. <disk>.<snapname>).
func UpdateVMDiskPath(ctx context.Context, c *Client, vmName, diskName, path string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_disks SET path = ?, updated_at = ?
		 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`,
		path, now, vmName, diskName)
}

// SoftDeleteDisk marks a disk as deleted.
func SoftDeleteDisk(ctx context.Context, c *Client, vmName, diskName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_disks SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND disk_name = ?`,
		now, now, vmName, diskName)
}

// ListDisks returns all disks for a VM (alias for GetVMDisks).
func ListDisks(ctx context.Context, c *Client, vmName string) ([]DiskRecord, error) {
	return GetVMDisks(ctx, c, vmName)
}

// InsertInterface adds a single interface record (used by hot-plug attach).
func InsertInterface(ctx context.Context, c *Client, i InterfaceRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_interfaces
		 (vm_name, network_name, ordinal, mac, ip, tap_device, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		i.VMName, i.NetworkName, i.Ordinal, i.MAC, i.IP, i.TapDevice, now)
}

// UpdateVMSpec updates the spec JSON and actual CPU/memory for a stopped VM.
func UpdateVMSpec(ctx context.Context, c *Client, name, specJSON string, cpu, mem int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vms SET spec = ?, cpu_actual = ?, mem_actual = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`,
		specJSON, cpu, mem, now, name,
	)
}

// SoftDeleteInterfaceByMAC marks an interface as deleted by MAC address.
func SoftDeleteInterfaceByMAC(ctx context.Context, c *Client, vmName, mac string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND mac = ?`,
		now, now, vmName, mac)
}
