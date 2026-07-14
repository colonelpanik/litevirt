package corrosion

import (
	"context"
)

// pciSelectCols is the common column list for PCI device queries.
const pciSelectCols = `host_name, address, vendor_id, device_id, vendor_name, device_name,
	type, iommu_group, sriov_capable, sriov_vfs_total, sriov_vfs_free,
	driver, vm_name, numa_node, pcie_root_port, pcie_bridge, link_clique, link_peers`

// PCIDeviceRecord represents a row in the host_pci_devices table.
type PCIDeviceRecord struct {
	HostName      string
	Address       string
	VendorID      string
	DeviceID      string
	VendorName    string
	DeviceName    string
	Type          string // gpu | network | nvme | infiniband | other
	IOMMUGroup    int
	SRIOVCapable  bool
	SRIOVVFsTotal int
	SRIOVVFsFree  int
	Driver        string
	VMName        string
	NUMANode      int

	// PCIe topology
	PCIeRootPort string
	PCIeBridge   string
	LinkClique   string
	LinkPeers    string // comma-separated PCI addresses
}

// UpsertPCIDevice inserts or fully replaces a PCI device record, INCLUDING
// vm_name. 🔴 Do NOT use this on a host scan / rescan path: a scan carries no
// vm_name, so INSERT OR REPLACE would erase the assignment of an owned device.
// Scan/observation paths MUST use ObservePCIDevice (preserves vm_name). This
// full-replace form is for genuine full-record writes and test seeding only.
func UpsertPCIDevice(ctx context.Context, c *Client, d PCIDeviceRecord) error {
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO host_pci_devices
		 (host_name, address, vendor_id, device_id, vendor_name, device_name,
		  type, iommu_group, sriov_capable, sriov_vfs_total, sriov_vfs_free,
		  driver, vm_name, numa_node, pcie_root_port, pcie_bridge, link_clique,
		  link_peers, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		d.HostName, d.Address, d.VendorID, d.DeviceID, d.VendorName, d.DeviceName,
		d.Type, d.IOMMUGroup, d.SRIOVCapable, d.SRIOVVFsTotal, d.SRIOVVFsFree,
		d.Driver, d.VMName, d.NUMANode, d.PCIeRootPort, d.PCIeBridge, d.LinkClique,
		d.LinkPeers, c.NowTS())
}

// ObservePCIDevice records a device's HARDWARE facts from a host scan while
// PRESERVING any existing vm_name assignment: a rescan must never erase which VM
// owns a device (the bug that INSERT OR REPLACE + an empty scan vm_name caused).
// A never-seen device is inserted UNASSIGNED; an existing row keeps its vm_name
// and is revived (deleted_at cleared) if it had disappeared. Ownership is changed
// only through Assign/Release/Claim, never through observation. Only the owning
// host observes its own PCI rows.
func ObservePCIDevice(ctx context.Context, c *Client, d PCIDeviceRecord) error {
	return c.Execute(ctx,
		`INSERT INTO host_pci_devices
		   (host_name, address, vendor_id, device_id, vendor_name, device_name,
		    type, iommu_group, sriov_capable, sriov_vfs_total, sriov_vfs_free,
		    driver, vm_name, numa_node, pcie_root_port, pcie_bridge, link_clique,
		    link_peers, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(host_name, address) DO UPDATE SET
		    vendor_id       = excluded.vendor_id,
		    device_id       = excluded.device_id,
		    vendor_name     = excluded.vendor_name,
		    device_name     = excluded.device_name,
		    type            = excluded.type,
		    iommu_group     = excluded.iommu_group,
		    sriov_capable   = excluded.sriov_capable,
		    sriov_vfs_total = excluded.sriov_vfs_total,
		    sriov_vfs_free  = excluded.sriov_vfs_free,
		    driver          = excluded.driver,
		    numa_node       = excluded.numa_node,
		    pcie_root_port  = excluded.pcie_root_port,
		    pcie_bridge     = excluded.pcie_bridge,
		    link_clique     = excluded.link_clique,
		    link_peers      = excluded.link_peers,
		    updated_at      = excluded.updated_at,
		    deleted_at      = NULL`,
		// vm_name is deliberately absent from DO UPDATE SET — it is preserved.
		d.HostName, d.Address, d.VendorID, d.DeviceID, d.VendorName, d.DeviceName,
		d.Type, d.IOMMUGroup, d.SRIOVCapable, d.SRIOVVFsTotal, d.SRIOVVFsFree,
		d.Driver, d.NUMANode, d.PCIeRootPort, d.PCIeBridge, d.LinkClique,
		d.LinkPeers, c.NowTS())
}

func scanPCIDevice(r Row) PCIDeviceRecord {
	return PCIDeviceRecord{
		HostName:      r.String("host_name"),
		Address:       r.String("address"),
		VendorID:      r.String("vendor_id"),
		DeviceID:      r.String("device_id"),
		VendorName:    r.String("vendor_name"),
		DeviceName:    r.String("device_name"),
		Type:          r.String("type"),
		IOMMUGroup:    r.Int("iommu_group"),
		SRIOVCapable:  r.Int("sriov_capable") != 0,
		SRIOVVFsTotal: r.Int("sriov_vfs_total"),
		SRIOVVFsFree:  r.Int("sriov_vfs_free"),
		Driver:        r.String("driver"),
		VMName:        r.String("vm_name"),
		NUMANode:      r.Int("numa_node"),
		PCIeRootPort:  r.String("pcie_root_port"),
		PCIeBridge:    r.String("pcie_bridge"),
		LinkClique:    r.String("link_clique"),
		LinkPeers:     r.String("link_peers"),
	}
}

// ListPCIDevices returns all PCI devices for a host, optionally filtered by type.
func ListPCIDevices(ctx context.Context, c *Client, hostName, typeFilter string) ([]PCIDeviceRecord, error) {
	query := `SELECT ` + pciSelectCols + `
	          FROM host_pci_devices WHERE host_name = ? AND deleted_at IS NULL`
	args := []any{hostName}
	if typeFilter != "" {
		query += " AND type = ?"
		args = append(args, typeFilter)
	}
	query += " ORDER BY address"

	rows, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	devices := make([]PCIDeviceRecord, len(rows))
	for i, r := range rows {
		devices[i] = scanPCIDevice(r)
	}
	return devices, nil
}

// AssignPCIDevice marks a PCI device as assigned to a VM.
func AssignPCIDevice(ctx context.Context, c *Client, hostName, address, vmName string) error {
	return c.Execute(ctx,
		`UPDATE host_pci_devices SET vm_name = ?, updated_at = ?
		 WHERE host_name = ? AND address = ?`,
		vmName, c.NowTS(), hostName, address)
}

// ReleasePCIDevicesByVM clears all device assignments for a given VM.
func ReleasePCIDevicesByVM(ctx context.Context, c *Client, vmName string) error {
	return c.Execute(ctx,
		`UPDATE host_pci_devices SET vm_name = NULL, updated_at = ?
		 WHERE vm_name = ?`,
		c.NowTS(), vmName)
}

// ReleasePCIDevice clears the VM assignment for a single PCI device.
func ReleasePCIDevice(ctx context.Context, c *Client, hostName, address string) error {
	return c.Execute(ctx,
		`UPDATE host_pci_devices SET vm_name = NULL, updated_at = ?
		 WHERE host_name = ? AND address = ?`,
		c.NowTS(), hostName, address)
}

// SoftDeletePCIDevice marks a device as deleted (disappeared from host).
func SoftDeletePCIDevice(ctx context.Context, c *Client, hostName, address string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE host_pci_devices SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND address = ?`,
		nowRFC3339(), now, hostName, address)
}

// GetAvailableDevicesByType returns unassigned devices of a given type on a host.
func GetAvailableDevicesByType(ctx context.Context, c *Client, hostName, devType string) ([]PCIDeviceRecord, error) {
	query := `SELECT ` + pciSelectCols + `
	          FROM host_pci_devices
	          WHERE host_name = ? AND type = ? AND (vm_name IS NULL OR vm_name = '')
	          AND deleted_at IS NULL ORDER BY address`
	rows, err := c.Query(ctx, query, hostName, devType)
	if err != nil {
		return nil, err
	}
	devices := make([]PCIDeviceRecord, len(rows))
	for i, r := range rows {
		devices[i] = scanPCIDevice(r)
	}
	return devices, nil
}

// GetAvailableDevicesWithTopology returns unassigned devices ordered by topology
// (root port, bridge, address) for placement scoring.
// If devType is empty, all types are returned.
func GetAvailableDevicesWithTopology(ctx context.Context, c *Client, hostName, devType string) ([]PCIDeviceRecord, error) {
	query := `SELECT ` + pciSelectCols + `
	          FROM host_pci_devices
	          WHERE host_name = ? AND (vm_name IS NULL OR vm_name = '')
	          AND deleted_at IS NULL`
	args := []any{hostName}
	if devType != "" {
		query += " AND type = ?"
		args = append(args, devType)
	}
	query += " ORDER BY pcie_root_port, pcie_bridge, address"
	rows, err := c.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	devices := make([]PCIDeviceRecord, len(rows))
	for i, r := range rows {
		devices[i] = scanPCIDevice(r)
	}
	return devices, nil
}

// GetDevicesByIOMMUGroup returns all devices in a given IOMMU group on a host.
func GetDevicesByIOMMUGroup(ctx context.Context, c *Client, hostName string, group int) ([]PCIDeviceRecord, error) {
	query := `SELECT ` + pciSelectCols + `
	          FROM host_pci_devices
	          WHERE host_name = ? AND iommu_group = ? AND deleted_at IS NULL ORDER BY address`
	rows, err := c.Query(ctx, query, hostName, group)
	if err != nil {
		return nil, err
	}
	devices := make([]PCIDeviceRecord, len(rows))
	for i, r := range rows {
		devices[i] = scanPCIDevice(r)
	}
	return devices, nil
}
