package libvirt

import (
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// Golden-file coverage for GenerateDomainXML. Each fixture pins a
// rendering surface that real Proxmox refugees lean on (UEFI vs BIOS,
// VNC vs SPICE, CPU pinning, NUMA, PCI passthrough, multi-disk,
// macvtap direct attach, VLAN tagging). Update with `go test
// ./internal/libvirt/ -run TestGenerateDomainXMLGolden -update`.
func TestGenerateDomainXMLGolden(t *testing.T) {
	cases := []struct {
		name string
		path string
		cfg  VMConfig
	}{
		{
			name: "minimal_uefi_vnc",
			path: "testdata/xmlgen_minimal.golden",
			cfg: VMConfig{
				Name:      "vm-min",
				CPU:       2,
				MemoryMiB: 1024,
				EnableVNC: true,
				Disks: []DiskConfig{
					{Name: "root", Path: "/var/lib/litevirt/disks/vm-min/root.qcow2", Bus: "virtio", Cache: "none"},
				},
				Networks: []NetworkConfig{
					{Bridge: "br0", Model: "virtio", MAC: "52:54:00:11:22:33"},
				},
			},
		},
		{
			name: "bios_two_disks_vlan",
			path: "testdata/xmlgen_bios_vlan.golden",
			cfg: VMConfig{
				Name:      "vm-bios",
				CPU:       4,
				MemoryMiB: 4096,
				Firmware:  "bios",
				Boot:      "disk",
				EnableVNC: true,
				Disks: []DiskConfig{
					{Name: "root", Path: "/data/vm-bios/root.qcow2", Bus: "virtio", Cache: "none"},
					{Name: "data", Path: "/data/vm-bios/data.qcow2", Bus: "scsi", Cache: "writeback"},
				},
				Networks: []NetworkConfig{
					{Bridge: "br-prod", Model: "virtio", MAC: "52:54:00:aa:bb:cc", VLAN: 206},
				},
			},
		},
		{
			name: "spice_pci_passthrough",
			path: "testdata/xmlgen_spice_pci.golden",
			cfg: VMConfig{
				Name:        "vm-gpu",
				CPU:         8,
				MemoryMiB:   16384,
				CPUMode:     "host-passthrough",
				EnableVNC:   true,
				EnableSPICE: true,
				HugePages:   true,
				CPUPinning:  []int{0, 1, 2, 3},
				IOThreads:   2,
				NUMAPolicy:  &NUMAPolicy{PreferredNode: 0, Strict: true},
				Disks: []DiskConfig{
					{Name: "root", Path: "/data/vm-gpu/root.qcow2", Bus: "virtio", Cache: "none"},
				},
				Networks: []NetworkConfig{
					{Bridge: "br0", Model: "virtio", MAC: "52:54:00:de:ad:be"},
				},
				Hostdevs: []HostdevConfig{
					{Address: "0000:41:00.0"},
				},
			},
		},
		{
			name: "macvtap_direct_with_iso",
			path: "testdata/xmlgen_macvtap_iso.golden",
			cfg: VMConfig{
				Name:         "vm-direct",
				CPU:          2,
				MemoryMiB:    2048,
				EnableVNC:    true,
				CloudInitISO: "/var/lib/litevirt/cloudinit/vm-direct.iso",
				Boot:         "disk",
				Disks: []DiskConfig{
					{Name: "root", Path: "/data/vm-direct/root.qcow2", Bus: "virtio", Cache: "none"},
				},
				Networks: []NetworkConfig{
					{Direct: "bond0.206", Model: "virtio", MAC: "52:54:00:33:44:55"},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateDomainXML(tc.cfg)
			if err != nil {
				t.Fatalf("GenerateDomainXML: %v", err)
			}
			golden.Assert(t, tc.path, got)
		})
	}
}
