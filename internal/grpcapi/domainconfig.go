package grpcapi

import (
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// baseDomainConfig assembles the libvirt VMConfig fields that MUST be identical
// between CreateVM and a full-regeneration redefine — every field derived from the
// VMSpec. Both paths route through here so they can't diverge again: the old inline
// redefine builder dropped MinMemoryMiB/MaxMemoryMiB (collapsing the balloon ceiling
// to the current memory) and Hostdevs (silently detaching PCI passthrough on any
// `lv update` of a stopped VM).
//
// Disks, networks, and hostdevs are passed in because their SOURCING differs:
// CreateVM allocates brand-new devices, while a redefine rebuilds them from the
// authoritative stored spec + PCI ownership. Firmware/nvram/TPM and the create-time
// cloud-init ISO are applied by the caller (create host-resolves firmware paths and
// refuses to adopt orphaned state; redefine reuses the existing state).
func baseDomainConfig(spec *pb.VMSpec, disks []lv.DiskConfig, nets []lv.NetworkConfig, hostdevs []lv.HostdevConfig) lv.VMConfig {
	cfg := lv.VMConfig{
		Name:         spec.Name,
		UUID:         spec.Uuid,
		CPU:          int(spec.Cpu),
		MaxCPU:       int(spec.MaxCpu),
		CPUMode:      spec.CpuMode,
		MemoryMiB:    int(spec.MemoryMib),
		MinMemoryMiB: int(spec.MinMemoryMib),
		MaxMemoryMiB: int(spec.MaxMemoryMib),
		Machine:      spec.Machine,
		Firmware:     spec.Firmware,
		GuestAgent:   spec.GuestAgent,
		EnableVNC:    !spec.DisableVnc,
		EnableSPICE:  spec.EnableSpice,
		Disks:        disks,
		Networks:     nets,
		Hostdevs:     hostdevs,
		Boot:         spec.Boot,
	}
	if r := spec.Resources; r != nil {
		cfg.HugePages = r.Hugepages
		cfg.IOThreads = int(r.IoThreads)
		for _, pin := range r.CpuPinning {
			cfg.CPUPinning = append(cfg.CPUPinning, int(pin))
		}
		if np := r.NumaPolicy; np != nil {
			cfg.NUMAPolicy = &lv.NUMAPolicy{
				PreferredNode: int(np.PreferredNode),
				Strict:        np.Strict,
			}
		}
	}
	return cfg
}
