package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// SetVCPUs hot-adds or reduces vCPUs on a running domain.
// Only increases are supported on most hypervisors; reductions require guest cooperation.
func (c *Client) SetVCPUs(name string, count int) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := c.virt.DomainSetVcpusFlags(dom, uint32(count), uint32(golibvirt.DomainAffectLive)); err != nil {
		return fmt.Errorf("setvcpus %s to %d (live): %w", name, count, err)
	}
	// Also update the config so it persists across reboots.
	c.virt.DomainSetVcpusFlags(dom, uint32(count), uint32(golibvirt.DomainAffectConfig)) //nolint:errcheck
	return nil
}

// SetMemoryMiB hot-adds memory to a running domain.
// Memory can only be increased up to the max memory configured at domain creation.
func (c *Client) SetMemoryMiB(name string, mib int) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	kib := uint64(mib) * 1024
	if err := c.virt.DomainSetMemoryFlags(dom, kib, uint32(golibvirt.DomainMemLive)); err != nil {
		return fmt.Errorf("setmem %s to %d MiB (live): %w", name, mib, err)
	}
	// Also update the config so it persists across reboots.
	c.virt.DomainSetMemoryFlags(dom, kib, uint32(golibvirt.DomainMemConfig)) //nolint:errcheck
	return nil
}

// BlockResize live-resizes a block device on a running domain.
// The path should match the disk's source file as seen in the domain XML.
// sizeBytes is the new total size in bytes.
func (c *Client) BlockResize(domainName, path string, sizeBytes int64) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	// DomainBlockResize expects size in kibibytes by default.
	sizeKiB := uint64(sizeBytes / 1024)
	if err := c.virt.DomainBlockResize(dom, path, sizeKiB, 0); err != nil {
		return fmt.Errorf("block resize %s on %s: %w", path, domainName, err)
	}
	return nil
}

// CanHotModify checks if the spec change is limited to CPU/memory increases
// (which can be applied live). Returns true if hot-modify is possible.
func CanHotModify(oldCPU, oldMem, newCPU, newMem int) (bool, string) {
	if newCPU < oldCPU {
		return false, "CPU reduction not supported for hot-modify"
	}
	if newMem < oldMem {
		return false, "memory reduction not supported for hot-modify"
	}
	if newCPU == oldCPU && newMem == oldMem {
		return false, "no change"
	}
	return true, ""
}
