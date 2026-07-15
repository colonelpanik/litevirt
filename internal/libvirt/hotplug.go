package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// SetVCPUs sets a domain's vCPU count, PERSISTENT config first (so a lost/failed
// config write is surfaced BEFORE any live change — a live-only grow that doesn't
// survive a reboot is worse than a refused resize), then the live count when the
// domain is running, and finally verifies both views match the target. Only
// increases are reliable live; reductions require guest cooperation.
func (c *Client) SetVCPUs(name string, count int) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	// CONFIG first — propagate the error so a resize never applies live on top of a
	// persistent-config write that didn't take.
	if err := c.virt.DomainSetVcpusFlags(dom, uint32(count), uint32(golibvirt.DomainAffectConfig)); err != nil {
		return fmt.Errorf("setvcpus %s to %d (config): %w", name, count, err)
	}
	running := c.domainRunning(dom)
	if running {
		if err := c.virt.DomainSetVcpusFlags(dom, uint32(count), uint32(golibvirt.DomainAffectLive)); err != nil {
			return fmt.Errorf("setvcpus %s to %d (live): %w", name, count, err)
		}
	}
	// Verify both views converged (config always; live only when running).
	if got, gerr := c.virt.DomainGetVcpusFlags(dom, uint32(golibvirt.DomainAffectConfig)); gerr == nil && int(got) != count {
		return fmt.Errorf("setvcpus %s: config view is %d after setting %d", name, got, count)
	}
	if running {
		if got, gerr := c.virt.DomainGetVcpusFlags(dom, uint32(golibvirt.DomainAffectLive)); gerr == nil && int(got) != count {
			return fmt.Errorf("setvcpus %s: live view is %d after setting %d", name, got, count)
		}
	}
	return nil
}

// domainRunning reports whether dom is in the running state (best-effort: an
// introspection error is treated as not-running so a config-only apply is used).
func (c *Client) domainRunning(dom golibvirt.Domain) bool {
	state, _, err := c.virt.DomainGetState(dom, 0)
	return err == nil && state == int32(golibvirt.DomainRunning)
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
