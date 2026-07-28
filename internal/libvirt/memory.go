package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// libvirt VIR_DOMAIN_MEM_* / VIR_DOMAIN_AFFECT_* flag values. Not all are
// exported as typed constants by this go-libvirt version, so we pin the
// numeric API values here.
const (
	domainMemAffectLive   = 1 // VIR_DOMAIN_AFFECT_LIVE
	domainMemAffectConfig = 2 // VIR_DOMAIN_AFFECT_CONFIG
)

// SetMemory sets the balloon target (current memory) of a domain in MiB. It
// applies the PERSISTENT config first and propagates that error BEFORE driving the
// live balloon — a live balloon change that a restart discards is worse than a
// refused resize — then drives the virtio balloon live when the domain is running.
// The value must not exceed the domain's maxMemory. For a stopped VM it updates
// the persistent config only. The live balloon converges asynchronously (the guest
// cooperates), so the set call succeeding is the available live-view confirmation;
// the observed actual is reconciled from stats afterward.
func (c *Client) SetMemory(domainName string, memMiB int) error {
	if memMiB <= 0 {
		return fmt.Errorf("invalid memory target %d MiB", memMiB)
	}
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	kib := uint64(memMiB) * 1024
	// CONFIG first — propagate so a live balloon never applies on top of a persistent
	// write that libvirt rejected (e.g. above maxMemory).
	if err := c.virt.DomainSetMemoryFlags(dom, kib, uint32(domainMemAffectConfig)); err != nil {
		return fmt.Errorf("set memory %q to %d MiB (config): %w", domainName, memMiB, err)
	}
	if state, _, sErr := c.virt.DomainGetState(dom, 0); sErr == nil && state == int32(golibvirt.DomainRunning) {
		if err := c.virt.DomainSetMemoryFlags(dom, kib, uint32(domainMemAffectLive)); err != nil {
			return fmt.Errorf("set memory %q to %d MiB (live): %w", domainName, memMiB, err)
		}
	}
	return nil
}
