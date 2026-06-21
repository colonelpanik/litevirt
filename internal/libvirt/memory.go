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

// SetMemory sets the balloon target (current memory) of a domain in MiB. For a
// running VM this drives the virtio balloon live AND persists to config so a
// restart keeps the target; the value must not exceed the domain's maxMemory.
// For a stopped VM it updates the persistent config only.
func (c *Client) SetMemory(domainName string, memMiB int) error {
	if memMiB <= 0 {
		return fmt.Errorf("invalid memory target %d MiB", memMiB)
	}
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	flags := uint32(domainMemAffectConfig)
	if state, _, sErr := c.virt.DomainGetState(dom, 0); sErr == nil && state == int32(golibvirt.DomainRunning) {
		flags |= domainMemAffectLive
	}
	// libvirt takes KiB.
	if err := c.virt.DomainSetMemoryFlags(dom, uint64(memMiB)*1024, flags); err != nil {
		return fmt.Errorf("set memory %q to %d MiB: %w", domainName, memMiB, err)
	}
	return nil
}
