package libvirt

import "fmt"

// FreezeGuest asks the qemu-guest-agent to freeze all guest filesystems so a
// backup or snapshot taken immediately after is application-consistent. The
// guest must be running and have a working guest agent; otherwise libvirt
// returns an error and the caller proceeds crash-consistent. Always pair with
// ThawGuest (defer it) — a guest left frozen will hang on I/O.
func (c *Client) FreezeGuest(domainName string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	// nil mountpoints = freeze every filesystem; flags must be 0.
	if _, err := c.virt.DomainFsfreeze(dom, nil, 0); err != nil {
		return fmt.Errorf("fs-freeze %q: %w", domainName, err)
	}
	return nil
}

// ThawGuest unfreezes guest filesystems frozen by FreezeGuest. Safe to call
// even if nothing is frozen (libvirt reports 0 thawed). Errors are returned so
// the caller can log them, but a backup must never fail because thaw failed —
// it just means the guest agent will eventually time out the freeze itself.
func (c *Client) ThawGuest(domainName string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	if _, err := c.virt.DomainFsthaw(dom, nil, 0); err != nil {
		return fmt.Errorf("fs-thaw %q: %w", domainName, err)
	}
	return nil
}
