// (live-restore auto-define) — wrapper around go-libvirt's
// block-pull API. After a VM boots off an NBD-backed qcow2 overlay,
// blockpull flattens the backing chain into the overlay so the disk
// becomes self-contained and the transient NBD source can be torn down.
package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// BlockPull starts a block-pull job on (domain, disk) that streams the
// backing chain into the top overlay. disk is the target dev ("vda") or
// the overlay's source path. Progress is observed via BlockJobStatus
// (shared with block-copy); when the job completes libvirt removes it, so
// a poll that returns Found=false means the disk is fully localized.
func (c *Client) BlockPull(domain, disk string) error {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	if err := c.virt.DomainBlockPull(dom, disk, 0, golibvirt.DomainBlockPullFlags(0)); err != nil {
		return fmt.Errorf("block pull %s/%s: %w", domain, disk, err)
	}
	return nil
}
