// wrappers around the go-libvirt block-job API so the
// gRPC layer can drive a live storage motion without re-implementing
// the RPC boilerplate.
package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// BlockJobStatus is a small typed view of go-libvirt's progress
// counters. Cur ≥ End signals the mirror is fully synced and ready to
// pivot.
type BlockJobStatus struct {
	Found     bool
	Type      int32
	Bandwidth uint64
	Cur       uint64
	End       uint64
}

// StartBlockCopy launches a libvirt block-copy job that mirrors disk
// (the source dev path inside the domain XML, e.g. "vda" or
// "/var/lib/litevirt/disks/vm1-root.qcow2") into destXML's <source>.
//
// destXML is a small disk-element snippet libvirt accepts:
//
//	<disk type="file" device="disk">
//	  <source file="/path/to/dest.qcow2"/>
//	  <driver type="qcow2"/>
//	</disk>
//
// flags is the OR of DomainBlockCopyFlags (Reuse_Ext + Transient_Job
// in the typical case). We pass through to go-libvirt verbatim.
func (c *Client) StartBlockCopy(domain, disk, destXML string, flags uint32) error {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	return c.virt.DomainBlockCopy(dom, disk, destXML, nil, golibvirt.DomainBlockCopyFlags(flags))
}

// BlockJobStatus returns the current progress of an in-flight job on
// (domain, disk). Found=false means no job is in progress (already
// pivoted or never started).
func (c *Client) BlockJobStatus(domain, disk string) (BlockJobStatus, error) {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return BlockJobStatus{}, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	found, typ, bw, cur, end, err := c.virt.DomainGetBlockJobInfo(dom, disk, 0)
	if err != nil {
		return BlockJobStatus{}, fmt.Errorf("get block job info: %w", err)
	}
	return BlockJobStatus{Found: found != 0, Type: typ, Bandwidth: bw, Cur: cur, End: end}, nil
}

// PivotBlockCopy completes the live mirror by atomically swapping the
// VM's source to the destination. After this returns the original
// disk file is no longer in use and can be deleted.
func (c *Client) PivotBlockCopy(domain, disk string) error {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	return c.virt.DomainBlockJobAbort(dom, disk, golibvirt.DomainBlockJobAbortPivot)
}

// CancelBlockCopy aborts the mirror without pivoting. Used as the
// rollback path when the orchestration logic decides to bail.
func (c *Client) CancelBlockCopy(domain, disk string) error {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	return c.virt.DomainBlockJobAbort(dom, disk, golibvirt.DomainBlockJobAbortAsync)
}
