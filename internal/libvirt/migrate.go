package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// MigrateParams configures migration behaviour.
type MigrateParams struct {
	Live          bool
	WithStorage   bool
	BandwidthMiB  int
	AutoConverge  bool     // enable auto-converge (throttle vCPUs to help convergence)
	MaxDowntimeMS int64    // max downtime in ms during cutover (0 = libvirt default)
	TargetAddress string   // target host IP/hostname for explicit migrate_uri (non-tunnelled)
	DiskTargets   []string // disk target devices to migrate (e.g. "vda"); empty = all
}

// MigrateToTarget performs a live (or cold) P2P migration of a domain to
// the given destination libvirt URI (e.g. "qemu+tls://10.0.0.2/system").
// When WithStorage is true, disk contents are copied alongside memory
// (MigrateNonSharedDisk), enabling migration of VMs with local disks.
// The call blocks until migration completes or fails.
func (c *Client) MigrateToTarget(name, dconnuri string, p MigrateParams) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}

	flags := golibvirt.MigratePeer2peer |
		golibvirt.MigratePersistDest |
		golibvirt.MigrateUndefineSource

	if p.Live {
		flags |= golibvirt.MigrateLive
		if p.AutoConverge {
			flags |= golibvirt.MigrateAutoConverge
		}
	}

	if p.WithStorage {
		// QEMU doesn't support tunnelled + non-shared disk together.
		// Without tunnelling, QEMU opens a direct TLS connection to the
		// target for block copy (uses migration port range, default 49152-49215).
		flags |= golibvirt.MigrateNonSharedDisk
		// libvirt's qemuMigrationSrcIsSafe rejects a non-shared-storage
		// migration ("Migration without shared storage is unsafe") whenever a
		// disk's cache mode isn't none/directsync — and our generated domains
		// use cache='writeback'. With NonSharedDisk the disk content IS copied
		// over the NBD block-mirror channel, so the cache-coherency concern
		// that gate guards against doesn't apply; assert that explicitly.
		flags |= golibvirt.MigrateUnsafe
	} else {
		// Memory-only migration can be tunnelled through the single
		// libvirt TLS connection (port 16514) — no extra ports needed.
		flags |= golibvirt.MigrateTunnelled
	}

	// Set max downtime before starting migration.
	if p.MaxDowntimeMS > 0 {
		_ = c.virt.DomainMigrateSetMaxDowntime(dom, uint64(p.MaxDowntimeMS), 0)
	}

	var params []golibvirt.TypedParam
	if p.BandwidthMiB > 0 {
		params = append(params, golibvirt.TypedParam{
			Field: "bandwidth",
			Value: golibvirt.TypedParamValue{I: uint64(p.BandwidthMiB)},
		})
	}

	// For non-tunnelled migration (--with-storage), provide an explicit
	// migrate_uri so the target listens on the right address and QEMU
	// can establish the NBD data channel for disk copy.
	if p.WithStorage && p.TargetAddress != "" {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamURI,
			Value: *golibvirt.NewTypedParamValueString(fmt.Sprintf("tcp://%s", p.TargetAddress)),
		})
	}

	// When specific disk targets are provided, tell libvirt which disks to
	// block-copy — this avoids copying read-only devices like CDROMs.
	for _, dt := range p.DiskTargets {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamMigrateDisks,
			Value: *golibvirt.NewTypedParamValueString(dt),
		})
	}

	_, err = c.virt.DomainMigratePerform3Params(
		dom,
		[]string{dconnuri}, // OptString
		params,
		nil, // cookieIn
		flags,
	)
	return err
}

// DomainJobProgress returns the memory and disk migration progress (0–100)
// for a running migration, or -1 if no migration job is active.
func (c *Client) DomainJobProgress(name string) (memPct, diskPct float32) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return -1, -1
	}
	_, _, _, _, _, _, rMemTotal, rMemProcessed, _, rFileTotal, rFileProcessed, _, err := c.virt.DomainGetJobInfo(dom)
	if err != nil || rMemTotal == 0 {
		return -1, -1
	}
	memPct = float32(rMemProcessed) / float32(rMemTotal) * 100
	if rFileTotal > 0 {
		diskPct = float32(rFileProcessed) / float32(rFileTotal) * 100
	}
	return memPct, diskPct
}
