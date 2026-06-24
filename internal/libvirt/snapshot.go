package libvirt

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// libvirt VIR_DOMAIN_SAVE_* flag values (not all exported as typed consts by
// this go-libvirt version, so we pin the numeric API values).
const (
	domainSaveRunning = 2 // VIR_DOMAIN_SAVE_RUNNING — restore as running
	domainSavePaused  = 4 // VIR_DOMAIN_SAVE_PAUSED  — save/restore as paused
)

// CreateSnapshot takes an external disk-only snapshot of a VM.
// External snapshots work with UEFI/pflash firmware (no qcow2 nvram required).
// Returns the allocation size (bytes) of the disk at the time of the snapshot.
func (c *Client) CreateSnapshot(domainName, snapshotName string) (int64, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return 0, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	// Get current disk allocation before snapshot — this becomes the snapshot's size.
	allocation, _, _, _ := c.virt.DomainGetBlockInfo(dom, "vda", 0)

	xml := fmt.Sprintf(`<domainsnapshot><name>%s</name></domainsnapshot>`, snapshotName)
	flags := uint32(golibvirt.DomainSnapshotCreateDiskOnly | golibvirt.DomainSnapshotCreateAtomic)
	_, err = c.virt.DomainSnapshotCreateXML(dom, xml, flags)
	if err != nil {
		return 0, err
	}
	return int64(allocation), nil
}

// ListSnapshots returns all snapshot names for a domain.
func (c *Client) ListSnapshots(domainName string) ([]string, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snaps, _, err := c.virt.DomainListAllSnapshots(dom, -1, 0)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(snaps))
	for i, s := range snaps {
		names[i] = s.Name
	}
	return names, nil
}

// RevertToSnapshot reverts a domain to the named external disk-only snapshot.
//
// Libvirt does not support DomainRevertToSnapshot for external disk-only
// snapshots, so we revert manually. The disk revert RESETS the live overlay to
// a fresh empty qcow2 over its (frozen) base — it does NOT swap the domain back
// onto the base path. Swapping makes the restarted domain open the base file
// read-WRITE, which races the just-destroyed domain's read lock on that same
// base (held while the base was the overlay's backing) and fails with "Failed
// to get write lock". Keeping the domain on the overlay leaves the base opened
// read-only exactly as before — no lock conflict. (Same technique as
// RevertToLiveSnapshot, which fixed the identical class of bug.)
func (c *Client) RevertToSnapshot(domainName, snapshotName string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}

	// The snapshot XML embeds the <domain> as it was at snapshot time — its disk
	// <source file/> entries are the (frozen) base paths.
	snapXML, err := c.virt.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	origDisks := parseSnapshotDomainDisks(snapXML) // dev → base (frozen)
	if len(origDisks) == 0 {
		return fmt.Errorf("snapshot %q: no disk sources found in snapshot XML", snapshotName)
	}

	// Current (live) domain XML has the overlay paths the snapshot cut over to.
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	currentDisks := parseDomainDiskSources(domXML) // dev → overlay (live)

	// Each changed disk: reset overlay (live) → empty over base (frozen).
	type overlayReset struct{ overlay, base string }
	var resets []overlayReset
	for dev, base := range origDisks {
		overlay, ok := currentDisks[dev]
		if !ok || overlay == base {
			continue
		}
		resets = append(resets, overlayReset{overlay: overlay, base: base})
	}

	// Inactive XML still references the overlay paths — redefine with it
	// unchanged after the overlays are reset (no path swap).
	inactiveXML, err := c.virt.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive)
	if err != nil {
		inactiveXML = domXML
	}

	// Destroy the running domain — but skip if it's already shut off, so
	// reverting a STOPPED VM works instead of erroring "domain is not running".
	if st, _, sErr := c.virt.DomainGetState(dom, 0); sErr == nil && st != int32(golibvirt.DomainShutoff) {
		if err := c.virt.DomainDestroy(dom); err != nil {
			return fmt.Errorf("destroy domain before revert: %w", err)
		}
		for i := 0; i < 30; i++ {
			dom2, lookupErr := c.virt.DomainLookupByName(domainName)
			if lookupErr != nil {
				break
			}
			state, _, _ := c.virt.DomainGetState(dom2, 0)
			if state == int32(golibvirt.DomainShutoff) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	// Delete snapshot metadata (we manage overlay files ourselves) and undefine
	// to release virtlockd locks.
	_ = c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	if d, e := c.virt.DomainLookupByName(domainName); e == nil {
		_ = c.virt.DomainUndefineFlags(d, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineNvram))
	}
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		if !c.DomainExists(domainName) {
			break
		}
	}
	time.Sleep(time.Second)

	// Disk revert: reset each overlay to an empty qcow2 over its frozen base.
	// All post-snapshot writes (in the old overlay) are discarded.
	for _, r := range resets {
		if err := resetOverlay(r.overlay, r.base); err != nil {
			return fmt.Errorf("reset overlay %q: %w", r.overlay, err)
		}
	}

	// Redefine with the original (overlay-pointing) XML.
	if _, err := c.virt.DomainDefineXML(inactiveXML); err != nil {
		return fmt.Errorf("redefine domain after revert: %w", err)
	}

	// Re-register the snapshot metadata the undefine dropped. Without this the
	// snapshot is GONE from libvirt while still recorded in the cluster DB, so a
	// later "lv snapshot restore" fails with "no domain snapshot with matching
	// name" — permanently unrevertable. Doing it here (before the start) means
	// the snapshot survives even if the start below fails and the operator
	// retries. The overlay is freshly reset over the same base, so the recorded
	// point still holds. Best-effort.
	if redom, lerr := c.virt.DomainLookupByName(domainName); lerr == nil {
		_, _ = c.virt.DomainSnapshotCreateXML(redom, snapXML, uint32(golibvirt.DomainSnapshotCreateRedefine))
	}

	// Start, retrying on any residual lock-release race (the base stays
	// read-only now, so this should not normally trigger).
	var startErr error
	for i := 0; i < 10; i++ {
		if startErr = c.StartDomain(domainName); startErr == nil {
			return nil
		}
		if !strings.Contains(startErr.Error(), "lock") {
			return fmt.Errorf("start domain %s after revert: %w", domainName, startErr)
		}
		if d, e := c.virt.DomainLookupByName(domainName); e == nil {
			_ = c.virt.DomainDestroy(d) // drop any partial lock; keeps the definition
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("start domain %s after revert (disk lock not released after retries): %w", domainName, startErr)
}

// FlattenSnapshot live-merges (block-commit) each disk's active overlay down
// into the named snapshot's base, then deletes the snapshot metadata. After
// this the running VM is on a single standalone disk (the snapshot's base, now
// holding all current data) — no backing chain — so it can be migrated and the
// chain stops growing across snapshot+delete cycles.
//
// We commit only down to THIS snapshot's base (not to the bottom of the chain),
// so a shared/lower base image (e.g. the OS image other VMs share) is never
// touched. RUNNING domains only.
func (c *Client) FlattenSnapshot(domainName, snapshotName string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	if st, _, sErr := c.virt.DomainGetState(dom, 0); sErr != nil || st != int32(golibvirt.DomainRunning) {
		return fmt.Errorf("flatten requires a running domain")
	}
	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}
	snapXML, err := c.virt.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	base := parseSnapshotDomainDisks(snapXML) // dev → base (commit target)
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	cur := parseDomainDiskSources(domXML) // dev → overlay (active)

	for dev, basePath := range base {
		overlay, ok := cur[dev]
		if !ok || overlay == basePath {
			continue // disk has no overlay to merge
		}
		// Active-layer commit: merge the active overlay DOWN into basePath. base
		// is set so the commit stops at this snapshot's base (lower layers, e.g.
		// a shared OS image, are untouched); empty top = the active layer.
		if err := c.virt.DomainBlockCommit(dom, dev,
			golibvirt.OptString{basePath}, golibvirt.OptString{}, 0,
			golibvirt.DomainBlockCommitActive); err != nil {
			return fmt.Errorf("block-commit %s: %w", dev, err)
		}
		if err := c.waitBlockJobReady(dom, dev); err != nil {
			return fmt.Errorf("block-commit %s sync: %w", dev, err)
		}
		// Pivot the active layer onto base, ending the job.
		if err := c.virt.DomainBlockJobAbort(dom, dev, golibvirt.DomainBlockJobAbortPivot); err != nil {
			return fmt.Errorf("pivot %s onto base: %w", dev, err)
		}
		os.Remove(overlay) // committed overlay is no longer referenced
	}

	_ = c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)
	return nil
}

// waitBlockJobReady polls a disk's block job until it has synced (cur >= end),
// the point at which an active-layer commit is ready to pivot. Returns when the
// job is ready or gone; errors only on a query failure or timeout.
func (c *Client) waitBlockJobReady(dom golibvirt.Domain, dev string) error {
	for i := 0; i < 1200; i++ { // ~10 min ceiling for large disks
		found, _, _, curr, end, err := c.virt.DomainGetBlockJobInfo(dom, dev, 0)
		if err != nil {
			return err
		}
		if found == 0 {
			return nil // no active job (already complete)
		}
		if end > 0 && curr >= end {
			return nil // synced — ready to pivot
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("block job on %s did not reach ready state in time", dev)
}

// DeleteSnapshot removes a named snapshot from a domain.
func (c *Client) DeleteSnapshot(domainName, snapshotName string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}

	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}

	return c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteFlags(0))
}

// CreateLiveSnapshot captures both the guest's disks AND its RAM/CPU state at a
// single instant, leaving the VM running. The saved RAM image is written to
// vmstatePath; a later RevertToLiveSnapshot restores both disk and RAM to this
// exact point. Returns (disk allocation bytes, vmstate file bytes).
//
// Sequence (the suspend is the single freeze point, so disk and RAM are the
// same instant):
//  1. suspend the guest
//  2. external disk-only snapshot of the frozen guest (overlay cutover)
//  3. save RAM to vmstatePath (libvirt stops the domain when the save finishes)
//  4. restore from that image as running — the VM resumes with its exact RAM,
//     now writing to the post-snapshot overlay
//
// The VM is unavailable only for the suspend→save→restore window (seconds for
// small guests); it does NOT reboot. Memory snapshots are not compatible with a
// stopped VM — callers must fall back to CreateSnapshot for that case.
func (c *Client) CreateLiveSnapshot(domainName, snapshotName, vmstatePath string) (diskBytes, vmstateBytes int64, err error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	state, _, _ := c.virt.DomainGetState(dom, 0)
	if state != int32(golibvirt.DomainRunning) && state != int32(golibvirt.DomainPaused) {
		return 0, 0, fmt.Errorf("domain %q is not running — memory snapshot requires a running VM", domainName)
	}

	// 1. Freeze point.
	if err := c.virt.DomainSuspend(dom); err != nil {
		return 0, 0, fmt.Errorf("suspend domain %q: %w", domainName, err)
	}
	resumed := false
	// On any early error, best-effort resume so we don't leave the guest paused.
	defer func() {
		if !resumed {
			_ = c.virt.DomainResume(dom)
		}
	}()

	// 2. External disk snapshot of the frozen guest.
	snapXML := fmt.Sprintf(`<domainsnapshot><name>%s</name></domainsnapshot>`, snapshotName)
	flags := uint32(golibvirt.DomainSnapshotCreateDiskOnly | golibvirt.DomainSnapshotCreateAtomic)
	if _, err := c.virt.DomainSnapshotCreateXML(dom, snapXML, flags); err != nil {
		return 0, 0, fmt.Errorf("disk snapshot: %w", err)
	}
	allocation, _, _, _ := c.virt.DomainGetBlockInfo(dom, "vda", 0)

	// 3. Save RAM. This stops the (already-paused) domain and writes the full
	// domain XML (referencing the new overlay paths) into the image.
	if err := c.virt.DomainSaveFlags(dom, vmstatePath, nil, uint32(domainSavePaused)); err != nil {
		return 0, 0, fmt.Errorf("save guest memory: %w", err)
	}

	// 4. Resume from the saved image as running (disks already point at the
	// overlay, so no Dxml override is needed here).
	if err := c.restoreWithRetry(domainName, vmstatePath, ""); err != nil {
		return 0, 0, fmt.Errorf("resume from saved memory: %w", err)
	}
	resumed = true // the domain is running again; the deferred resume is a no-op

	if fi, statErr := os.Stat(vmstatePath); statErr == nil {
		vmstateBytes = fi.Size()
	}
	return int64(allocation), vmstateBytes, nil
}

// RevertToLiveSnapshot reverts disk AND RAM to a memory snapshot taken by
// CreateLiveSnapshot, leaving the VM running at the snapshot instant. All disk
// writes since the snapshot are discarded.
//
// The VM runs on an external overlay whose backing file (the base) was frozen at
// snapshot time, and the saved RAM image references that overlay path. To revert
// we RESET the overlay to empty (a fresh qcow2 over the same frozen base), then
// restore the RAM unchanged — the overlay reference stays valid and now shows
// exactly the snapshot-instant content. This avoids any disk-path rewrite (an
// earlier attempt that swapped overlay→base made qemu open the base file both
// read-write as the disk AND read-only as its own backing → write-lock
// self-deadlock).
func (c *Client) RevertToLiveSnapshot(domainName, snapshotName, vmstatePath string) error {
	// Pre-flight: never start tearing the VM down if the RAM image is gone.
	if _, err := os.Stat(vmstatePath); err != nil {
		return fmt.Errorf("vmstate image %q missing — cannot restore memory snapshot: %w", vmstatePath, err)
	}

	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	snap, err := c.virt.DomainSnapshotLookupByName(dom, snapshotName, 0)
	if err != nil {
		return fmt.Errorf("snapshot %q not found: %w", snapshotName, err)
	}
	snapXML, err := c.virt.DomainSnapshotGetXMLDesc(snap, 0)
	if err != nil {
		return fmt.Errorf("get snapshot XML: %w", err)
	}
	origDisks := parseSnapshotDomainDisks(snapXML)
	if len(origDisks) == 0 {
		return fmt.Errorf("snapshot %q: no disk sources found in snapshot XML", snapshotName)
	}
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML: %w", err)
	}
	currentDisks := parseDomainDiskSources(domXML)

	// Each changed disk: overlay (live) → base (frozen at snapshot). We reset the
	// overlay to a fresh empty qcow2 backed by the base.
	type overlayReset struct{ overlay, base string }
	var resets []overlayReset
	for dev, base := range origDisks {
		overlay, ok := currentDisks[dev]
		if !ok || overlay == base {
			continue
		}
		resets = append(resets, overlayReset{overlay: overlay, base: base})
	}

	// The saved image's domain XML references the overlay paths — keep it as-is
	// for the persistent redefine after restore.
	savedXML, err := c.virt.DomainSaveImageGetXMLDesc(vmstatePath, 0)
	if err != nil {
		return fmt.Errorf("read saved image XML: %w", err)
	}

	// Destroy the running domain and wait for shutoff.
	if err := c.virt.DomainDestroy(dom); err != nil {
		return fmt.Errorf("destroy domain before revert: %w", err)
	}
	for i := 0; i < 30; i++ {
		dom2, lookupErr := c.virt.DomainLookupByName(domainName)
		if lookupErr != nil {
			break
		}
		st, _, _ := c.virt.DomainGetState(dom2, 0)
		if st == int32(golibvirt.DomainShutoff) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Delete snapshot metadata (we manage the overlay files ourselves).
	_ = c.virt.DomainSnapshotDelete(snap, golibvirt.DomainSnapshotDeleteMetadataOnly)

	// Undefine to release virtlockd locks (mirrors the disk-only revert).
	dom, _ = c.virt.DomainLookupByName(domainName)
	_ = c.virt.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineNvram))
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		if !c.DomainExists(domainName) {
			break
		}
	}
	time.Sleep(time.Second)

	// Reset each overlay to empty over its (frozen) base — this is the disk
	// revert: all post-snapshot writes (in the old overlay) are discarded.
	for _, r := range resets {
		if err := resetOverlay(r.overlay, r.base); err != nil {
			return fmt.Errorf("reset overlay %q: %w", r.overlay, err)
		}
	}

	// Restore the VM running from the snapshot-instant RAM. The saved XML's disk
	// references (the overlays) are valid and now empty, so no Dxml override is
	// needed; the chain is overlay→base→image with no file opened twice.
	if err := c.restoreWithRetry(domainName, vmstatePath, ""); err != nil {
		return fmt.Errorf("restore guest memory: %w", err)
	}
	if _, err := c.virt.DomainDefineXML(savedXML); err != nil {
		// Running instance is fine; it just isn't persistent yet. Surface it so
		// the operator knows a stop would lose the definition.
		return fmt.Errorf("revert restored the running VM but re-defining it persistently failed: %w", err)
	}

	// The undefine above dropped the libvirt snapshot metadata. Re-register it
	// (best-effort) so the snapshot stays revertible AND deletable — the overlay
	// is freshly reset over the same base, so the recorded snapshot point still
	// holds. A failure here is non-fatal: the revert already succeeded.
	if redom, lerr := c.virt.DomainLookupByName(domainName); lerr == nil {
		_, _ = c.virt.DomainSnapshotCreateXML(redom, snapXML, uint32(golibvirt.DomainSnapshotCreateRedefine))
	}
	return nil
}

// resetOverlay recreates overlay as a fresh, empty qcow2 backed by base,
// discarding any prior contents. Used by the live-snapshot revert to roll a
// disk back to its frozen base without touching the base itself.
func resetOverlay(overlay, base string) error {
	_ = os.Remove(overlay)
	cmd := exec.Command("qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, overlay)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// restoreWithRetry calls DomainRestoreFlags (as running) retrying on virtlockd
// lock-release races, mirroring the StartDomain retry in RevertToSnapshot. When
// dxml is non-empty it is passed as the restore-time domain XML override (used
// to swap the saved image's overlay disk paths back to the originals).
//
// A restore that fails at QEMU 'cont' (disk write-lock not yet released by the
// just-destroyed domain) can leave a paused domain holding things, so between
// attempts we destroy any partial domain and wait for the lease to release —
// sanlock/lockd leases can take longer than a single second.
func (c *Client) restoreWithRetry(domainName, vmstatePath, dxml string) error {
	var dxmlOpt golibvirt.OptString
	if dxml != "" {
		dxmlOpt = golibvirt.OptString{dxml}
	}
	// Restore PAUSED first so qemu opens the disks and acquires their write
	// locks before we resume the CPU. Restoring with the RUNNING flag does the
	// 'cont' as part of the same call, which races the just-destroyed domain's
	// lock release and fails with "Failed to get write lock". Splitting the
	// resume into a separate, retried DomainResume lets the lease settle.
	var err error
	for i := 0; i < 8; i++ {
		err = c.virt.DomainRestoreFlags(vmstatePath, dxmlOpt, uint32(domainSavePaused))
		if err == nil {
			break
		}
		msg := err.Error()
		if !strings.Contains(msg, "lock") && !strings.Contains(msg, "already") {
			return err
		}
		c.forceRemoveDomain(domainName) // clear any partial domain holding the lock
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}
	// The domain is restored and paused, holding its disk locks. Resume the CPU.
	dom, lerr := c.virt.DomainLookupByName(domainName)
	if lerr != nil {
		return fmt.Errorf("lookup restored domain: %w", lerr)
	}
	for i := 0; i < 6; i++ {
		if err = c.virt.DomainResume(dom); err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "lock") {
			return err
		}
		time.Sleep(time.Second)
	}
	return err
}

// forceRemoveDomain destroys (if up) and undefines (if defined) a domain so a
// subsequent restore starts from a clean slate and the disk lease is released.
func (c *Client) forceRemoveDomain(domainName string) {
	d, e := c.virt.DomainLookupByName(domainName)
	if e != nil {
		return
	}
	_ = c.virt.DomainDestroy(d) // no-op/err if already shut off
	if d2, e2 := c.virt.DomainLookupByName(domainName); e2 == nil {
		_ = c.virt.DomainUndefineFlags(d2, golibvirt.DomainUndefineFlagsValues(golibvirt.DomainUndefineNvram))
	}
}

// parseSnapshotDomainDisks extracts the original disk paths from the <domain>
// element embedded in a snapshot's XML. Returns a map of target dev → file path.
func parseSnapshotDomainDisks(snapXML string) map[string]string {
	var snap struct {
		Domain struct {
			Devices struct {
				Disks []struct {
					Source struct {
						File string `xml:"file,attr"`
					} `xml:"source"`
					Target struct {
						Dev string `xml:"dev,attr"`
					} `xml:"target"`
				} `xml:"disk"`
			} `xml:"devices"`
		} `xml:"domain"`
	}
	if err := xml.Unmarshal([]byte(snapXML), &snap); err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, d := range snap.Domain.Devices.Disks {
		if d.Target.Dev != "" && d.Source.File != "" {
			m[d.Target.Dev] = d.Source.File
		}
	}
	return m
}

// DomainDiskSources returns the live domain's disk sources as target-dev →
// source-file. Used to reconcile litevirt's recorded vm_disks.path after a
// snapshot op cuts the domain over to an overlay. Method form so callers can go
// through grpcapi.LibvirtBackend (and the fake can stub it).
func (c *Client) DomainDiskSources(domainName string) (map[string]string, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	xmlStr, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return nil, fmt.Errorf("get domain XML %q: %w", domainName, err)
	}
	return parseDomainDiskSources(xmlStr), nil
}

// parseDomainDiskSources extracts disk target dev → source file from domain XML.
func parseDomainDiskSources(domXML string) map[string]string {
	var domain struct {
		Devices struct {
			Disks []struct {
				Source struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &domain); err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, d := range domain.Devices.Disks {
		if d.Target.Dev != "" && d.Source.File != "" {
			m[d.Target.Dev] = d.Source.File
		}
	}
	return m
}
