package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

// The destruction half of `lv cutover`, driven entirely from the journaled
// manifest.
//
// It cannot be driven from the database instead: the replacement transition
// DISPLACES the replaced VM's parent row and every child row whose key the
// replacement claims, and the name those rows were recorded under now belongs to
// the replacement. Reading it back would free the wrong VM's disks. The manifest,
// taken before the transition and committed with the step that authorizes this,
// is the only surviving description of what to free.

// operatorStopDetail is the sticky marker StopVM records. It is the one thing
// that overrides a cutover's journaled running intent: an operator's decision,
// as opposed to a reconciler's observation of a domain that is shut off because
// the handoff has not run yet.
const operatorStopDetail = "operator-stop"

// vmReplaceStopTimeout bounds the graceful shutdown of the replacement before it
// is forced. The domain is about to be redefined and restarted under the new
// name, so waiting long buys nothing.
const vmReplaceStopTimeout = 30 * time.Second

// SetCutoverCrashHook installs a TEST-ONLY seam that fires at each of cutover's
// crash boundaries and, by returning an error, makes the handler abandon the
// operation exactly there.
//
// The stages are the boundaries between phases that cannot be one commit:
// "before-commit" (the transition), "mid-cleanup" (part of the destruction done),
// "before-runtime" (destruction recorded, the handoff not started) and
// "after-commit" (nothing after the transition has run).
//
// A process that dies mid-cutover cannot be arranged from a test any other way,
// and the guarantees at those three boundaries (an uncommitted operation destroys
// nothing; a committed one is finished by a restart; the replacement's resources
// survive every retry) are the whole reason the journal exists. Production never
// calls this.
func (s *Server) SetCutoverCrashHook(h func(stage string) error) { s.cutoverCrashHook = h }

func (s *Server) fireCutoverCrashHook(stage string) error {
	if h := s.cutoverCrashHook; h != nil {
		return h(stage)
	}
	return nil
}

// finishVMReplaceCleanup frees what the manifest lists and records completion —
// in that order, and only in that order. The completion step is what stops a
// restart from retrying, so writing it while a volume is still there would
// strand exactly what the journal exists to free.
//
// Every step is idempotent, because this runs again after any interruption: a
// volume already gone, firmware state already wiped, and an ISO already removed
// are all successes. The shared-path check is retained — a volume another VM
// still references is skipped, not freed.
func (s *Server) finishVMReplaceCleanup(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	if !cl.ReleaseDone {
		if err := s.releaseReplacedVMAddresses(ctx, cl); err != nil {
			return err
		}
		if err := corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
			corrosion.OpStepReleased); err != nil {
			return err
		}
	}
	if !cl.CleanupDone {
		if err := s.freeReplacedVMResources(ctx, cl); err != nil {
			return err
		}
		if err := corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
			corrosion.OpStepConfigApplied); err != nil {
			return err
		}
	}
	if !cl.RuntimeDone {
		if hErr := s.fireCutoverCrashHook("before-runtime"); hErr != nil {
			return hErr
		}
		if err := s.finishVMReplaceRuntime(ctx, cl); err != nil {
			return err
		}
		if err := corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
			corrosion.OpStepRedefined); err != nil {
			return err
		}
	}
	return corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
		corrosion.OpStepCompleted)
}

// replacedVMLeases captures the addresses the replaced VM holds, while its own
// NIC rows still say so. After the transition the REPLACEMENT's leases have moved
// onto the same name, so the owner name no longer separates them.
//
// Each entry carries the external IDENTITY as well as the object id, taken here
// because it is derived from the replaced VM's own incarnation uuid — which the
// transition displaces along with everything else. It is what lets the release
// phase prove, later, that the object it is about to delete is still the one this
// VM claimed.
func (s *Server) replacedVMLeases(ctx context.Context, vm *corrosion.VMRecord) ([]corrosion.VMReplaceLease, error) {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
	if err != nil {
		return nil, err
	}
	var out []corrosion.VMReplaceLease
	for _, nic := range nics {
		if nic.IP == "" {
			continue // never addressed — nothing to give back
		}
		entry := corrosion.VMReplaceLease{Network: nic.NetworkName, IP: nic.IP, MAC: nic.MAC}
		// The external object's id, while the lease row still carries it.
		lease, lErr := corrosion.GetLeaseByIPForOwner(ctx, s.db, nic.NetworkName, nic.IP, "vm", "", vm.Name)
		if lErr != nil {
			return nil, lErr
		}
		if lease != nil {
			entry.NetBoxIPID = lease.NetBoxIPID
		}
		// A VM with no uuid in its spec never claimed anything externally, so an
		// identity cannot be built and none is needed. It is NOT an error here: it
		// only removes the release phase's licence to delete remotely, which is the
		// safe side to land on.
		if id, iErr := s.nicIdentity(ctx, vm, nic.MAC); iErr == nil {
			entry.Identity = id
		} else if entry.NetBoxIPID != 0 {
			return nil, fmt.Errorf("build the external identity for %s on %s: %w",
				nic.IP, nic.NetworkName, iErr)
		}
		out = append(out, entry)
	}
	return out, nil
}

// releaseReplacedVMAddresses gives the replaced VM's addresses back, after the
// transition has committed and from the manifest rather than from rows that no
// longer distinguish the two VMs.
//
// Ownership is checked on BOTH halves, and neither check stands in for the other.
// Locally, the allocation at that key is read OWNER-BLIND and must still be this
// VM's: the same owner tuple, the MAC that held it, and the external object the
// manifest captured. An owner-scoped read cannot be the gate here, because it
// answers a foreign live row and a genuinely absent one with the same nil — and
// those authorize opposite actions, since absence is what licenses finishing a
// remote delete. Even a matching owner and MAC identify no incarnation on their
// own: the contested name belongs to the replacement after the transition and a
// cutover may reuse the original's MAC, so the external object is what separates
// them. Remotely, that object is read back by identity, because a numeric object
// id is a name and not a claim — a local identity does not encode the owner tuple
// any more than the owner tuple encodes the object.
//
// An address that has moved on either way is left alone: releasing it would take a
// live workload's address, and leaving it is what the orphan sweep exists for.
//
// This does not go through releaseOneNICLease, which the ordinary delete and
// detach paths share. That function proves ownership from the LEASE ROW, which is
// the one thing a cutover cannot rely on — the row it would read may already be
// the replacement's, and the object it would delete is named by a manifest the row
// knows nothing about. So the two halves are done explicitly here, and the remote
// half by the same identity-checked, idempotent helper the row-already-gone case
// uses.
//
// A failure is returned, not logged: the phase stays owed and a restart retries
// it, instead of the address being stranded under a cutover that said it was
// finished.
func (s *Server) releaseReplacedVMAddresses(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	m := cl.Manifest
	if m.HostName != s.hostName || len(m.Leases) == 0 {
		return nil
	}
	var failures []string
	for _, l := range m.Leases {
		held, err := corrosion.GetLeaseByIP(ctx, s.db, l.Network, l.IP)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %s: read: %v", l.Network, l.IP, err))
			continue
		}
		// held == nil is not "nothing to do": an earlier attempt may have landed
		// the local half and failed the remote one, which is the single state the
		// lease row can no longer describe. The remote half runs either way — but
		// ONLY on a row that is genuinely gone, which is why the read above is
		// owner-blind.
		if held != nil {
			if held.OwnerKind != "vm" || held.OwnerHost != "" || held.VMName != m.ReplacedVM {
				// A live allocation someone else now holds. It vetoes BOTH halves:
				// the local row is not ours to retire, and the external object it
				// names is backing an address that is still in use — deleting it
				// because our identity still happens to be on it would strand that
				// workload with a local claim and no remote one.
				slog.Warn("cutover cleanup: the address belongs to another workload now — not releasing it",
					"network", l.Network, "ip", l.IP, "want_owner", m.ReplacedVM,
					"have_owner", held.VMName, "have_owner_kind", held.OwnerKind,
					"have_owner_host", held.OwnerHost)
				continue
			}
			if held.MAC != l.MAC {
				slog.Warn("cutover cleanup: the address is held by a different MAC now — not releasing it",
					"network", l.Network, "ip", l.IP, "want_mac", l.MAC, "have_mac", held.MAC)
				continue
			}
			if held.NetBoxIPID != l.NetBoxIPID {
				// Same key, same owner name, same MAC — and still a different
				// allocation. The external object behind the row is what separates
				// the incarnations: a released-and-reclaimed address carries a new one.
				slog.Warn("cutover cleanup: the address backs a different allocation now — not releasing it",
					"network", l.Network, "ip", l.IP, "want_object", l.NetBoxIPID, "have_object", held.NetBoxIPID)
				continue
			}
			// The LOCAL half first, owner-scoped, so it still fails loudly if
			// ownership moved between the read and the write. Local before remote is
			// the same order every other release uses: a live local row pointing at
			// an object that is already gone is the state the sweeper's live-lease
			// veto can never reclaim.
			if rErr := network.ReleaseLease(ctx, s.db, l.Network, l.IP, l.MAC, "vm", "", m.ReplacedVM); rErr != nil {
				failures = append(failures,
					fmt.Sprintf("%s %s: tombstone lease: %v", l.Network, l.IP, rErr))
				continue
			}
		}
		if rErr := s.finishReplacedAddressRemotely(ctx, l); rErr != nil {
			failures = append(failures,
				fmt.Sprintf("%s %s: remote release: %v", l.Network, l.IP, rErr))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("release the replaced VM's addresses: %s", strings.Join(failures, "; "))
	}
	return nil
}

// finishReplacedAddressRemotely completes the REMOTE half of a release whose
// local half already landed — the state an earlier attempt leaves behind when it
// tombstones the lease row and then cannot reach the external IPAM.
//
// The journaled object id is a NAME, not a claim. By the time this runs the
// address may have been re-allocated to something else, which keeps the id and
// moves the identity; deleting on the id alone takes a live workload's address.
// So the object is read back by IDENTITY — an owner-independent read — and
// deleted only while it still answers to the identity the replaced VM claimed it
// under.
//
// That same read makes the phase IDEMPOTENT without having to interpret a status
// code: an object that is no longer there is an empty result, and an empty result
// is a completed release. A crash between a successful delete and the `released`
// record therefore resumes cleanly, where re-deleting a known id would resume
// into a permanent 404.
//
// A failed READ is a different thing from an absent object and is returned: the
// ownership check was unavailable, so the phase stays owed for the next attempt
// rather than falling through to a delete it could not justify.
func (s *Server) finishReplacedAddressRemotely(ctx context.Context, l corrosion.VMReplaceLease) error {
	if l.NetBoxIPID == 0 {
		return nil // a builtin lease: the local tombstone was the whole release
	}
	alloc, binding, aErr := s.allocatorFor(ctx, "vm", l.Network)
	if aErr != nil || alloc == nil || binding == nil {
		// No reachable remote authority for this network — an unbound network (no
		// external object can exist), or a binding that is suspended or cannot be
		// resolved. Blocking the cutover's remaining phases on that would leave the
		// replacement's domain stranded under its temporary name for as long as the
		// binding stays broken, which is strictly worse than the address it would be
		// protecting. Name the identity for the orphan sweep instead: the sweep
		// applies the same ownership test and the same live-reference veto, so
		// nothing is deleted that this path would not have deleted itself.
		if aErr != nil {
			slog.Warn("cutover cleanup: no allocator for the network — handing the address to the orphan sweep",
				"network", l.Network, "ip", l.IP, "error", aErr)
		}
		if l.Identity != "" {
			if eErr := s.enqueueOrphanCheck(ctx, l.Identity); eErr != nil {
				slog.Error("cutover cleanup: could not enqueue an orphan check — the address may be stranded until the next full sweep",
					"identity", l.Identity, "error", eErr)
			}
		}
		return nil
	}
	if l.Identity == "" {
		// Nothing to prove ownership WITH. The manifest was taken from a VM whose
		// spec carried no uuid, so it never claimed this object under an identity
		// litevirt can recognise, and deleting it would be the blind delete this
		// whole function exists to remove.
		slog.Warn("cutover cleanup: the address was journaled without an external identity — not releasing it remotely",
			"network", l.Network, "ip", l.IP, "object", l.NetBoxIPID)
		return nil
	}
	found, err := s.netbox.LookupByIdentity(ctx, l.Identity, binding.VRFID, binding.ObservedCIDR)
	if err != nil {
		return fmt.Errorf("read back %s to confirm it is still ours: %w", l.IP, err)
	}
	for _, obj := range found {
		if obj.ID != l.NetBoxIPID {
			continue
		}
		return s.netbox.ReleaseIP(ctx, obj.ID)
	}
	// Verified absence: either an earlier attempt's delete landed and its record
	// did not, or the object was re-identified by something else. Neither is work
	// this phase may still do.
	return nil
}

// freeReplacedVMResources is the destruction phase. It must run exactly once:
// after it, the runtime handoff moves the REPLACEMENT's firmware onto the
// contested name, and a second pass of this name-keyed wipe would destroy that
// instead.
func (s *Server) freeReplacedVMResources(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	m := cl.Manifest
	if m.HostName == s.hostName {
		// EVERY live reference protects the volume — no name is exempt. The
		// contested name now belongs to the replacement, and the temporary name is
		// free and reusable, so exempting either would exempt whatever VM happens
		// to hold that name when a delayed cleanup finally runs. A VM created after
		// the crash can legitimately reference the volume.
		//
		// There is deliberately no images.DeleteVMDisks default-dir sweep. That
		// globs "<name>-*.qcow2", which matches the replacement's own flat-named
		// disks ("<name>-next-*.qcow2") — the sweep would delete the disks the
		// cutover exists to keep. The manifest is authoritative and its records are
		// driver-dispatched, so a volume outside the default pool is freed where it
		// actually lives.
		if err := s.deleteCapturedVMDiskVolumes(ctx, m.Disks); err != nil {
			return fmt.Errorf("free the replaced VM's volumes: %w", err)
		}
		if hErr := s.fireCutoverCrashHook("mid-cleanup"); hErr != nil {
			return hErr
		}
		// The swtpm tree is keyed by the replaced VM's own UUID, so it cannot
		// belong to anything else and is always safe to free (G1).
		lv.WipeFirmwareStateByUUID(m.FirmwareUUID)

		// The vars file and the cloud-init ISO are keyed by the NAME, which is
		// reusable. If the contested name has since been deleted and recreated,
		// those files are the NEW incarnation's and deleting them destroys a VM
		// this operation has nothing to do with. Everything uniquely identified
		// is still freed above; only the name-keyed artifacts are held back.
		ours, oErr := s.nameStillHoldsThisIncarnation(ctx, m)
		if oErr != nil {
			return oErr
		}
		if !ours {
			slog.Warn("cutover cleanup: the contested name holds a different incarnation — "+
				"leaving its name-keyed firmware and cloud-init state alone",
				"vm", m.ReplacedVM, "operation", cl.OperationID)
			return nil
		}
		lv.WipeNameKeyedFirmwareState(s.dataDir, m.ReplacedVM)
		for _, p := range m.Paths {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", p, err)
			}
		}
	}
	return nil
}

// nameStillHoldsThisIncarnation reports whether the contested name is still the
// row this operation transitioned, which is what makes its NAME-keyed artifacts
// this operation's to delete.
//
// It reads TOMBSTONES too, and that is the whole point. GetVM hides them, so a
// newer incarnation deleted with its disks retained — which deliberately keeps
// its firmware and cloud-init state — reads as "nobody owns this name" and its
// retained artifacts get deleted by an old cleanup. Only genuine absence, or this
// operation's OWN incarnation (live or since tombstoned, which must still be
// cleaned up), is ownership.
func (s *Server) nameStillHoldsThisIncarnation(
	ctx context.Context, m corrosion.VMReplaceManifest,
) (bool, error) {
	row, err := corrosion.GetVMIncludingDeleted(ctx, s.db, m.ReplacedVM)
	if err != nil {
		return false, err
	}
	if row == nil {
		return true, nil // nothing has held this name since
	}
	return row.CreatedAt == m.ReplacementIncarnation, nil
}

// finishVMReplaceRuntime is the runtime-handoff phase: the replacement's libvirt
// domain and its name-keyed firmware still answer to the temporary name after the
// transition commits, and moving them is the other half of a cutover.
//
// Three things make this harder than "rename the domain":
//
//   - The temporary name is FREE the moment the transition commits, so acting on
//     it by name alone can consume a VM that reused it. Every step checks the
//     recorded domain UUID first, including the already-done shortcut.
//   - Undefining destroys the only copy of the definition, so it is journaled
//     first. A transient redefine failure would otherwise leave neither name
//     defined and nothing left to redefine from.
//   - The desired runtime state is read from the DATABASE now, not from the
//     manifest's pre-transition snapshot. An operator stop acknowledged between
//     capture and handoff must not be undone by replaying a stale "running".
//
// For a Secure-Boot/vTPM VM a failure is HARD: the reconciler cannot heal a
// firmware VM (a fresh redefine would mint new firmware), so it is reported and
// leaves the phase unrecorded for the next attempt. For a plain VM the reconciler
// rebuilds from the row, so a failure is logged and the phase still completes.
func (s *Server) finishVMReplaceRuntime(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	m := cl.Manifest
	if m.HostName != s.hostName {
		return nil
	}
	// The authoritative desired state, and the proof this operation still owns the
	// name. A different incarnation there means someone else's cutover or recreate
	// has taken over; touching libvirt for it would be acting on another VM.
	desired, err := corrosion.GetVM(ctx, s.db, m.ReplacedVM)
	if err != nil {
		return err
	}
	if desired == nil || desired.CreatedAt != m.ReplacementIncarnation {
		slog.Warn("cutover: skipping the runtime handoff — the name no longer holds this incarnation",
			"vm", m.ReplacedVM, "operation", cl.OperationID)
		return nil
	}

	// No recorded identity means there was no local domain to move when the
	// manifest was taken, so there is nothing for this phase to do. It is NOT a
	// licence to act by name: the temporary name is reusable, and a name match
	// alone would let a delayed recovery consume whatever VM now holds it.
	if m.ReplacementUUID == "" {
		return nil
	}
	firmware := usesFirmwareState(m.ReplacementSpec)
	// EVERY failure here is returned, so the phase stays unrecorded and a restart
	// retries it. The older behaviour tolerated a plain VM's failure on the grounds
	// that the reconciler rebuilds from the row — but that predates the journal,
	// and swallowing it now records the handoff as done: a redefine that failed
	// leaves neither name defined with the operation closed, and a start that
	// failed leaves a VM the operator asked to be running shut off for good. The
	// reconciler is still a backstop; it is no longer the only one.
	failed := func(step string, e error) error {
		slog.Error("cutover: runtime handoff step failed",
			"step", step, "vm", m.ReplacedVM, "error", e, "firmware_vm", firmware)
		s.recordVMEvent(ctx, m.ReplacedVM, "vm.cutover", "error", step+" failed: "+e.Error())
		// A firmware VM cannot be healed by a fresh redefine (it would mint new
		// firmware), so the failure is surfaced on its row for an operator to see —
		// in the DETAIL, keeping the state itself untouched. Writing state=error
		// here is what made a failed start unrecoverable: the next attempt reads the
		// row for the desired runtime state, sees "error", concludes the VM was not
		// asked to run, and completes the operation with it shut off. Operation
		// failure and running intent are different facts and cannot share a column.
		// NEVER over an acknowledged operator stop. That marker is the one thing
		// that overrides the journaled running intent, so replacing it with
		// diagnostic text makes the next retry start a VM the operator stopped.
		// The failure is already on the VM's event feed and the operation stays
		// owed in the journal; the row is not the only place it can be seen.
		if firmware && desired.StateDetail != operatorStopDetail {
			if werr := corrosion.UpdateVMState(ctx, s.db, m.ReplacedVM, desired.State,
				"cutover "+step+" failed: "+e.Error()); werr != nil {
				s.noteStateWriteFail(corrosion.OpVMState, werr)
			}
		}
		return fmt.Errorf("%s: %w", step, e)
	}

	// 1. The definition, durably, before anything undefines it.
	alreadyAtTarget, _, atErr := s.domainOwnership(m.ReplacedVM, m.ReplacementUUID)
	if atErr != nil {
		return failed("read the domain at the contested name", atErr)
	}
	handoff := cl.Handoff
	if handoff.XML == "" {
		xml, derr := s.virt.DumpXML(m.Replacement)
		switch {
		case derr == nil && s.domainIdentityMatches(xml, m.ReplacementUUID):
			handoff = corrosion.VMReplaceHandoff{XML: xml, UUID: m.ReplacementUUID}
			if rErr := corrosion.RecordVMReplaceHandoff(ctx, s.db, cl.OperationID, cl.OwnerEpoch, handoff); rErr != nil {
				return rErr
			}
		case alreadyAtTarget:
			// Already redefined by an earlier attempt; only the runtime state may
			// still be owed, which the tail of this function settles.
		case derr == nil:
			// A DIFFERENT VM answers to the temporary name. Never undefine it.
			slog.Warn("cutover: the temporary name holds a different VM — leaving it alone",
				"name", m.Replacement, "want_uuid", m.ReplacementUUID)
			return nil
		default:
			return failed("dump the replacement's XML", derr)
		}
	}

	// Whether the temporary name is still OURS. A foreign domain there means some
	// other VM has taken the freed name: neither its definition nor its firmware
	// may be touched.
	//
	// A read that FAILED is neither answer. Treating it as "not foreign" is what
	// let a transient libvirt error authorize moving an unrelated VM's firmware, so
	// only a verified not-found counts as absence and anything else aborts the
	// phase for the next attempt.
	ownsTemporary, foreignAtTemporary, idErr := s.domainOwnership(m.Replacement, m.ReplacementUUID)
	if idErr != nil {
		return failed("read the domain at the replacement's name", idErr)
	}

	// 2. STOP it, and confirm. libvirt cannot rename a domain, and undefining an
	// ACTIVE one leaves it running as a TRANSIENT domain that still holds its UUID
	// — after which defining that UUID under the contested name is refused, so the
	// whole handoff fails with the replacement left running under its temporary
	// name. Cutting over a RUNNING replacement therefore restarts it; there is no
	// libvirt operation that moves a live domain to another name.
	//
	// Journaled, because the restart it makes owed has to survive a crash here.
	// Checked EVERY time, never skipped because the phase is already recorded. A
	// recorded stop is a statement about the past: between it and the undefine the
	// domain can be started again by hand, or by libvirt's own autostart after a
	// host reboot, and undefining it then hits exactly the conflict this exists to
	// avoid. So the live activity query is the gate, and the phase record only
	// keeps the journal honest about what has happened.
	if handoff.XML != "" && ownsTemporary {
		if err := s.stopDomainForHandoff(m.Replacement); err != nil {
			return failed("stop the replacement's domain", err)
		}
		if !cl.StopDone {
			if err := corrosion.RecordVMReplacePhase(ctx, s.db, cl.OperationID, cl.OwnerEpoch,
				corrosion.OpStepStopped); err != nil {
				return err
			}
		}
	}

	// 3. Undefine — only ever the domain this operation recorded.
	if handoff.XML != "" && ownsTemporary {
		// KEEP NVRAM/vTPM: the recorded XML carries the stable <uuid>, so the
		// UUID-keyed swtpm follows automatically and only the name-keyed vars file
		// moves. The undefine MUST precede that rename or the file is pulled out
		// from under a still-defined domain, leaving a dangling <nvram> path (G1).
		if e := s.virt.UndefineDomainPreservingState(m.Replacement); e != nil {
			return failed("undefine the replacement's domain", e)
		}
	}

	// 4. Redefine under the contested name, from the recorded definition.
	targetIsOurs, _, tErr := s.domainOwnership(m.ReplacedVM, m.ReplacementUUID)
	if tErr != nil {
		return failed("read the domain at the contested name", tErr)
	}
	if handoff.XML != "" && !targetIsOurs {
		oldNvram := lv.NvramPath(s.dataDir, m.Replacement)
		newNvram := lv.NvramPath(s.dataDir, m.ReplacedVM)
		// The destination definition, derived UNCONDITIONALLY — not as a side effect
		// of this attempt performing the rename. A retry after a failed redefine
		// finds the file already moved, skips the rename, and would otherwise define
		// the VM pointing at a vars file that is no longer there.
		xml := strings.ReplaceAll(
			replaceDomainName(handoff.XML, m.Replacement, m.ReplacedVM), oldNvram, newNvram)
		// The firmware moves only while the temporary name is still ours. It is a
		// name-keyed path, so a VM that took the freed name owns the file at it now,
		// and moving it would hand that VM's firmware to the contested name.
		if !foreignAtTemporary {
			if _, e := os.Stat(oldNvram); e == nil {
				if e := os.Rename(oldNvram, newNvram); e != nil {
					return failed("nvram rename", e)
				}
			}
		}
		if e := s.virt.DefineDomain(xml); e != nil {
			return failed("redefine", e)
		}
	}

	// 5. The runtime state the cutover asks for — never the manifest's
	// snapshot. A domain merely existing is not the finished state: a start that
	// failed on an earlier attempt leaves it defined and shut off, and recording
	// the phase then would strand a VM the operator asked to be running.
	// The intent comes from the JOURNAL — the facts recorded atomically with the
	// transition — not from the row and not from the manifest. The row's state is
	// observational: a reconciler pass that finds the domain shut off, which is
	// exactly what an unfinished handoff looks like, syncs it to "stopped", and
	// reading that back would erase the very start this phase owes. The manifest is
	// older still: it is captured before the FIRST attempt's teardown and adopted
	// verbatim by every retry, so a start the operator asked for between two
	// attempts is not in it. Only an operation journaled before this was recorded
	// falls back to the manifest. Only an explicit operator stop overrides either,
	// because that is a decision rather than an observation.
	accepted := cl.AcceptedState
	if accepted == "" {
		accepted = m.ReplacementState
	}
	wantRunning := accepted == "running"
	if desired.StateDetail == operatorStopDetail {
		wantRunning = false
	}
	if !wantRunning {
		return nil
	}
	state, sErr := s.virt.DomainState(m.ReplacedVM)
	if sErr != nil {
		return failed("read the domain state", sErr)
	}
	if state == "running" {
		return nil
	}
	if e := s.virt.StartDomain(m.ReplacedVM); e != nil {
		return failed("start", e)
	}
	return nil
}

// confirmOriginalRetiredOnItsHost establishes, from the node that actually holds
// the replaced VM, that no domain occupies the contested name there.
//
// Cutover retires the original's domain itself — stopped if active, undefined,
// absence confirmed — but only on the node it runs on. When the original is
// hosted elsewhere there is nothing to run that sequence with, and the parts that
// follow are not conditional on it: the transition hands the name over, the
// journal frees the address, and the guest on the other host keeps running on
// both. So the retirement becomes a PRECONDITION, answered by the host that can
// actually see its own libvirt.
//
// Only `absent` is accepted. `defined_stopped` still occupies the name;
// `unknown` is what an incomplete survey reports, and treating it as absence is
// the exact inversion the inventory's own contract warns against; an error —
// including the Unimplemented an older peer answers with — is a definite failure
// to establish anything. Every one of those refuses.
func (s *Server) confirmOriginalRetiredOnItsHost(ctx context.Context, host, vmName string) error {
	state, err := s.CheckPeerVMRuntime(ctx, host, vmName)
	if err != nil {
		return fmt.Errorf("confirm the replaced VM %q has no domain left on %s: %w", vmName, host, err)
	}
	if state != health.RuntimeAbsent {
		return fmt.Errorf(
			"the replaced VM %q is hosted on %s, where its domain is %s — a cutover retires a "+
				"domain only on the node it runs on, so that one has to be stopped and undefined "+
				"there first", vmName, host, state)
	}
	return nil
}

// retireOriginalDomain removes the REPLACED VM's domain from the contested name
// and verifies it is gone, so the replacement can be defined there.
//
// Not the destructive undefine: that one always passes DomainUndefineNvram
// (libvirt requires either Nvram or KeepNvram to undefine a UEFI domain), which
// would delete the original's per-VM UEFI vars before the database transition has
// committed. The firmware is freed explicitly, from the journal, afterwards.
//
// Verified at every step. An already-absent domain is success; anything else that
// leaves the name occupied is an error, because the caller is about to destroy
// this VM's disks on the strength of it.
func (s *Server) retireOriginalDomain(name string) error {
	active, err := s.virt.DomainIsActive(name)
	switch {
	case err != nil && lv.IsNotFound(err):
		return nil // nothing holds the name
	case err != nil:
		return err
	case active:
		if sErr := s.stopDomainForHandoff(name); sErr != nil {
			return sErr
		}
	}
	if uErr := s.virt.UndefineDomainPreservingState(name); uErr != nil && !lv.IsNotFound(uErr) {
		return uErr
	}
	if _, dErr := s.virt.DumpXML(name); dErr == nil {
		return fmt.Errorf("domain %q is still defined after being undefined", name)
	} else if !lv.IsNotFound(dErr) {
		return dErr
	}
	return nil
}

// stopDomainForHandoff brings the replacement's domain to a stop and CONFIRMS it,
// because an undefine of an active domain silently leaves it running.
//
// Graceful first, then forced — the same escalation StopVM uses. A domain that is
// already inactive is a no-op.
func (s *Server) stopDomainForHandoff(name string) error {
	// ACTIVITY, not the coarse state. DomainState collapses paused, shut-off and
	// pm-suspended into "stopped", and a PAUSED domain is active: undefining it
	// leaves a transient domain holding the UUID, and the new definition is then
	// refused — after the original has already been cleaned up.
	active, err := s.virt.DomainIsActive(name)
	if err != nil {
		return err
	}
	if !active {
		return nil
	}
	// Graceful first, then forced — the same escalation StopVM uses. A paused
	// domain will not answer ACPI, so the force path is the one that ends it.
	if err := s.virt.ShutdownDomain(name); err != nil {
		slog.Warn("cutover: graceful shutdown of the replacement failed; forcing",
			"domain", name, "error", err)
	} else if s.virt.WaitForShutdown(name, vmReplaceStopTimeout) {
		return s.confirmDomainInactive(name)
	}
	if err := s.virt.DestroyDomain(name); err != nil {
		return err
	}
	return s.confirmDomainInactive(name)
}

// confirmDomainInactive is the verification the undefine depends on. It must be
// neither inferred from the stop call returning nil nor read off DomainState,
// which cannot see the difference between paused and shut off.
func (s *Server) confirmDomainInactive(name string) error {
	active, err := s.virt.DomainIsActive(name)
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("domain %q is still active after being stopped", name)
	}
	return nil
}

// domainIdentityMatches reports whether libvirt XML carries the expected UUID. An
// empty expectation matches nothing: a manifest without a recorded UUID cannot
// authorize acting on a reusable name.
func (s *Server) domainIdentityMatches(xml, want string) bool {
	return want != "" && domainUUIDFromXML(xml) == want
}

// domainOwnership reports whether the domain at name is the expected one (ours),
// whether some OTHER domain answers to that name (foreign), or an error.
//
// Three-valued on purpose. A failed read is not "absent" and not "not foreign":
// collapsing it into either lets a transient libvirt error authorize acting on a
// name whose real occupant is unknown, which for a reusable name means acting on
// another VM. Only a verified not-found is absence (false, false, nil).
func (s *Server) domainOwnership(name, want string) (ours, foreign bool, err error) {
	xml, dErr := s.virt.DumpXML(name)
	switch {
	case dErr == nil:
		if s.domainIdentityMatches(xml, want) {
			return true, false, nil
		}
		return false, true, nil
	case lv.IsNotFound(dErr):
		return false, false, nil
	default:
		return false, false, dErr
	}
}

// domainUUIDFromXML extracts <uuid>…</uuid> from a domain definition.
func domainUUIDFromXML(xml string) string {
	const open, close = "<uuid>", "</uuid>"
	i := strings.Index(xml, open)
	if i < 0 {
		return ""
	}
	rest := xml[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// lockedFinishVMReplace takes the lifecycle locks the phases require, in name
// order, and finishes what is owed. Recovery has to serialize with StopVM/StartVM
// exactly as the handler does: a resumed handoff reads the desired runtime state
// and then acts on it, and a lifecycle call landing between those is how a VM the
// operator just stopped gets started again.
func (s *Server) lockedFinishVMReplace(ctx context.Context, cl corrosion.VMReplaceCleanup) error {
	for _, n := range sortedPair(cl.Manifest.ReplacedVM, cl.Manifest.Replacement) {
		unlock := s.lockVM(n)
		defer unlock()
	}
	// RELOAD under the locks. The snapshot that got us here was taken before them,
	// so another caller holding them may have finished phases in the meantime —
	// and repeating the destruction phase after the handoff has moved the
	// replacement's firmware onto the contested name would wipe it.
	fresh, err := corrosion.ListVMReplaceCleanups(ctx, s.db, s.hostName)
	if err != nil {
		return err
	}
	for _, f := range fresh {
		if f.OperationID == cl.OperationID {
			return s.finishVMReplaceCleanup(ctx, f)
		}
	}
	return nil // finished by whoever held the locks first
}

// ResumeVMReplaceCleanups finishes the destruction for every cutover on this host
// whose transition COMMITTED and whose cleanup was never recorded as done — the
// work a daemon that died mid-cutover left behind.
//
// It never re-runs a replacement and never reconstructs the replaced VM's
// resources from the reused name: a planned-only operation is skipped precisely
// because its transition did not land, and a committed one is driven from its
// manifest. Called at startup, and safe to call at any time.
func (s *Server) ResumeVMReplaceCleanups(ctx context.Context) error {
	pending, err := corrosion.ListVMReplaceCleanups(ctx, s.db, s.hostName)
	if err != nil {
		return err
	}
	var firstErr error
	for _, cl := range pending {
		slog.Info("cutover: resuming a committed cleanup left by an interrupted attempt",
			"replaced_vm", cl.Manifest.ReplacedVM, "operation", cl.OperationID,
			"disks", len(cl.Manifest.Disks))
		if cErr := s.lockedFinishVMReplace(ctx, cl); cErr != nil {
			slog.Error("cutover: resumed cleanup failed — it stays journaled for the next attempt",
				"replaced_vm", cl.Manifest.ReplacedVM, "operation", cl.OperationID, "error", cErr)
			if firstErr == nil {
				firstErr = cErr
			}
		}
	}
	return firstErr
}
