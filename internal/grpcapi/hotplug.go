package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pci"
)

// detachHostdevIfPresent detaches the PCI hostdev at addr from vmName's LIVE domain
// only if it is still a member of it, making a guest-detach idempotent so a retry
// converges. It FAILS CLOSED on a DumpXML error (membership cannot be confirmed → do
// NOT assume the device is already gone). When addr is absent from the live domain's
// hostdev source addresses it returns nil (nothing to do); otherwise it delegates to
// DetachHostdev.
//
// This removes the non-convergence cause on the un-journaled legacy/migration detach
// paths: DetachHostdev (DomainDetachDeviceFlags) errors on an already-absent device, so a
// bare retry after a failed release would error on the (already-detached) device and
// return before it could re-attempt the release. Mirrors what recoverPCIDetach does with
// hostdevAliasInXML on the journaled path — but keys on the source BDF, since legacy
// hostdevs carry no user alias.
func (s *Server) detachHostdevIfPresent(vmName, addr string) error {
	live, err := s.virt.DumpXML(vmName)
	if err != nil {
		return err
	}
	want, ok := pci.CanonicalBDF(addr)
	if !ok {
		want = strings.ToLower(strings.TrimSpace(addr))
	}
	for _, raw := range libvirt.HostdevSourcePCIAddresses(live) {
		got, gok := pci.CanonicalBDF(raw)
		if !gok {
			got = strings.ToLower(strings.TrimSpace(raw))
		}
		if got == want {
			return s.virt.DetachHostdev(vmName, addr)
		}
	}
	return nil // already detached — nothing to do
}

// detachHostdevConfigIfPresent is the CONFIG-only counterpart to detachHostdevIfPresent,
// for a SHUT-OFF domain: it removes the PCI hostdev at addr from the PERSISTENT definition
// only if that definition still carries it. For a shut-off defined domain DumpXML returns
// the persistent/inactive config, so the same by-source-BDF membership check correctly
// finds a persisted-but-not-live hostdev (and skips a member that was never persisted). It
// FAILS CLOSED on a DumpXML error (membership cannot be confirmed → do NOT assume the
// device is already gone) and delegates to DetachHostdevConfig, which never touches a
// (nonexistent) live domain — the live-flagged DetachHostdev a shut-off domain rejects.
func (s *Server) detachHostdevConfigIfPresent(vmName, addr string) error {
	live, err := s.virt.DumpXML(vmName)
	if err != nil {
		return err
	}
	want, ok := pci.CanonicalBDF(addr)
	if !ok {
		want = strings.ToLower(strings.TrimSpace(addr))
	}
	for _, raw := range libvirt.HostdevSourcePCIAddresses(live) {
		got, gok := pci.CanonicalBDF(raw)
		if !gok {
			got = strings.ToLower(strings.TrimSpace(raw))
		}
		if got == want {
			return s.virt.DetachHostdevConfig(vmName, addr)
		}
	}
	return nil // not in the persistent definition — nothing to do
}

// AttachDevice hot-attaches a disk, NIC, or PCI device to a running VM.
func (s *Server) AttachDevice(ctx context.Context, req *pb.AttachDeviceRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}

	vmRec, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vmRec == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vmRec), "vm.update", "operator"); err != nil {
		return nil, err
	}
	// Adoption gate (fail-closed): under the active hardware_v2 regime a blocked VM
	// must not have its hardware mutated until it is repaired + re-audited. No-op
	// pre-latch (adoption state is informational only then).
	if err := s.hardwareAdoptionRefused(ctx, vmRec.Name); err != nil {
		return nil, err
	}
	// Disk, NIC, and CONCRETE-ADDRESS PCI attach are journaled, stopped-capable, and
	// at-most-once: each owns its forward decision, the
	// operation_protocol_v1/hardware_v2 gates, and the crash-safe DAG, and records
	// its own device.attached event at the owner level. Only address-selector PCI is
	// converted; SR-IOV/type/vendor/mapping selectors keep the legacy running-only
	// attachPCIDevice path below (their resolve is side-effecting / Unimplemented in
	// the pure resolver, and the foundation UI only creates concrete-address PCI).
	if req.Disk != nil {
		out, err := s.attachDiskEntry(ctx, req, vmRec)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	if req.Nic != nil {
		return s.attachNICEntry(ctx, req, vmRec)
	}
	if req.PciDevice != nil {
		if kind, _ := corrosion.ClassifyPCISelector(req.PciDevice); kind == "address" {
			return s.attachPCIEntry(ctx, req, vmRec)
		}
		// Non-address selectors fall through to the legacy running-only path below.
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		return client.AttachDevice(ctx, req)
	}
	// Mutation barrier: don't hot-plug while a resource operation holds the VM.
	if vmRec.ActiveOperationID != "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot attach a device to %q: an operation is in progress", req.VmName)
	}
	if vmRec.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", req.VmName, vmRec.State)
	}

	var (
		out    *pb.VM
		detail string
	)
	switch {
	case req.PciDevice != nil:
		out, err = s.attachPCIDevice(ctx, req.VmName, req.PciDevice)
		detail = "pci device"
	default:
		return nil, status.Error(codes.InvalidArgument, "one of disk, nic, or pci_device must be specified")
	}
	if err != nil {
		return nil, err
	}
	s.recordVMEvent(ctx, req.VmName, "device.attached", "ok", detail)
	return out, nil
}

// DetachDevice hot-detaches a disk, NIC, or PCI device from a running VM.
func (s *Server) DetachDevice(ctx context.Context, req *pb.DetachDeviceRequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}

	vmRec, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vmRec == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vmRec), "vm.update", "operator"); err != nil {
		return nil, err
	}
	// Adoption gate (fail-closed): under the active hardware_v2 regime a blocked VM
	// must not have its hardware mutated until it is repaired + re-audited. No-op
	// pre-latch (adoption state is informational only then).
	if err := s.hardwareAdoptionRefused(ctx, vmRec.Name); err != nil {
		return nil, err
	}
	// Disk, NIC, and CONCRETE-ADDRESS PCI detach are journaled, stopped-capable, and
	// at-most-once; each owns its forward + gates and records
	// its own device.detached event at the owner level. A PCI address that backs a
	// live address-kind vm_pci_intent takes the journaled path; any other PCI address
	// (attached via the legacy SR-IOV/type path or CreateVM ownership) keeps the
	// legacy running-only detachPCIDevice path below.
	if req.DiskName != "" {
		out, err := s.detachDiskEntry(ctx, req, vmRec)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	if req.NicMac != "" {
		return s.detachNICEntry(ctx, req, vmRec)
	}
	if req.PciAddress != "" {
		_, journaled, ierr := s.liveAddressIntent(ctx, vmRec.Name, req.PciAddress)
		if ierr != nil {
			return nil, status.Errorf(codes.Internal, "read PCI intents for %q: %v", req.VmName, ierr)
		}
		if journaled {
			return s.detachPCIEntry(ctx, req, vmRec)
		}
		// No concrete-address intent → legacy running-only path below.
	}

	if vmRec.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vmRec.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vmRec.HostName, err)
		}
		defer conn.Close()
		return client.DetachDevice(ctx, req)
	}
	// Mutation barrier: don't hot-unplug while a resource operation holds the VM.
	if vmRec.ActiveOperationID != "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot detach a device from %q: an operation is in progress", req.VmName)
	}
	if vmRec.State != "running" {
		return nil, status.Errorf(codes.FailedPrecondition, "VM %q is not running (state: %s)", req.VmName, vmRec.State)
	}

	var (
		out    *pb.VM
		detail string
	)
	switch {
	case req.PciAddress != "":
		out, err = s.detachPCIDevice(ctx, req.VmName, req.PciAddress)
		detail = "pci " + req.PciAddress
	default:
		return nil, status.Error(codes.InvalidArgument, "one of disk_name, nic_mac, or pci_address must be specified")
	}
	if err != nil {
		return nil, err
	}
	s.recordVMEvent(ctx, req.VmName, "device.detached", "ok", detail)
	return out, nil
}

func (s *Server) attachPCIDevice(ctx context.Context, vmName string, spec *pb.DeviceSpec) (*pb.VM, error) {
	// The device lease begins at Stage in_progress: this legacy running-attach path is
	// UNJOURNALED (the lease is its ONLY crash anchor) and the VM ALWAYS already exists, so
	// a crash during the vfio bind or the guest AttachHostdev loop below would otherwise
	// leave a "bound" lease + existing VM that recovery misreads as a completed allocation
	// and clears — leaking the owned + bound device. in_progress makes recovery reclaim it.
	addrs, finish, err := s.allocateDevices(ctx, vmName, []*pb.DeviceSpec{spec}, deviceLeaseStageInProgress)
	if err != nil {
		return nil, err
	}

	// Track the members whose live hostdev attach SUCCEEDED so a rollback can inverse-
	// detach them from the guest BEFORE releasing (never vfio-unbind/release a device
	// that is still attached to the live domain). NOTE: the durable device lease is
	// resolved explicitly — the SUCCESS path records completion (completeDeviceLease:
	// transition to bound, THEN best-effort remove) and a FULLY-completed rollback
	// clears it via finish() — never via a blanket defer, so an incomplete rollback
	// retains the lease for RecoverDeviceLeases.
	var attachedAddrs []string
	for _, addr := range addrs {
		if err := s.virt.AttachHostdev(vmName, addr); err != nil {
			// Roll back only the devices THIS attach claimed (not the VM's pre-existing
			// passthrough devices), in the correct order:
			//   1. inverse-detach every already-attached member from the guest (membership-
			//      aware + idempotent). If an inverse-detach cannot be confirmed (DumpXML
			//      error or a failed DetachHostdev), leave the op recoverable: return WITHOUT
			//      releasing — a member still in the guest must never be unbound/released. The
			//      durable lease is RETAINED as a recovery anchor: it is rewritten to Stage
			//      rollback_incomplete so the next startup recovery distinguishes it from a
			//      completed allocation and membership-aware-reclaims the left-owned+bound
			//      members (guest-detach FIRST, then unbind + owner-release) rather than
			//      clearing it. The safety invariant (a stuck member stays owned + bound, never
			//      unowned + bound) holds regardless; an operator retry/detach also converges it.
			for _, a := range attachedAddrs {
				if derr := s.detachHostdevIfPresent(vmName, a); derr != nil {
					slog.Error("legacy pci attach rollback: inverse-detach failed — device(s) left owned+bound (recoverable), lease marked rollback_incomplete",
						"vm", vmName, "address", a, "error", derr)
					s.markDeviceLeaseRollbackIncomplete(vmName, addrs)
					return nil, status.Errorf(codes.Internal, "attach PCI device %s: %v (rollback inverse-detach of %s failed: %v)", addr, err, a, derr)
				}
			}
			//   2. release via the strict all-or-nothing primitive. If a member cannot be
			//      confirmed unbound it releases NOTHING and errors — leave it owned + bound
			//      (recoverable via retry/detach), never unowned + bound. The durable lease is
			//      RETAINED as a recovery anchor (rewritten to Stage rollback_incomplete): the
			//      next startup recovery reclaims the left-owned+bound members instead of
			//      clearing the entry, so the leak is never silently lost.
			if rerr := s.unbindAndReleaseOwnership(ctx, vmName, addrs); rerr != nil {
				slog.Error("legacy pci attach rollback: release incomplete — device(s) left owned+bound (recoverable), lease marked rollback_incomplete", "vm", vmName, "error", rerr)
				s.markDeviceLeaseRollbackIncomplete(vmName, addrs)
				return nil, status.Errorf(codes.Internal, "attach PCI device %s: %v", addr, err)
			}
			// Rollback FULLY completed (inverse-detach + strict release both clean): nothing is
			// left owned+bound, so clear the durable device lease.
			finish()
			return nil, status.Errorf(codes.Internal, "attach PCI device %s: %v", addr, err)
		}
		attachedAddrs = append(attachedAddrs, addr)
		slog.Info("PCI device attached", "vm", vmName, "address", addr)
	}

	// Success: the VM's devices are attached + owned. Durably transition the in_progress
	// lease to bound BEFORE removing it, so a failed best-effort removal leaves a lease
	// recovery CLEARS (not one it reclaims) — the successfully-attached device is never
	// torn down on restart.
	s.completeDeviceLease(vmName)
	s.publish("device.attached", vmName, fmt.Sprintf("pci:%v", addrs))
	return s.vmToProto(ctx, vmName)
}

func (s *Server) detachPCIDevice(ctx context.Context, vmName, pciAddress string) (*pb.VM, error) {
	// Membership-aware (idempotent) guest detach so a retry converges: if a prior attempt
	// already live-detached the device but its release failed, the device is gone from the
	// guest and a bare DetachHostdev would error ("device not found") and return before
	// re-attempting the release. detachHostdevIfPresent skips the already-gone detach (and
	// fails closed on a DumpXML error) so control falls through to the idempotent release.
	if err := s.detachHostdevIfPresent(vmName, pciAddress); err != nil {
		return nil, status.Errorf(codes.Internal, "detach PCI device %s: %v", pciAddress, err)
	}

	// DetachHostdev removed the GUEST device but the HOST vfio bind persists, so this
	// device is still vfio-bound. Release ownership only through the strict all-or-
	// nothing primitive: if the unbind cannot be confirmed it releases NOTHING and
	// errors, leaving the device owned + bound (recoverable) — NEVER unowned + bound.
	// The legacy running-detach path is un-journaled, so "recoverable" is simply
	// failing the RPC: the operator retries and a since-unbound member (IsBoundToVFIO
	// = false) is skipped, so the release converges.
	if err := s.unbindAndReleaseOwnership(ctx, vmName, []string{pciAddress}); err != nil {
		return nil, status.Errorf(codes.Internal, "release PCI device %s after detach: %v", pciAddress, err)
	}
	slog.Info("PCI device detached", "vm", vmName, "address", pciAddress)
	s.publish("device.detached", vmName, "pci:"+pciAddress)
	return s.vmToProto(ctx, vmName)
}

// countVMDisks returns the number of disks currently attached to a VM.
func countVMDisks(ctx context.Context, db *corrosion.Client, vmName string) int {
	disks, _ := corrosion.ListDisks(ctx, db, vmName)
	return len(disks)
}

// maxDiskSizeGB is a sane upper bound on a requested disk size (in GB). It exists
// so the later uint64(sizeGB)*1024*1024*1024 byte-size conversion can never
// overflow — no real disk request needs a size anywhere near this cap.
const maxDiskSizeGB = 1 << 20 // ~1 PiB

// diskSizeRe matches an exact disk-size string: a run of digits, optional
// whitespace, then an optional unit suffix — and nothing else. The trailing
// $ anchor is what makes parsing exact: any leftover characters (garbage
// after a valid unit, a second token, a decimal point, a bare sign) fail to
// match rather than being silently ignored.
var diskSizeRe = regexp.MustCompile(`^([0-9]+)\s*([A-Za-z]*)$`)

// parseDiskSize parses sizes like "20G", "100G" into GB. It fails closed: a
// non-positive magnitude, an unrecognized unit, a magnitude that would scale
// beyond maxDiskSizeGB, or any input with trailing/malformed content beyond a
// plain "<digits><unit>" are all rejected rather than silently accepted (a
// bare unknown unit must NOT be treated as GiB, and garbage after a valid
// unit must NOT be truncated away).
func parseDiskSize(size string) (int, error) {
	if size == "" {
		return 0, fmt.Errorf("size is required")
	}
	m := diskSizeRe.FindStringSubmatch(size)
	if m == nil {
		return 0, fmt.Errorf("cannot parse %q", size)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q", size)
	}
	unit := m[2]
	if n <= 0 {
		return 0, fmt.Errorf("size must be positive: %q", size)
	}
	// Bound n before it is ever multiplied (the T/TB branch below computes
	// n*1024): without this, a large-but-parseable n can overflow the int64
	// multiply — wrapping to zero or negative — and slip past the final
	// gb > maxDiskSizeGB check with a nil error.
	if n > maxDiskSizeGB {
		return 0, fmt.Errorf("size %q exceeds the maximum allowed disk size", size)
	}
	var gb int
	switch unit {
	case "", "G", "GB", "g", "gb":
		gb = n
	case "T", "TB", "t", "tb":
		gb = n * 1024
	case "M", "MB", "m", "mb":
		if n < 1024 {
			gb = 1
		} else {
			gb = n / 1024
		}
	default:
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}
	if gb > maxDiskSizeGB {
		return 0, fmt.Errorf("size %q exceeds the maximum allowed disk size", size)
	}
	return gb, nil
}
