package grpcapi

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/pci"
)

// SR-IOV policy reason vocabulary (must match metrics/sriov.go).
const (
	sriovReasonPFNotFound  = "pf_not_found"
	sriovReasonPFNotSRIOV  = "pf_not_sriov"
	sriovReasonOverCap     = "vfs_over_cap"
	sriovReasonShortCreate = "short_create"
)

// SetSRIOVPolicy wires this host's SR-IOV VF-pool policy. managedPFs entries are
// canonicalized (a malformed one is warned about + ignored); the canonical set is
// used as BOTH the allowlist and the per-PF mutex key. Validation of each PF against
// live hardware runs in ValidateSRIOVPolicy (also on rescan). Called by the daemon
// once at startup, before serving.
func (s *Server) SetSRIOVPolicy(managed bool, maxVFsPerPF int, managedPFs []string) {
	s.sriovManaged = managed
	if maxVFsPerPF <= 0 {
		maxVFsPerPF = 8
	}
	s.sriovMaxVFs = maxVFsPerPF
	s.sriovManagedPFs = map[string]bool{}
	s.pfLocks = map[string]*sync.Mutex{}
	s.sriovDegraded = map[string]map[string]bool{}
	for _, raw := range managedPFs {
		bdf, ok := pci.CanonicalBDF(raw)
		if !ok {
			slog.Warn("sriov: ignoring malformed managed_pf BDF", "value", raw)
			s.setSRIOVDegraded("", sriovReasonPFNotFound, true) // a config we can't honor is degraded
			continue
		}
		s.sriovManagedPFs[bdf] = true
	}
}

// SetSRIOVMetrics wires the SR-IOV degraded gauge / over-cap counter. Called by the
// daemon after NewSRIOVMetrics.
func (s *Server) SetSRIOVMetrics(m *metrics.SRIOVMetrics) { s.sriovMetrics = m }

// pfLock returns the per-PF serialization mutex for a canonical BDF, creating it on
// first use. The lock covers the whole live-inventory → create → observe → CAS-claim
// critical section; the caller RELEASES it before binding (binding + its rollback run
// later in allocateDevices).
func (s *Server) pfLock(canonBDF string) *sync.Mutex {
	s.pfLocksMu.Lock()
	defer s.pfLocksMu.Unlock()
	if s.pfLocks == nil {
		s.pfLocks = map[string]*sync.Mutex{}
	}
	mu, ok := s.pfLocks[canonBDF]
	if !ok {
		mu = &sync.Mutex{}
		s.pfLocks[canonBDF] = mu
	}
	return mu
}

// setSRIOVDegraded records (or clears) a degraded reason for one PF and recomputes
// the aggregated gauge so a reason reads 1 while ANY PF still has it — a healthy PF's
// rescan can't clear a reason still active on another. A fresh transition into
// over-cap also trips the over-cap counter.
func (s *Server) setSRIOVDegraded(pf, reason string, on bool) {
	s.sriovDegradedMu.Lock()
	if s.sriovDegraded == nil {
		s.sriovDegraded = map[string]map[string]bool{}
	}
	prev := s.sriovDegraded[pf][reason]
	if on {
		if s.sriovDegraded[pf] == nil {
			s.sriovDegraded[pf] = map[string]bool{}
		}
		s.sriovDegraded[pf][reason] = true
	} else if s.sriovDegraded[pf] != nil {
		delete(s.sriovDegraded[pf], reason)
	}
	// Aggregate: is this reason active on ANY PF now?
	anyActive := false
	for _, reasons := range s.sriovDegraded {
		if reasons[reason] {
			anyActive = true
			break
		}
	}
	s.sriovDegradedMu.Unlock()

	s.sriovMetrics.SetDegraded(reason, anyActive)
	if reason == sriovReasonOverCap && on && !prev {
		s.sriovMetrics.OvercapTripped(pf)
	}
}

// sriovDegradedActive reports whether a degraded reason is currently active on ANY
// managed PF — the same aggregation the gauge exposes.
func (s *Server) sriovDegradedActive(reason string) bool {
	s.sriovDegradedMu.Lock()
	defer s.sriovDegradedMu.Unlock()
	for _, reasons := range s.sriovDegraded {
		if reasons[reason] {
			return true
		}
	}
	return false
}

// ValidateSRIOVPolicy checks each configured managed PF against live hardware and
// sets/clears the pf_not_found / pf_not_sriov degraded reasons. Safe to call at
// startup and on every rescan cycle.
func (s *Server) ValidateSRIOVPolicy() {
	if !s.sriovManaged {
		return
	}
	for pf := range s.sriovManagedPFs {
		d, err := pci.ScanDevice(pf)
		if err != nil {
			slog.Warn("sriov: managed PF not found on host", "pf", pf, "error", err)
			s.setSRIOVDegraded(pf, sriovReasonPFNotFound, true)
			continue
		}
		s.setSRIOVDegraded(pf, sriovReasonPFNotFound, false)
		if !d.SRIOVCapable {
			slog.Warn("sriov: managed PF is not SR-IOV capable", "pf", pf)
			s.setSRIOVDegraded(pf, sriovReasonPFNotSRIOV, true)
			continue
		}
		s.setSRIOVDegraded(pf, sriovReasonPFNotSRIOV, false)
	}
}

// RunSRIOVValidation re-validates managed PFs on the given cadence (defaulting to 5
// minutes when rescan is off), so a PF that appears/disappears or loses SR-IOV
// capability updates the degraded gauge. No-op when SR-IOV isn't managed.
func (s *Server) RunSRIOVValidation(ctx context.Context, interval time.Duration) {
	if !s.sriovManaged {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.ValidateSRIOVPolicy()
		}
	}
}

// cappedPoolSize is the VF pool size litevirt will create on a managed PF: the
// configured cap clamped to the PF's hardware total.
func cappedPoolSize(maxVFs, hwTotal int) int {
	if hwTotal > 0 && maxVFs > hwTotal {
		return hwTotal
	}
	return maxVFs
}

// allocateSRIOVVFs resolves `count` SR-IOV VFs for a device spec and returns their
// PCI addresses (the caller binds them). Policy:
//   - REUSE FIRST, any candidate PF: CAS-claim free VFs (DB-unassigned ∩ live) —
//     never writes sriov_numvfs.
//   - CREATE only on an adopted (managed && in managed_pfs), currently EMPTY PF, once,
//     capped to min(max_vfs_per_pf, hw totalvfs); reject requested > cap up front.
//   - A non-empty PF short of free VFs FAILS with no sysfs write (over-cap → DEGRADED,
//     reuse still allowed, creation refused).
//
// The per-PF lock is held only through inventory → create → observe → claim; it is
// released before the caller binds.
func (s *Server) allocateSRIOVVFs(ctx context.Context, vmName string, spec *pb.DeviceSpec, count int) ([]string, error) {
	candidates, err := s.sriovCandidatePFs(ctx, spec)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, status.Errorf(codes.ResourceExhausted,
			"no SR-IOV capable %s device on host %s", spec.Type, s.hostName)
	}

	// Pass 1: reuse existing free VFs on any candidate PF (no sysfs write).
	for _, pf := range candidates {
		if addrs, ok := s.reuseFreeVFs(ctx, pf, vmName, count); ok {
			return addrs, nil
		}
	}

	// Pass 2: create a capped pool on an adopted, empty PF.
	for _, pf := range candidates {
		addrs, created, err := s.createManagedVFs(ctx, pf, vmName, count)
		if err != nil {
			return nil, err
		}
		if created {
			return addrs, nil
		}
	}

	return nil, status.Errorf(codes.ResourceExhausted,
		"no SR-IOV VFs available for %s on host %s: no free VF to reuse and no adopted empty PF to create on",
		spec.Type, s.hostName)
}

// sriovCandidatePFs returns the canonical BDFs of candidate PFs: the explicit parent
// if set, else every SR-IOV capable device of the spec's type in inventory.
func (s *Server) sriovCandidatePFs(ctx context.Context, spec *pb.DeviceSpec) ([]string, error) {
	if spec.Parent != "" {
		bdf, ok := pci.CanonicalBDF(spec.Parent)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "malformed SR-IOV parent BDF %q", spec.Parent)
		}
		return []string{bdf}, nil
	}
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, spec.Type)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list devices: %v", err)
	}
	var pfs []string
	for _, d := range devices {
		if !d.SRIOVCapable {
			continue
		}
		if bdf, ok := pci.CanonicalBDF(d.Address); ok {
			pfs = append(pfs, bdf)
		}
	}
	return pfs, nil
}

// reuseFreeVFs CAS-claims up to `count` free VFs on pf (DB-unassigned ∩ live-present),
// under the PF lock. Returns ok=true only when the full count was claimed; a partial
// claim is rolled back (owner-scoped) so the next PF is tried cleanly.
func (s *Server) reuseFreeVFs(ctx context.Context, pf, vmName string, count int) ([]string, bool) {
	mu := s.pfLock(pf)
	mu.Lock()
	defer mu.Unlock()

	liveVFs, err := pci.ListVFs(pf)
	if err != nil {
		return nil, false
	}
	live := make(map[string]bool, len(liveVFs))
	for _, a := range liveVFs {
		if c, ok := pci.CanonicalBDF(a); ok {
			live[c] = true
		}
	}
	// Over-cap detection: more live VFs than the cap → mark degraded (reuse still ok).
	s.reconcileOverCap(ctx, pf, len(liveVFs))

	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil, false
	}
	var claimed []string
	for _, d := range devices {
		if len(claimed) >= count {
			break
		}
		c, ok := pci.CanonicalBDF(d.Address)
		if !ok || !live[c] {
			continue
		}
		if d.VMName != "" { // already assigned
			continue
		}
		ok2, cerr := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, d.Address, vmName)
		if cerr != nil || !ok2 {
			continue
		}
		claimed = append(claimed, d.Address)
	}
	if len(claimed) < count {
		// Roll back this request's claims so the next PF starts clean.
		for _, a := range claimed {
			_ = corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, a, vmName)
		}
		return nil, false
	}
	return claimed, true
}

// createManagedVFs creates a capped VF pool on pf when pf is adopted (managed &&
// allowlisted) and currently EMPTY, then observes + CAS-claims exactly `count`. It
// returns created=false (no error) when pf is not eligible for creation (not adopted,
// or non-empty), so the caller tries the next candidate. A short create is a failure.
func (s *Server) createManagedVFs(ctx context.Context, pf, vmName string, count int) (addrs []string, created bool, err error) {
	if !s.sriovManaged || !s.sriovManagedPFs[pf] {
		return nil, false, nil // not adopted for creation
	}
	mu := s.pfLock(pf)
	mu.Lock()
	defer mu.Unlock()

	dev, serr := pci.ScanDevice(pf)
	if serr != nil {
		s.setSRIOVDegraded(pf, sriovReasonPFNotFound, true)
		return nil, false, nil
	}
	if !dev.SRIOVCapable {
		s.setSRIOVDegraded(pf, sriovReasonPFNotSRIOV, true)
		return nil, false, nil
	}
	existing, _ := pci.ListVFs(pf)
	if len(existing) != 0 {
		// Non-empty pool: litevirt never resizes it. Over-cap is degraded; either way
		// creation is refused here (reuse was already tried in pass 1).
		s.reconcileOverCap(ctx, pf, len(existing))
		return nil, false, nil
	}

	pool := cappedPoolSize(s.sriovMaxVFs, dev.SRIOVVFsTotal)
	if count > pool {
		return nil, false, status.Errorf(codes.ResourceExhausted,
			"PF %s: request for %d VFs exceeds the managed pool cap %d (max_vfs_per_pf=%d, hw totalvfs=%d)",
			pf, count, pool, s.sriovMaxVFs, dev.SRIOVVFsTotal)
	}

	newVFs, cerr := pci.CreateVFs(pf, pool)
	if cerr != nil {
		s.setSRIOVDegraded(pf, sriovReasonShortCreate, true)
		return nil, false, status.Errorf(codes.Internal, "create VF pool on PF %s: %v", pf, cerr)
	}
	s.setSRIOVDegraded(pf, sriovReasonShortCreate, false)

	// Observe every new VF (records hardware facts, preserves ownership), then
	// CAS-claim exactly `count`.
	for _, vf := range newVFs {
		d, scanErr := pci.ScanDevice(vf)
		if scanErr != nil {
			slog.Warn("sriov: scan new VF failed", "vf", vf, "error", scanErr)
			continue
		}
		_ = corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: s.hostName, Address: d.Address, VendorID: d.VendorID, DeviceID: d.DeviceID,
			VendorName: d.VendorName, DeviceName: d.DeviceName, Type: d.Type,
			IOMMUGroup: d.IOMMUGroup, Driver: d.Driver, NUMANode: d.NUMANode,
			SRIOVCapable: d.SRIOVCapable, SRIOVVFsTotal: d.SRIOVVFsTotal, SRIOVVFsFree: d.SRIOVVFsFree,
		})
	}
	for _, vf := range newVFs {
		if len(addrs) >= count {
			break
		}
		ok, claimErr := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, vf, vmName)
		if claimErr != nil || !ok {
			continue
		}
		addrs = append(addrs, vf)
	}
	if len(addrs) < count {
		for _, a := range addrs {
			_ = corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, a, vmName)
		}
		return nil, false, status.Errorf(codes.Internal,
			"PF %s: created a pool of %d VFs but could only claim %d of the requested %d", pf, len(newVFs), len(addrs), count)
	}
	slog.Info("sriov: created + claimed VFs", "pf", pf, "pool", pool, "claimed", len(addrs), "vm", vmName)
	return addrs, true, nil
}

// reconcileOverCap sets/clears the over-cap degraded reason for a PF given its live VF
// count vs the configured cap. Only meaningful for adopted PFs.
func (s *Server) reconcileOverCap(ctx context.Context, pf string, liveVFs int) {
	_ = ctx
	if !s.sriovManaged || !s.sriovManagedPFs[pf] {
		return
	}
	over := liveVFs > s.sriovMaxVFs
	s.setSRIOVDegraded(pf, sriovReasonOverCap, over)
}
