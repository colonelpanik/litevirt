package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lb"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// The unified runtime inventory — the ONE local-truth collector every consumer
// reads: the dual-run detector, owner assertion, owner-epoch readiness,
// capacity sampling, and health evidence. It replaces three overlapping
// contracts (ReportRuntime's name-only snapshot, CheckVMRuntime,
// CheckContainerRuntime), each of which answered a narrower question from the
// same underlying probes and could therefore disagree with the others.
//
// The collector reads LOCAL runtime truth only — libvirt, LXC, the kernel, the
// on-disk owner-epoch markers. It never consults the cluster DB for workload
// state (the DB is exactly the disputed value its callers corroborate against);
// database comparison is the caller's job. The single DB read is enumerating
// the CONFIGURED LBs whose VIPs to kernel-check, which is a probe target list,
// not evidence.

// Marker statuses for RuntimeWorkload.MarkerStatus.
const (
	MarkerValid      = "valid"
	MarkerMissing    = "missing"
	MarkerCorrupt    = "corrupt"
	MarkerUnreadable = "unreadable"
)

// runtimeWorkload is one workload as the local runtime actually sees it.
type runtimeWorkload struct {
	Kind             string // corrosion.WorkloadVM | corrosion.WorkloadContainer
	Name             string
	State            string // health.RuntimeRunning / RuntimeDefinedStopped / RuntimeUnknown
	DiskHolder       bool
	CPU              int
	MemoryMiB        int
	OwnerEpochMarker int64
	MarkerStatus     string
	Uncapped         bool
	ProbeError       string
}

// runtimeInventory is one host's full local runtime view.
type runtimeInventory struct {
	Host       string
	Workloads  []runtimeWorkload
	KernelVIPs []string
	// UnresolvedTies is the FLEET-WIDE count across every replicated table. It
	// reports "something is divergent on this node" — the state digest and the
	// dual-run cross-node finding both want it that broad.
	UnresolvedTies int
	// OwnershipTies counts unresolved ties on the ownership tables ONLY. A
	// readiness predicate answers a narrower question than the digest does —
	// "could a tie be hiding the ownership row I am about to certify?" — and only
	// these categories can. See ownershipTieCategory.
	//
	// Carried over the wire since v53 (ownership_tie_count), so a peer's count is
	// a real answer rather than a fabricated zero.
	OwnershipTies int
	Complete      bool
	Errors        []string
	SampledAt     string
}

// ownershipTieCategories are the tie CATEGORIES that can hide an ownership
// decision from OwnerEpochReadiness, and therefore the only ones that withhold
// owner_epoch_v1.
//
// Categories, not table names. This used to be a map of tables maintained here,
// in a package that cannot see internal/corrosion's schema — its own comment
// admitted the hazard ("Adding an owner_epoch column to a table WITHOUT adding
// it here silently narrows one") and nothing could enforce it from here. It was
// already wrong on four tables: runtime_action_proofs, operations,
// operation_steps and project_authority_epochs all carry an owner epoch and all
// answered "not an ownership table".
//
// The resolver already computes a category per conflict and corrosion splits its
// immutable-row conflicts into an ownership and a ledger flavour, so the
// classification is expressed in categories the emitting package defines
// (corrosion.KnownTieCategories) and is checked against them by
// TestOwnershipTieCategory_PartitionsEveryKnownCategory.
//
// An UNRECOGNISED category counts as ownership — fail closed. This latch is
// monotone and never re-opens, so withholding it wrongly is recoverable while
// latching over a live ownership dispute is not.
var ownershipTieCategories = map[string]bool{
	corrosion.TieCategoryRuntimeOwned:       true, // host_name, pending_action_id, active_operation_id
	corrosion.TieCategoryTenancy:            true, // a project ownership split
	corrosion.TieCategoryControlPlane:       true, // hosts.state IS the voting roster this latch is derived from
	corrosion.TieCategoryImmutableOwnership: true,
	corrosion.TieCategoryIdentityContent:    true,
	corrosion.TieCategoryWorkloadIdentity:   true,
	corrosion.TieCategoryUncategorized:      true, // unclassified by the resolver ⇒ unknown ⇒ closed
	corrosion.TieCategoryPolicy:             true, // see below — this one was wrong
	corrosion.TieCategoryOpaque:             true, // and so was this one
}

// nonOwnershipTieCategories are the categories deliberately EXCLUDED. Both maps
// are READ, and TestOwnershipTieCategory_PartitionsEveryKnownCategory fails if
// any corrosion.KnownTieCategories entry is missing from both — which is the
// only reason the partition claim means anything. The previous version of this
// comment claimed "a new category cannot be silently absent from both" while
// the allowlist above was never read by anything, and three emitted categories
// were absent from both on arrival.
//
//   - immutable_ledger_conflict: a contested lease term. Two nodes claiming one
//     tenure is real and must stay visible, but it is not evidence about any
//     workload's owner epoch — the whole point of the fix that scoped this
//     predicate in the first place.
//   - auth_factor: a differing 2FA secret or recovery code (user_2fa,
//     recovery_codes). Fail-to-human by design and never auto-converging, so
//     leaving it in the withholding set — which the missing entry did, via the
//     fail-closed default — withheld the capability permanently for a reason
//     that has nothing to do with any workload's ownership.
//   - auth_pointer, lb_token: the same, for an auth pointer column and an LB
//     bearer token.
//
// Two entries were moved OUT of this map, both of them wrong:
//
//   - policy is not "a policy blob". policyChain is
//     {ruleTombstone(), ruleUnresolved(TieCategoryPolicy)} — an unconditional
//     fail-to-human on any tied difference — and it covers projects,
//     project_quotas, roles, role_bindings, users, tokens, security_groups,
//     sg_rules, ip_sets, the firewall tables, registry_credentials and the
//     notification tables. Two nodes disagreeing about a `projects` row IS a
//     tenancy dispute, and the identical dispute seen on vms.project is
//     categorised tenancy and withholds — so excluding policy made the
//     predicate answer differently depending on which side of the relation
//     diverged.
//   - opaque is vms.spec and containers.create_spec, which are workload rows.
//     It is also where a vms tie LANDS when ruleNumericMax passes on an
//     unparseable vm_owner_epoch (cellStr returns "" for a nil cell and
//     ParseInt fails, so the rule declines to decide) — the one case the
//     narrowing was asserted to be safe against.
//
// "content" is deliberately absent from both maps: the content chains end in
// ruleContentMax and resolve, so no tie is ever tracked under it. It used to
// sit here, which is what made the partition claim look satisfied.
var nonOwnershipTieCategories = map[string]bool{
	corrosion.TieCategoryImmutableLedger: true,
	corrosion.TieCategoryAuthFactor:      true,
	corrosion.TieCategoryAuthPointer:     true,
	corrosion.TieCategoryLBToken:         true,
}

// ownershipTieCategory reports whether a category withholds the owner-epoch
// regime. Unknown ⇒ true (closed), and loudly: the latch is monotone and never
// re-opens, so an unclassified category means this build shipped past the
// partition test.
func ownershipTieCategory(category string) bool {
	if nonOwnershipTieCategories[category] {
		return false
	}
	if ownershipTieCategories[category] {
		return true
	}
	slog.Warn("unclassified unresolved-tie category withholding owner_epoch_v1 by default",
		"category", category)
	return true
}

// find returns the inventory entry for (kind, name), if present.
func (inv *runtimeInventory) find(kind, name string) (runtimeWorkload, bool) {
	for _, w := range inv.Workloads {
		if w.Kind == kind && w.Name == name {
			return w, true
		}
	}
	return runtimeWorkload{}, false
}

// collectRuntimeInventory builds this host's inventory.
//
// Error discipline, unchanged from the snapshot it replaces: any probe error
// makes the inventory INCOMPLETE rather than being swallowed into a
// false-empty result — a reachable host with broken libvirt must not read as
// "positively probed and absent", which would both mask a dual-run and forge
// owner-mismatch evidence. Positive entries gathered before an error are still
// valid; only ABSENCE becomes unreliable. A per-item error marks that ITEM,
// and the inventory incomplete, but does not blind the rest of the host.
func (s *Server) collectRuntimeInventory(ctx context.Context) runtimeInventory {
	inv := runtimeInventory{
		Host:      s.hostName,
		Complete:  true,
		SampledAt: time.Now().UTC().Format(time.RFC3339),
	}
	fail := func(f string, args ...interface{}) {
		inv.Complete = false
		inv.Errors = append(inv.Errors, fmt.Sprintf(f, args...))
	}

	// VMs. Every DEFINED domain is listed (a stopped-but-defined domain is
	// runtime state the DB comparison needs), with running domains marked as
	// disk-holders exactly as before: DomainState=="running" is RUNNING|BLOCKED,
	// so a PAUSED incoming-migration target is correctly not a holder.
	if s.virt != nil {
		names, err := s.virt.ListDomains()
		if err != nil {
			fail("list domains: %v", err)
		}
		for _, n := range names {
			w := runtimeWorkload{Kind: corrosion.WorkloadVM, Name: n}
			st, err := s.virt.DomainState(n)
			switch {
			case err != nil:
				w.State = health.RuntimeUnknown
				w.ProbeError = fmt.Sprintf("domain state: %v", err)
				fail("domain %s state: %v", n, err)
			case st == "running":
				w.State = health.RuntimeRunning
				w.DiskHolder = true
			default:
				w.State = health.RuntimeDefinedStopped
			}
			if xmlDef, err := s.virt.DumpXML(n); err != nil {
				if w.ProbeError == "" {
					w.ProbeError = fmt.Sprintf("dump xml: %v", err)
				}
				fail("domain %s xml: %v", n, err)
			} else {
				w.CPU = lv.CurrentVCPUFromXML(xmlDef)
				w.MemoryMiB = lv.CurrentMemoryMiBFromXML(xmlDef)
			}
			w.OwnerEpochMarker, w.MarkerStatus = s.readVMMarker(n)
			if w.MarkerStatus == MarkerUnreadable {
				fail("vm %s owner-epoch marker unreadable", n)
			}
			inv.Workloads = append(inv.Workloads, w)
		}
	}

	// Containers — only on an LXC-capable host (a non-LXC host has no local
	// containers to miss, so it is neither probed nor marked incomplete).
	if s.containerRuntime != nil && lxcCapable() {
		names, err := s.containerRuntime.ListContainers(ctx)
		if err != nil {
			fail("list containers: %v", err)
		}
		for _, n := range names {
			w := runtimeWorkload{Kind: corrosion.WorkloadContainer, Name: n}
			st, err := s.containerRuntime.StateContainer(ctx, n)
			switch {
			case err != nil:
				w.State = health.RuntimeUnknown
				w.ProbeError = fmt.Sprintf("container state: %v", err)
				fail("container %s state: %v", n, err)
			case st == "running":
				w.State = health.RuntimeRunning
			case st == "stopped":
				w.State = health.RuntimeDefinedStopped
			default:
				w.State = health.RuntimeUnknown
			}
			cpu, mem, err := s.containerRuntime.ContainerLimits(ctx, n)
			if err != nil {
				if w.ProbeError == "" {
					w.ProbeError = fmt.Sprintf("container limits: %v", err)
				}
				fail("container %s limits: %v", n, err)
			} else {
				w.CPU, w.MemoryMiB = cpu, mem
				// Uncapped is per the dimension that matters. MEMORY is the only
				// host-reservable container dimension (cpu_limit is cgroup shares,
				// not a vCPU reservation — host capacity never counts it), so a
				// container with no memory cap is unbounded in the dimension
				// capacity accounting cares about, whatever its CPU shares say.
				// The old cpu==0 && mem==0 form classified a cpu-limited,
				// memory-unlimited container as bounded: it was charged 0 MiB,
				// left the observation Complete, and slid past the rogue gate —
				// unbounded consumption counted as zero.
				w.Uncapped = mem == 0
			}
			w.OwnerEpochMarker, w.MarkerStatus = s.readContainerMarker(n)
			if w.MarkerStatus == MarkerUnreadable {
				fail("container %s owner-epoch marker unreadable", n)
			}
			inv.Workloads = append(inv.Workloads, w)
		}
	}

	// VIP addresses assigned on THIS host's KERNEL. The kernel check is
	// authoritative — a VRRP backup renders the config but holds no address.
	cfgs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		fail("list LB configs: %v", err)
	} else {
		var vips []string
		for _, cfg := range cfgs {
			if cfg.Enabled && cfg.VIP != "" {
				vips = append(vips, cfg.VIP)
			}
		}
		if assigned, err := lb.NewManager().AssignedVIPs(vips); err != nil {
			fail("kernel VIP dump: %v", err)
		} else {
			for v := range assigned {
				inv.KernelVIPs = append(inv.KernelVIPs, v)
			}
		}
	}

	if s.db != nil {
		// ONE lock acquisition, and the fleet-wide total is DERIVED from the same
		// snapshot rather than read separately. Two acquisitions could straddle a
		// concurrent merge and yield a snapshot where OwnershipTies exceeded
		// UnresolvedTies — its own superset — so readiness withheld while the state
		// digest on the same snapshot reported the node clean.
		for category, n := range s.db.UnresolvedTieCategories() {
			inv.UnresolvedTies += n
			if ownershipTieCategory(category) {
				inv.OwnershipTies += n
			}
		}
	}
	return inv
}

// readVMMarker reads the host-local VM owner-epoch marker and classifies the
// outcome. Corrupt or unreadable is NEVER reported as epoch 0 — garbage read as
// the zero generation would authorize exactly the stale actions the marker
// exists to refuse.
func (s *Server) readVMMarker(name string) (int64, string) {
	if s.dataDir == "" {
		return 0, MarkerMissing
	}
	return classifyMarker(health.ReadVMOwnerEpochMarker(s.dataDir, name))
}

func (s *Server) readContainerMarker(name string) (int64, string) {
	if s.containersRoot == "" {
		return 0, MarkerMissing
	}
	return classifyMarker(health.ReadContainerOwnerEpochMarker(s.containersRoot, name))
}

func classifyMarker(epoch int64, found bool, err error) (int64, string) {
	switch {
	// Keyed off the sentinel and the wrapper text, not the text alone. A
	// pre-epoch marker must classify as CORRUPT: MarkerUnreadable makes
	// collectRuntimeInventory fail the whole host's inventory as
	// not-decision-complete, which suppresses owner-assert for every workload on
	// it — a host-wide outage of the checks, from one VM's bad marker.
	case errors.Is(err, health.ErrPreEpochMarker):
		return 0, MarkerCorrupt
	case err != nil && strings.Contains(err.Error(), "corrupt"):
		return 0, MarkerCorrupt
	case err != nil:
		return 0, MarkerUnreadable
	case !found:
		return 0, MarkerMissing
	default:
		return epoch, MarkerValid
	}
}

// GetRuntimeInventory serves this host's inventory to a peer. Peer-only
// (host-cert mTLS), so an operator bearer credential can't probe runtime state.
// A (kind, name) filter narrows to one workload — the targeted form owner
// assertion uses. A filtered request for an absent workload returns an
// inventory with no entries; ABSENCE is only meaningful when Complete is true.
func (s *Server) GetRuntimeInventory(ctx context.Context, req *pb.GetRuntimeInventoryRequest) (*pb.RuntimeInventory, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if (req.GetKind() == "") != (req.GetName() == "") {
		return nil, status.Error(codes.InvalidArgument, "a workload filter needs both kind and name")
	}
	inv := s.collectRuntimeInventory(ctx)
	if req.GetKind() != "" {
		filtered := inv
		filtered.Workloads = nil
		if w, ok := inv.find(req.GetKind(), req.GetName()); ok {
			filtered.Workloads = []runtimeWorkload{w}
		}
		inv = filtered
	}
	return inventoryToProto(inv), nil
}

func inventoryToProto(inv runtimeInventory) *pb.RuntimeInventory {
	out := &pb.RuntimeInventory{
		Host:               inv.Host,
		KernelAssignedVips: inv.KernelVIPs,
		UnresolvedTieCount: int32(inv.UnresolvedTies),
		OwnershipTieCount:  int32(inv.OwnershipTies),
		Complete:           inv.Complete,
		Errors:             inv.Errors,
		SampledAt:          inv.SampledAt,
	}
	for _, w := range inv.Workloads {
		out.Workloads = append(out.Workloads, &pb.RuntimeWorkload{
			Kind: w.Kind, Name: w.Name, State: w.State,
			DiskHolder: w.DiskHolder, Cpu: int32(w.CPU), MemoryMib: int32(w.MemoryMiB),
			OwnerEpochMarker: w.OwnerEpochMarker, MarkerStatus: w.MarkerStatus,
			Uncapped: w.Uncapped, ProbeError: w.ProbeError,
		})
	}
	return out
}

func inventoryFromProto(p *pb.RuntimeInventory) runtimeInventory {
	inv := runtimeInventory{
		Host:           p.GetHost(),
		KernelVIPs:     p.GetKernelAssignedVips(),
		UnresolvedTies: int(p.GetUnresolvedTieCount()),
		OwnershipTies:  int(p.GetOwnershipTieCount()),
		Complete:       p.GetComplete(),
		Errors:         p.GetErrors(),
		SampledAt:      p.GetSampledAt(),
	}
	for _, w := range p.GetWorkloads() {
		inv.Workloads = append(inv.Workloads, runtimeWorkload{
			Kind: w.GetKind(), Name: w.GetName(), State: w.GetState(),
			DiskHolder: w.GetDiskHolder(), CPU: int(w.GetCpu()), MemoryMiB: int(w.GetMemoryMib()),
			OwnerEpochMarker: w.GetOwnerEpochMarker(), MarkerStatus: w.GetMarkerStatus(),
			Uncapped: w.GetUncapped(), ProbeError: w.GetProbeError(),
		})
	}
	return inv
}

// getPeerRuntimeInventory dials a peer for its inventory, optionally filtered.
func (s *Server) getPeerRuntimeInventory(ctx context.Context, host, kind, name string) (runtimeInventory, error) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return runtimeInventory{}, err
	}
	defer conn.Close()
	resp, err := client.GetRuntimeInventory(ctx, &pb.GetRuntimeInventoryRequest{Kind: kind, Name: name})
	if err != nil {
		return runtimeInventory{}, err
	}
	return inventoryFromProto(resp), nil
}

// CheckPeerVMRuntime asks a peer for its local libvirt view of one VM, in the
// shared runtime vocabulary. It is the hook the owner-assert reconciler uses
// (via SetPeerRuntimeChecker) — now answered from the unified inventory. An
// INCOMPLETE peer inventory reports unknown, never absent: partial coverage
// must not become absence proof.
func (s *Server) CheckPeerVMRuntime(ctx context.Context, host, name string) (string, error) {
	return s.checkPeerRuntime(ctx, host, corrosion.WorkloadVM, name)
}

// CheckPeerContainerRuntime is the container twin.
func (s *Server) CheckPeerContainerRuntime(ctx context.Context, host, name string) (string, error) {
	return s.checkPeerRuntime(ctx, host, corrosion.WorkloadContainer, name)
}

func (s *Server) checkPeerRuntime(ctx context.Context, host, kind, name string) (string, error) {
	inv, err := s.getPeerRuntimeInventory(ctx, host, kind, name)
	if err != nil {
		return "", err
	}
	if w, ok := inv.find(kind, name); ok {
		return w.State, nil
	}
	if !inv.Complete {
		// The workload was not listed, but the probe could not see everything —
		// that is "unknown", not "absent".
		return health.RuntimeUnknown, nil
	}
	return health.RuntimeAbsent, nil
}

// localVMRuntime maps this host's libvirt state to the shared runtime
// vocabulary — kept for the local half of owner assertion.
func (s *Server) localVMRuntime(name string) string {
	if s.virt == nil {
		return health.RuntimeUnknown
	}
	if !s.virt.DomainExists(name) {
		return health.RuntimeAbsent
	}
	state, err := s.virt.DomainState(name)
	if err != nil {
		return health.RuntimeUnknown
	}
	if state == "running" {
		return health.RuntimeRunning
	}
	return health.RuntimeDefinedStopped
}

// snapshotFromInventory derives the dual-run detector's grouping view from an
// inventory: disk-holder VMs, running containers, kernel VIPs, tie count, and
// the partial flag (inverse of Complete).
func snapshotFromInventory(inv runtimeInventory) runtimeSnapshot {
	snap := runtimeSnapshot{
		kernelVIPs:     inv.KernelVIPs,
		unresolvedTies: inv.UnresolvedTies,
		partial:        !inv.Complete,
		vmMarkers:      map[string]markerInfo{},
		ctMarkers:      map[string]markerInfo{},
	}
	for _, w := range inv.Workloads {
		switch {
		case w.Kind == corrosion.WorkloadVM && w.DiskHolder:
			snap.diskHolderVMs = append(snap.diskHolderVMs, w.Name)
			snap.vmMarkers[w.Name] = markerInfo{epoch: w.OwnerEpochMarker, status: w.MarkerStatus}
		case w.Kind == corrosion.WorkloadContainer && w.State == health.RuntimeRunning:
			snap.runningCTs = append(snap.runningCTs, w.Name)
			snap.ctMarkers[w.Name] = markerInfo{epoch: w.OwnerEpochMarker, status: w.MarkerStatus}
		}
	}
	return snap
}

// markerInfo is one running workload's owner-epoch marker as its host reported it.
type markerInfo struct {
	epoch  int64
	status string
}
