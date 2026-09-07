package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/network"
)

// claimedAddr is one address claimed from NetBox during a create, held so it can
// be compensated if any later step fails.
type claimedAddr struct {
	Network string
	IP      string
	MAC     string
	// OwnerKind, OwnerHost and Name are the owner triple of the LOCAL
	// ip_allocations lease this claim persisted, and are what releaseAll
	// tombstones it by. ReleaseLease is owner-scoped and refuses a row it does
	// not match, so the triple has to travel with the claim rather than be
	// assumed by the rollback — a claimant with a different owner would
	// otherwise fail its tombstone silently and strand the address.
	//
	// An empty Name means the claim never got as far as a local lease, so there
	// is nothing local to undo.
	OwnerKind string
	OwnerHost string
	Name      string
	Identity  string
	NetBoxID  int
}

// claimSet accumulates the claims one create has taken.
//
// A NetBox claim is a synchronous remote side-effect and cannot join the local
// atomic batch the container path uses, so compensation is explicit.
type claimSet struct {
	srv   *Server
	items []claimedAddr
}

func (c *claimSet) add(a claimedAddr) { c.items = append(c.items, a) }
func (c *claimSet) empty() bool       { return len(c.items) == 0 }

// releaseAll compensates every claim. A release that itself fails leaves an
// address nothing references, so it is enqueued for the sweeper rather than
// dropped — otherwise it is stranded until a human notices.
func (c *claimSet) releaseAll(ctx context.Context) {
	for _, a := range c.items {
		// The LOCAL lease goes first, and a failure to tombstone it stops the
		// remote delete — the same order and the same reason as
		// netboxAllocator.Release. Freeing the address in NetBox while litevirt
		// still holds the lease lets another system take an address litevirt
		// believes is its own; the reverse order only risks an address the
		// orphan sweep can reclaim. A claim that never persisted a lease
		// (Name empty) has nothing local to undo.
		if a.Name != "" {
			if err := network.ReleaseLease(ctx, c.srv.db, a.Network, a.IP, a.MAC, a.OwnerKind, a.OwnerHost, a.Name); err != nil {
				slog.Warn("netbox: local lease tombstone failed during rollback; NetBox delete skipped",
					"address", a.IP, "owner", a.Name, "error", err)
				if eerr := c.srv.enqueueOrphanCheck(ctx, a.Identity); eerr != nil {
					slog.Error("netbox: could not enqueue orphan check — address may be stranded",
						"identity", a.Identity, "error", eerr)
				}
				continue
			}
		}
		if a.NetBoxID == 0 {
			continue
		}
		var releaseErr error
		if c.srv.netbox == nil {
			// A non-zero NetBoxID with no wired client is a programming error (a
			// server that claimed an address without a client could not exist),
			// but panicking mid-rollback is the worst place to discover that.
			// Treat it exactly like a failed release.
			releaseErr = fmt.Errorf("netbox client not wired")
		} else {
			releaseErr = c.srv.netbox.ReleaseIP(ctx, a.NetBoxID)
			if releaseErr != nil {
				// Counted where the API call is, not where the rollback ends: a
				// compensating release is a NetBox request like any other, and
				// leaving it out made a cluster whose rollbacks were all failing
				// read as zero API errors.
				c.srv.nbMetrics().IncAPIError(netbox.Classify(releaseErr))
			}
		}
		if releaseErr != nil {
			slog.Warn("netbox: compensating release failed; enqueueing orphan check",
				"address", a.IP, "netbox_id", a.NetBoxID, "error", releaseErr)
			if eerr := c.srv.enqueueOrphanCheck(ctx, a.Identity); eerr != nil {
				slog.Error("netbox: could not enqueue orphan check — address may be stranded",
					"identity", a.Identity, "error", eerr)
			}
		}
	}
	c.items = nil
}

// enqueueOrphanChecks names every claim in the set for the orphan sweep WITHOUT
// releasing any of them.
//
// This is the compensation-could-not-complete case: the addresses must STAY
// held, because a row that survived an incomplete rollback still names them, and
// freeing an address something still points at is the one outcome the release
// ordering exists to prevent. But a claim nothing will ever come back for is a
// stuck lease, and a stuck lease whose only trace is a log line is invisible.
// Naming each one hands it to the sweep's stuck-lease surfacing, which reports
// exactly this shape: an identity whose local lease is still live with nothing
// driving it forward.
//
// The set is emptied afterwards exactly as releaseAll empties it: this is the
// terminal disposition of every claim in it, so a second caller must not be able
// to enqueue the same identities again (or, worse, release addresses this
// disposition deliberately kept).
func (c *claimSet) enqueueOrphanChecks(ctx context.Context) {
	for _, a := range c.items {
		if a.Identity == "" {
			continue // never got as far as an identity; there is nothing to name
		}
		if eerr := c.srv.enqueueOrphanCheck(ctx, a.Identity); eerr != nil {
			slog.Error("netbox: could not enqueue orphan check for a retained claim — the address may stay stuck until the next full sweep",
				"identity", a.Identity, "error", eerr)
		}
	}
	c.items = nil
}

// enqueueOrphanCheck records that an identity may name an unreferenced NetBox
// object. The full sweep is what resolves it; this only shortens the latency.
func (s *Server) enqueueOrphanCheck(ctx context.Context, identity string) error {
	return corrosion.EnqueueSync(ctx, s.db, "orphan", identity, "check")
}

// vmSpecUUID reads the incarnation uuid out of a stored VM spec — the middle
// component of every netbox.Identity this package builds.
//
// A missing uuid is an ERROR, not an empty string: the uuid is what makes an
// identity incarnation-unique, and an identity built without one names nothing.
// Claiming under it would tag a NetBox object no later lookup could find, and
// enqueueing it would only send the sweeper after an object that does not exist.
func vmSpecUUID(vmSpec string) (string, error) {
	var sp struct {
		Uuid string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(vmSpec), &sp); err != nil {
		return "", fmt.Errorf("parse VM spec for its uuid: %w", err)
	}
	if sp.Uuid == "" {
		return "", fmt.Errorf("VM record carries no uuid")
	}
	return sp.Uuid, nil
}

// nicIdentity builds the NetBox identity ONE NIC of vm claims under: the cluster
// fingerprint + the VM's incarnation uuid + the NIC's mac, exactly as the claim
// paths build it. An identity built any other way names nothing.
func (s *Server) nicIdentity(ctx context.Context, vm *corrosion.VMRecord, mac string) (string, error) {
	fp, ferr := corrosion.ClusterFingerprint(ctx, s.db)
	if ferr != nil {
		return "", fmt.Errorf("cluster fingerprint: %w", ferr)
	}
	vmUUID, uerr := vmSpecUUID(vm.Spec)
	if uerr != nil {
		return "", uerr
	}
	return netbox.Identity(fp, vmUUID, mac), nil
}

// enqueueNICOrphanCheck hands ONE NIC's now-unreferenced NetBox object to the
// orphan sweep. Best effort by construction: every caller has already made the
// LOCAL half durable, so the full sweep is the backstop and a failure here costs
// latency, never correctness — which is why it logs rather than returning.
func (s *Server) enqueueNICOrphanCheck(ctx context.Context, vm *corrosion.VMRecord, nic corrosion.NICRecord) {
	identity, err := s.nicIdentity(ctx, vm, nic.MAC)
	if err != nil {
		slog.Error("netbox: could not build the identity for an orphan check — address may be stranded until the next full sweep",
			"vm", vm.Name, "network", nic.NetworkName, "ip", nic.IP, "error", err)
		return
	}
	if eerr := s.enqueueOrphanCheck(ctx, identity); eerr != nil {
		slog.Error("netbox: could not enqueue orphan check — address may be stranded until the next full sweep",
			"identity", identity, "error", eerr)
	}
}

// releaseOneNICLease gives back EXACTLY one NIC's address, and is the single
// implementation behind BOTH per-NIC releases: DeleteVM's loop over every NIC a
// VM holds, and a hot-detach of the one NIC that is going away. They were
// near-verbatim copies of each other, which is the shape where a fix to one
// silently misses the other.
//
// Keyed on the lease's own (network, ip) primary key, never on (network,
// vm_name): a VM can hold several leases, and a bulk release would free the
// addresses of the NICs that are staying. The LEASE decides whether there is
// anything to release — read owner-scoped, so a foreign row sharing this
// (network, ip) reads back as nil rather than as a row this VM may not retire.
//
// The error return is what the caller SURFACES. A release that failed means
// either the lease is still live (litevirt still holds the address, and the
// operator has to know) or ownership moved underneath — never something to
// swallow.
func (s *Server) releaseOneNICLease(ctx context.Context, vm *corrosion.VMRecord, nic corrosion.NICRecord) error {
	if nic.IP == "" {
		return nil // never addressed — nothing to give back
	}
	lease, lerr := corrosion.GetLeaseByIPForOwner(ctx, s.db, nic.NetworkName, nic.IP, "vm", "", vm.Name)
	if lerr != nil {
		return fmt.Errorf("read lease %s on %s: %w", nic.IP, nic.NetworkName, lerr)
	}
	if lease == nil {
		// No LIVE lease. Either this NIC never allocated one, or an EARLIER
		// release already tombstoned it and then failed its remote half — the one
		// state a re-run cannot finish, because the local row it would prove
		// ownership with is already gone.
		//
		// On a bound network that second case leaves a NetBox object nothing
		// references, which is precisely what the orphan sweep exists for, so
		// name it rather than let it wait for a full sweep. On an unbound network
		// (or one whose binding cannot be resolved) there is no remote authority
		// and nothing to name, and no identity is built — the cluster fingerprint
		// is a read, and the ordinary case must not gain one.
		alloc, _, aerr := s.allocatorFor(ctx, "vm", nic.NetworkName)
		if aerr != nil || alloc == nil {
			return nil
		}
		s.enqueueNICOrphanCheck(ctx, vm, nic)
		return nil
	}

	alloc, _, aerr := s.allocatorFor(ctx, "vm", nic.NetworkName)
	if aerr != nil {
		// A suspended or misconfigured binding must not block a delete or make a
		// NIC undetachable — the workload is going away either way, and a VM that
		// cannot be deleted at all (or a NIC that can never come off) is strictly
		// worse. But skipping the release outright burns the address in BOTH
		// systems: the row is removed while this lease stays LIVE under an owner
		// that no longer exists, and a live lease is exactly what the orphan sweep
		// must never touch (that invariant is what protects a running guest's
		// address), while the guarded upsert in netboxAllocator.persist refuses to
		// reuse a live row even after an operator frees the address in NetBox by
		// hand.
		//
		// So tombstone the LOCAL half directly. The allocator is only needed for
		// the remote half; the local half is a plain owner-scoped write, and
		// owner-scoping still makes it fail loudly if ownership moved.
		slog.Warn("netbox: no allocator for network, releasing the lease locally",
			"vm", vm.Name, "network", nic.NetworkName, "ip", nic.IP, "error", aerr)
		if rerr := network.ReleaseLease(ctx, s.db, nic.NetworkName, nic.IP, nic.MAC, "vm", "", vm.Name); rerr != nil {
			// Same treatment as any other release failure: the lease is still
			// live, so the caller has to know litevirt still holds the address.
			// Nothing destructive has run, so a retry re-runs this.
			return fmt.Errorf("tombstone lease %s on %s: %w", nic.IP, nic.NetworkName, rerr)
		}
		if lease.NetBoxIPID == 0 {
			return nil // a builtin lease: no remote object to hand over
		}
		// The remote object is now UNREFERENCED, which is precisely the case the
		// orphan sweep already handles correctly. Name it so it does not wait for
		// a full sweep to notice.
		//
		// A failure here is logged, not surfaced: the local tombstone already
		// landed, so a re-run would find no lease and could never reach this point
		// again — reporting it as retryable would be a lie, and the full sweep
		// remains the backstop either way.
		s.enqueueNICOrphanCheck(ctx, vm, nic)
		return nil
	}
	if alloc == nil {
		// An UNBOUND network. VMs have never allocated there, so the live lease
		// read above cannot be one of ours to give back; leave it exactly as
		// today's code does rather than newly tombstoning a row this path has
		// never owned.
		return nil
	}

	// The ordinary release: local tombstone then remote delete, in that order,
	// inside the allocator.
	return alloc.Release(ctx, network.ReleaseRequest{
		Network:    nic.NetworkName,
		IP:         nic.IP,
		MAC:        nic.MAC,
		OwnerKind:  "vm",
		OwnerHost:  "", // VM names are cluster-global
		Name:       vm.Name,
		NetBoxIPID: lease.NetBoxIPID,
	})
}

// releaseAllNICLeases gives back EVERY address a VM holds, and is what a path
// that is about to tombstone the VM's row calls first.
//
// DeleteVM has always done this inline and SURFACES a failure, because a delete
// can simply be retried. The other three row-deleting paths cannot: a cutover
// has already renamed the replacement into place, and the stale-record cleanup
// runs precisely because the VM no longer exists anywhere. Blocking those on a
// release failure would leave a duplicate identity or an undeletable ghost row.
//
// So this returns the per-NIC failures rather than deciding for the caller, and
// the callers that must complete anyway log them and hand each NIC to the
// orphan sweep. What none of them may do is stay SILENT: the lease survives the
// row, the sweeper's live-lease veto then refuses to reclaim it forever (that
// veto is what protects a running guest's address), and the result is an
// address stuck in both systems with no metric, no finding and no log line.
func (s *Server) releaseAllNICLeases(ctx context.Context, vm *corrosion.VMRecord) []string {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
	if err != nil {
		return []string{fmt.Sprintf("read NICs: %v", err)}
	}
	var failures []string
	for _, nic := range nics {
		if rerr := s.releaseOneNICLease(ctx, vm, nic); rerr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", nic.NetworkName, rerr))
		}
	}
	return failures
}

// releaseNICLeasesBestEffort is releaseAllNICLeases for the callers that MUST
// complete regardless: it logs at ERROR and names every NIC for the orphan
// sweep, so a stuck lease is surfaced by the stuck-lease detector instead of
// disappearing.
//
// Deliberately returns nothing. A caller that could act on the failure should
// be using releaseAllNICLeases and surfacing it.
func (s *Server) releaseNICLeasesBestEffort(ctx context.Context, vm *corrosion.VMRecord, op string) {
	failures := s.releaseAllNICLeases(ctx, vm)
	if len(failures) == 0 {
		return
	}
	slog.Error("netbox: address release failed before a VM row was removed — the lease may be stuck",
		"op", op, "vm", vm.Name, "failures", failures)
	// Name every NIC, not only the ones that failed: the failure list is keyed
	// by network and a VM can hold several leases on one, and a check the sweep
	// finds nothing for costs one lookup.
	nics, nerr := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
	if nerr != nil {
		slog.Error("netbox: could not read NICs to name them for the orphan sweep — an address may be stranded",
			"op", op, "vm", vm.Name, "error", nerr)
		return
	}
	for _, nic := range nics {
		if nic.IP == "" {
			continue
		}
		s.enqueueNICOrphanCheck(ctx, vm, nic)
	}
}

// ── refusals for the paths that mint a VM without claiming ──────────────────

// refuseIfBound refuses an operation that would put a VM on a NetBox-bound
// network WITHOUT claiming its addresses.
//
// CreateVM is the only create path that claims. Every other way a VM row comes
// into existence — clone, live-restore, import, a renamed promote — builds NIC
// records and persists them with InsertVMWithHardware directly, so on a bound
// network each would hand a guest an address litevirt never reserved: a clone
// and a restore copy the SOURCE's address onto a second VM (a guaranteed
// duplicate, invisible to NetBox), an import carries one in from a foreign
// hypervisor, and a renamed promote writes a second row holding the original's.
// The external IPAM is the authority for that prefix, and none of it asked.
//
// Making those paths claim-aware is a much larger change than the shape of a
// refusal — a clone would have to claim per NIC and compensate across a
// half-built disk set; a restore would have to reconcile a claim against a spec
// that already names an address. Refusing is the fail-closed half, and it is
// what ships: never let a guest hold an address litevirt did not reserve.
//
// Resolution runs through allocatorFor rather than reading the binding row
// directly, so every refusal the selector already makes is INHERITED and cannot
// drift: a config that names a prefix with no binding behind it, a suspended
// binding, a bound network on a node carrying no NetBox client. A nil allocator
// with a nil error is an unbound network — nothing to refuse, and the ordinary
// case must not gain one.
//
// op names the operation in the message ("clone", "restore", …) so the operator
// is told which of several paths declined, and what to do instead.
func (s *Server) refuseIfBound(ctx context.Context, op string, networks []string) error {
	seen := make(map[string]bool, len(networks))
	for _, netName := range networks {
		if netName == "" || seen[netName] {
			continue
		}
		seen[netName] = true
		alloc, _, err := s.allocatorFor(ctx, "vm", netName)
		if err != nil {
			// Not "assume unbound and carry on": an unresolvable network is
			// exactly the state in which allocating around an external authority
			// does the damage. Surfaced verbatim — the selector's messages are
			// already operator-actionable.
			return status.Errorf(codes.FailedPrecondition, "%s: %v", op, err)
		}
		if alloc != nil {
			return status.Errorf(codes.FailedPrecondition,
				"%s is not supported onto the NetBox-bound network %q; create the VM with `lv run` instead",
				op, netName)
		}
	}
	return nil
}

// specNetworkNames is the network list refuseIfBound takes, read off a VM spec.
func specNetworkNames(networks []*pb.NetworkAttachment) []string {
	out := make([]string, 0, len(networks))
	for _, n := range networks {
		if n != nil {
			out = append(out, n.Name)
		}
	}
	return out
}

// refuseRebuildIfBound refuses a rebuild of a VM that holds an address on a
// bound network.
//
// A rebuild is not a create with extra steps. It copies the VM's CURRENT
// address out of vm_interfaces into the new spec as an EXPLICIT one, destroys
// the disks, the firmware state and the row, and only then calls CreateVM —
// which mints a FRESH spec uuid. A NetBox claim is keyed on the identity
// (fingerprint, uuid, mac), so the recreate asks for the old address under a NEW
// identity: the specific-claim is refused as held by another system, and the
// recovery lookup finds the object under the OLD identity. That refusal lands
// AFTER the disks and firmware are gone — the VM is destroyed and cannot be
// recreated.
//
// So the refusal comes FIRST, before anything destructive, the same shape as the
// container refusal in resolveContainerNICs. Making rebuild claim-aware (release
// under the old identity, re-claim under the new, compensate if the recreate then
// fails) is a materially larger change.
//
// The NIC list comes from MergedVMNICs, not from the stored spec: a hot-attached
// NIC exists as a row long before any spec names it, and it is the ROWS a rebuild
// copies its addresses from.
func (s *Server) refuseRebuildIfBound(ctx context.Context, vmName string) error {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		// Fail closed: an unreadable NIC list means we do not know whether this
		// VM holds an external address, and the next step destroys its disks.
		// Retryable — nothing has run yet.
		return status.Errorf(codes.Internal,
			"rebuild %s: could not read its NICs to check for a NetBox-bound network (retry is safe): %v", vmName, err)
	}
	seen := make(map[string]bool, len(nics))
	for _, nic := range nics {
		if nic.NetworkName == "" || seen[nic.NetworkName] {
			continue
		}
		seen[nic.NetworkName] = true
		alloc, _, aerr := s.allocatorFor(ctx, "vm", nic.NetworkName)
		if aerr != nil {
			return status.Errorf(codes.FailedPrecondition, "rebuild %s: %v", vmName, aerr)
		}
		if alloc != nil {
			return status.Errorf(codes.FailedPrecondition,
				"rebuild is not supported for a VM on the NetBox-bound network %q; delete and recreate the VM instead",
				nic.NetworkName)
		}
	}
	return nil
}

// refuseTemplateIfBound refuses converting a VM that holds an address on a bound
// network into a template.
//
// A template is INVISIBLE to the inventory mirror — desiredState skips it — so
// the conversion hands the next sweep a delete: the `virtual_machine` object
// goes, the `vminterface` under it cascades away, and the address is unassigned.
// The local `ip_allocations` row, meanwhile, stays LIVE, because nothing in the
// conversion releases anything.
//
// That is the one combination neither reclaim path can answer. The orphan
// sweeper vetoes on the live lease, and vetoes CORRECTLY — a live lease is
// litevirt still holding the address, and that veto is what protects a running
// guest. The mirror cannot see the VM at all. What is left is an address
// carrying this cluster's identity, assigned to nothing, named by no inventory
// object, and held until an operator finds it by hand.
//
// REFUSED rather than released, and the ordering rule is why. Releasing would
// have to free the address while the NIC row still names it: the row survives the
// conversion (a template keeps its hardware, and `--revert` turns it back into a
// startable VM), so a released address is one the cluster still names — and on
// revert the guest would boot holding an address NetBox may have handed to
// somebody else. Removing the NIC rows instead would make "mark this a template"
// silently reconfigure the VM's hardware, and leave revert producing a VM with no
// network. Never free what the cluster still names; refuse instead.
//
// The remedy in the message is a real one: detaching the NIC releases the lease
// through the same single implementation every other release path uses, and the
// conversion then goes through.
//
// Resolution runs through allocatorFor, so every refusal the selector already
// makes is INHERITED — a suspended binding, a bound network on a node carrying no
// NetBox client — exactly as in the sibling refusals above. The NIC list comes
// from MergedVMNICs, not the stored spec, because a hot-attached NIC holds an
// address long before any spec names it.
func (s *Server) refuseTemplateIfBound(ctx context.Context, vmName string) error {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vmName)
	if err != nil {
		// Fail closed: an unreadable NIC list means we do not know whether this
		// VM holds an external address, and the next step makes it invisible to
		// the mirror. Retryable — nothing has run yet.
		return status.Errorf(codes.Internal,
			"convert %s to a template: could not read its NICs to check for a NetBox-bound network (retry is safe): %v",
			vmName, err)
	}
	seen := make(map[string]bool, len(nics))
	for _, nic := range nics {
		if nic.NetworkName == "" || seen[nic.NetworkName] {
			continue
		}
		seen[nic.NetworkName] = true
		alloc, _, aerr := s.allocatorFor(ctx, "vm", nic.NetworkName)
		if aerr != nil {
			return status.Errorf(codes.FailedPrecondition, "convert %s to a template: %v", vmName, aerr)
		}
		if alloc != nil {
			return status.Errorf(codes.FailedPrecondition,
				"converting to a template is not supported for a VM on the NetBox-bound network %q; "+
					"detach that NIC first — a template is invisible to the inventory mirror, so its "+
					"address would be left held by nothing and reclaimable by neither the mirror nor the sweep",
				nic.NetworkName)
		}
	}
	return nil
}
