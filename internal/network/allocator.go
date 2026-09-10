package network

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ClaimRequest is one address claim. PrefixID and VRFID are set only for a
// NetBox-bound network; Identity is the incarnation-unique NetBox identity and
// is ignored by the builtin allocator.
type ClaimRequest struct {
	Network    string
	Subnet     string
	MAC        string
	OwnerKind  string // "vm" | "ct"
	OwnerHost  string // "" for VMs (names are cluster-global); host for CTs
	Name       string
	Identity   string
	ExplicitIP string
	PrefixID   int
	VRFID      int
	// PrefixCIDR is the binding's ObservedCIDR — the prefix as NetBox reported
	// it at bind time. It is NOT req.Subnet: the litevirt network's subnet and
	// the bound NetBox prefix need not be identical, and containment must be
	// checked against the prefix litevirt actually claims from.
	PrefixCIDR string
}

// ClaimResult is the claimed address. NetBoxIPID is 0 for the builtin allocator.
type ClaimResult struct {
	IP         string
	NetBoxIPID int
}

// ReleaseRequest identifies EXACTLY ONE lease.
//
// IP is required. The pre-existing ReleaseIPFor is a bulk update keyed
// (network, vm_name), so a workload with two NICs on one network had BOTH
// leases tombstoned when the first was released. Carrying the IP — the actual
// (network, ip) primary key — is what makes a release per-NIC.
type ReleaseRequest struct {
	Network    string
	IP         string
	MAC        string
	OwnerKind  string
	OwnerHost  string
	Name       string
	NetBoxIPID int
}

// Allocator claims and releases addresses. Two implementations exist: builtin
// (the pre-existing CRDT allocator) and netbox.
type Allocator interface {
	Claim(ctx context.Context, req ClaimRequest) (ClaimResult, error)
	Release(ctx context.Context, req ReleaseRequest) error
}

type builtinAllocator struct{ db *corrosion.Client }

// NewBuiltinAllocator wraps the pre-existing allocator. It is a LITERAL
// passthrough — same function, same retry loop, same guarded upsert — so the
// interface refactor cannot change what an existing deployment gets.
//
// It is reached ONLY from the container path, which is exactly where
// AllocateIPFor was called before this refactor.
func NewBuiltinAllocator(db *corrosion.Client) Allocator { return &builtinAllocator{db: db} }

func (a *builtinAllocator) Claim(ctx context.Context, req ClaimRequest) (ClaimResult, error) {
	if req.ExplicitIP != "" {
		ok, err := ReserveContainerIP(ctx, a.db, req.Network, req.ExplicitIP, req.MAC, req.OwnerHost, req.Name)
		if err != nil {
			return ClaimResult{}, err
		}
		if !ok {
			return ClaimResult{}, fmt.Errorf("address %s on network %s is already held", req.ExplicitIP, req.Network)
		}
		return ClaimResult{IP: req.ExplicitIP}, nil
	}
	ip, err := AllocateIPFor(ctx, a.db, req.Network, req.Subnet, req.MAC, req.OwnerKind, req.OwnerHost, req.Name)
	if err != nil {
		return ClaimResult{}, err
	}
	return ClaimResult{IP: ip}, nil
}

// Release has NO PRODUCTION CALLER, and that is what keeps ReleaseLease's
// statement shape off a previous-release peer's replication stream.
//
// The shape is new at this release: its fingerprint is absent from the previous
// release's ledgers, and a receiver that cannot place a fingerprint
// back-pressures its whole stream rather than dropping the row. Every path that
// does emit it is a NetBox path, gated behind a bound network and so behind the
// netbox_ipam_v1 latch, which cannot form while a peer is on the old build. This
// method is the exception waiting to happen: allocatorFor hands the builtin
// allocator to a CONTAINER on an unbound network, which is every container in
// every existing deployment, and nothing about that path is gated.
//
// The container delete cascade tombstones leases directly, through
// ReleaseContainerLeases, whose bulk owner-scoped shape the previous release
// already accepts. Routing it through this method instead reads like a tidy-up
// and is a rolling-upgrade regression;
// TestDeleteContainer_ReleasesThroughTheOldLeaseShape fails if it happens.
//
// The method still exists because the Allocator interface is what makes the
// NetBox and builtin paths interchangeable at the call site, and a
// half-implemented interface would be worse. Wiring it up is a change that needs
// its own compatibility decision — the shape must be in the previous release's
// horizon, or the path must be gated — not a refactor.
func (a *builtinAllocator) Release(ctx context.Context, req ReleaseRequest) error {
	return ReleaseLease(ctx, a.db, req.Network, req.IP, req.MAC, req.OwnerKind, req.OwnerHost, req.Name)
}
