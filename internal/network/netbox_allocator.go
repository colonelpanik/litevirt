package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// ErrClaimUnknown means the claim was refused AND a NetBox object may exist that
// nothing local references. Callers must enqueue an orphan follow-up; the full
// sweep resolves it.
//
// It is returned for ANY inconclusive outcome regardless of status code — a 4xx
// included, because a 400 "duplicate" can mean our own earlier POST committed.
var ErrClaimUnknown = errors.New("netbox claim outcome unknown")

// ErrAddressNotOurs is a DEFINITE refusal: an ip_address object for the
// requested address exists in NetBox and litevirt may not take it, because it
// does not carry this cluster's identity.
//
// It covers both shapes of "not ours", which are one rule and not two:
//
//   - it carries ANOTHER identity — another litevirt installation's, or another
//     cluster's after a fingerprint move. Taking it is the "seize a co-tenant's
//     objects" failure the re-key design forbids outright.
//   - it carries NO identity — an operator-created object, a reservation, or a
//     row some other IPAM tool wrote. Stamping litevirt's identity onto a record
//     it did not create is not a read-only annotation: the identity is exactly
//     what authorizes the orphan sweep to DELETE the object under a whole-cluster
//     negative proof, so adopting one hands somebody else's reservation to a
//     garbage collector.
//
// Deliberately NOT an ErrClaimUnknown. The outcome here is known — NetBox
// answered, and the answer was no — so a caller must NOT enqueue an orphan
// follow-up for an object that was never litevirt's.
var ErrAddressNotOurs = errors.New("netbox address is not litevirt's to claim")

// claimSource records where an IPAddress came from, which decides whether
// litevirt may DELETE it when local persistence fails.
type claimSource int

const (
	// sourcePOST: this call's own POST returned 2xx, so this call created the
	// object and may safely compensate by deleting it.
	sourcePOST claimSource = iota
	// sourceRecovered: found by lookup after an inconclusive response. It may
	// PREDATE this call — created by the original attempt or a concurrent one —
	// and may already be in use by a live guest. It must never be deleted here.
	sourceRecovered
)

// netboxAPI is the slice of the client this allocator needs, so tests can stub
// it without an HTTP server.
type netboxAPI interface {
	ClaimAvailableIP(ctx context.Context, prefixID int, identity string) (netbox.IPAddress, error)
	ClaimSpecificIP(ctx context.Context, address string, vrfID int, identity string) (netbox.IPAddress, error)
	LookupByAddress(ctx context.Context, address string, vrfID int) ([]netbox.IPAddress, error)
	LookupByIdentity(ctx context.Context, identity string, vrfID int, prefixCIDR string) ([]netbox.IPAddress, error)
	ReleaseIP(ctx context.Context, id int) error
}

type netboxAllocator struct {
	db      *corrosion.Client
	nb      netboxAPI
	metrics apiErrorCounter
}

// apiErrorCounter records NetBox outcomes for metrics. Classification is used
// ONLY here — never to decide whether a write happened.
//
// It is a narrower view of the same sink grpcapi passes down (its netboxMetrics
// interface), so a type satisfying that one satisfies this one structurally and
// this package imports nothing from grpcapi or internal/metrics.
type apiErrorCounter interface {
	IncAPIError(class netbox.ErrClass)
	// IncAmbiguousClaim counts one claim whose outcome litevirt could not read
	// off the response and had to resolve by lookup. It is invisible to the
	// caller — a recovered claim returns an address like any other — so this
	// counter is the only place a cluster losing NetBox responses shows up
	// before an orphan does.
	IncAmbiguousClaim()
}

// NewNetBoxAllocator claims addresses from NetBox. There is no local fallback:
// while NetBox is unreachable, a claim on a bound network refuses.
func NewNetBoxAllocator(db *corrosion.Client, nb netboxAPI, m apiErrorCounter) Allocator {
	return &netboxAllocator{db: db, nb: nb, metrics: m}
}

func (a *netboxAllocator) Claim(ctx context.Context, req ClaimRequest) (ClaimResult, error) {
	var (
		ip  netbox.IPAddress
		err error
	)
	if req.ExplicitIP != "" {
		ip, err = a.nb.ClaimSpecificIP(ctx, req.ExplicitIP, req.VRFID, req.Identity)
	} else {
		ip, err = a.nb.ClaimAvailableIP(ctx, req.PrefixID, req.Identity)
	}
	if err == nil {
		// Validated on BOTH paths. A successful POST is not self-evidently in
		// scope: if the prefix was re-CIDRed between the last revalidation and
		// this claim, NetBox can hand back an address outside the recorded
		// binding, and skipping the check would send it straight to cloud-init.
		if verr := validateClaim(req, ip); verr != nil {
			// Our own POST created it, so compensating is safe here.
			if rerr := a.nb.ReleaseIP(ctx, ip.ID); rerr != nil {
				return ClaimResult{}, fmt.Errorf("%w: out-of-scope claim (%v) and release failed (%v)",
					ErrClaimUnknown, verr, rerr)
			}
			return ClaimResult{}, verr
		}
		return a.persist(ctx, req, ip, sourcePOST)
	}
	// Recovery runs after EVERY non-2xx, including a 4xx.
	//
	// Inferring "nothing was created" from a 4xx is exactly the status-code
	// inference the design forbids, and it has a concrete failure: our own
	// earlier POST commits, its response is lost, the retry returns 400
	// "duplicate address" — the object is OURS and should be adopted. Refusing
	// without a lookup strands an orphan nobody ever looks for.
	//
	// Classification survives for METRICS only.
	a.metrics.IncAPIError(netbox.Classify(err))
	recovered, rerr := a.recover(ctx, req)
	if rerr != nil {
		return ClaimResult{}, rerr
	}
	return a.persist(ctx, req, recovered, sourceRecovered)
}

// recover resolves an ambiguous claim by lookup. It NEVER infers the outcome
// from a status code, and it never treats a zero-result lookup as proof the
// POST will not commit — the original request may still be executing.
func (a *netboxAllocator) recover(ctx context.Context, req ClaimRequest) (netbox.IPAddress, error) {
	// Counted at ENTRY, not on success: an ambiguous claim is ambiguous whether
	// or not the lookup manages to resolve it, and the unresolved ones are the
	// ones that leave an orphan behind.
	a.metrics.IncAmbiguousClaim()

	byIdentity, err := a.nb.LookupByIdentity(ctx, req.Identity, req.VRFID, req.PrefixCIDR)
	if err != nil {
		return netbox.IPAddress{}, fmt.Errorf("%w: identity lookup failed: %v", ErrClaimUnknown, err)
	}
	if len(byIdentity) > 1 {
		return netbox.IPAddress{}, fmt.Errorf("%w: %d objects share identity %s",
			ErrClaimUnknown, len(byIdentity), req.Identity)
	}
	// Belt and braces on top of the scoped query.
	for _, c := range byIdentity {
		if verr := validateClaim(req, c); verr != nil {
			return netbox.IPAddress{}, fmt.Errorf("%w: %v", ErrClaimUnknown, verr)
		}
	}

	if req.ExplicitIP == "" {
		// DYNAMIC claim: NetBox never told us which address it picked, so an
		// address lookup is impossible. Identity is the only recovery.
		if len(byIdentity) == 0 {
			return netbox.IPAddress{}, fmt.Errorf("%w: no object carries identity %s yet",
				ErrClaimUnknown, req.Identity)
		}
		return byIdentity[0], nil
	}

	// EXPLICIT claim: cross-check. Disagreement is unknown, not a decision.
	byAddress, err := a.nb.LookupByAddress(ctx, req.ExplicitIP, req.VRFID)
	if err != nil {
		return netbox.IPAddress{}, fmt.Errorf("%w: address lookup failed: %v", ErrClaimUnknown, err)
	}
	switch {
	case len(byIdentity) == 1 && len(byAddress) == 1 && byIdentity[0].ID == byAddress[0].ID:
		return byIdentity[0], nil
	case len(byAddress) == 1 && byAddress[0].Identity != "" && byAddress[0].Identity != req.Identity:
		// The foreign identity is NAMED. Without it the operator is told an
		// address is taken and given nothing to look up: which installation
		// holds it, and whether it is a co-tenant cluster or this one's own
		// pre-rekey fingerprint, is the whole of what decides what to do next.
		return netbox.IPAddress{}, fmt.Errorf(
			"%w: address %s is object %d in NetBox carrying identity %q, not this cluster's %q",
			ErrAddressNotOurs, req.ExplicitIP, byAddress[0].ID, byAddress[0].Identity, req.Identity)
	case len(byAddress) == 1 && byAddress[0].Identity == "":
		// An object with NO litevirt identity. Refused, not adopted — see
		// ErrAddressNotOurs. Named separately from the case above because the
		// remedy is different and specific: an identity-less object is almost
		// always an operator's own row, and deleting it in NetBox so litevirt can
		// create it properly is the action that resolves this.
		return netbox.IPAddress{}, fmt.Errorf(
			"%w: address %s already exists as NetBox object %d with no litevirt identity — an "+
				"operator-created object or a reservation. litevirt will not stamp its identity "+
				"onto a record it did not create, because that identity is what would later "+
				"authorize the orphan sweep to delete it. Remove that object in NetBox and let "+
				"litevirt create the address itself, or move the workload off %s",
			ErrAddressNotOurs, req.ExplicitIP, byAddress[0].ID, req.ExplicitIP)
	default:
		return netbox.IPAddress{}, fmt.Errorf("%w: address and identity lookups disagree for %s",
			ErrClaimUnknown, req.ExplicitIP)
	}
}

// persist writes the lease alongside its NetBox join keys.
//
// The upsert is GUARDED and confirmed by read-back, mirroring AllocateIPFor's
// existing pattern: an unconditional ON CONFLICT DO UPDATE would let a NetBox
// result silently steal a LIVE (network, ip) row.
//
// If persistence fails the remote claim is compensated HERE, because the caller
// has not yet added it to its claim set and so cannot compensate it.
func (a *netboxAllocator) persist(ctx context.Context, req ClaimRequest, ip netbox.IPAddress, src claimSource) (ClaimResult, error) {
	// The lease key is the PARSED address in canonical form, never a textual
	// strip of ip.Address. ip_allocations is keyed on (network, ip), and one
	// IPv6 address has many spellings — "2001:db8::1" and "2001:0db8::1" are the
	// same address but different text. Keyed on text, NetBox handing back a
	// differently-spelled form of an address litevirt already leases would open
	// a SECOND row for it, and the guarded upsert that exists to stop a live
	// lease being stolen would never even see the row it has to lose to.
	//
	// validateClaim has already parsed this strictly on both routes into persist,
	// so a failure here cannot happen by construction — but it is handled rather
	// than assumed, and handled fail-closed: ErrClaimUnknown, so the caller
	// enqueues the orphan follow-up instead of this deleting an object it could
	// not even read.
	addr, perr := parseHostCIDR(ip.Address)
	if perr != nil {
		return ClaimResult{}, fmt.Errorf("%w: claimed address %q is unparseable: %v",
			ErrClaimUnknown, ip.Address, perr)
	}
	bare := addr.String()
	res, err := a.persistGuarded(ctx, req, ip, bare)
	if err == nil {
		return res, nil
	}

	// PROVENANCE decides whether compensation is permitted.
	//
	// A RECOVERED object may predate this call — created by the original attempt
	// or a concurrent one — and may already be in use by a live guest. Deleting
	// it here would free a live address, which is the exact failure the whole
	// fail-closed design exists to prevent. Leave it and let the orphan sweep,
	// which requires whole-cluster proof, decide.
	if src == sourceRecovered {
		return ClaimResult{}, fmt.Errorf("%w: persist failed for a recovered object (%v); not deleting it",
			ErrClaimUnknown, err)
	}

	// This call's own POST created it, so deleting it frees only what we made.
	if rerr := a.nb.ReleaseIP(ctx, ip.ID); rerr != nil {
		return ClaimResult{}, fmt.Errorf("%w: persist failed (%v) and compensating release failed (%v)",
			ErrClaimUnknown, err, rerr)
	}
	return ClaimResult{}, err
}

func (a *netboxAllocator) persistGuarded(ctx context.Context, req ClaimRequest, ip netbox.IPAddress, bare string) (ClaimResult, error) {
	// Only resurrect a tombstone; a LIVE row makes this a no-op.
	if err := a.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(network, ip) DO UPDATE SET
		   mac = excluded.mac, vm_name = excluded.vm_name,
		   owner_kind = excluded.owner_kind, owner_host = excluded.owner_host,
		   netbox_ip_id = excluded.netbox_ip_id,
		   netbox_prefix_id = excluded.netbox_prefix_id,
		   updated_at = excluded.updated_at, deleted_at = NULL
		 WHERE ip_allocations.deleted_at IS NOT NULL`,
		req.Network, bare, req.MAC, req.Name, req.OwnerKind, req.OwnerHost,
		ip.ID, req.PrefixID, a.db.NowWall(), a.db.NowTS()); err != nil {
		return ClaimResult{}, fmt.Errorf("persist lease: %w", err)
	}
	// Read back on EVERY persisted field. A guarded upsert that lost to a live
	// row is a NO-OP, not an error, so only a confirmed read proves we hold it —
	// and an owner-only check is not enough: with two NICs on one VM and network,
	// the OTHER NIC's lease satisfies an owner-only predicate.
	held, err := leaseHeldByExact(ctx, a.db, leaseIdentity{
		Network:    req.Network,
		IP:         bare,
		MAC:        req.MAC,
		OwnerKind:  req.OwnerKind,
		OwnerHost:  req.OwnerHost,
		Name:       req.Name,
		NetBoxIPID: ip.ID,
		PrefixID:   req.PrefixID,
	})
	if err != nil {
		return ClaimResult{}, fmt.Errorf("confirm lease: %w", err)
	}
	if !held {
		return ClaimResult{}, fmt.Errorf("address %s on %s is already held by a live lease", bare, req.Network)
	}
	return ClaimResult{IP: bare, NetBoxIPID: ip.ID}, nil
}

// leaseIdentity is every field a NetBox-backed lease persists.
type leaseIdentity struct {
	Network    string
	IP         string
	MAC        string
	OwnerKind  string
	OwnerHost  string
	Name       string
	NetBoxIPID int
	PrefixID   int
}

// leaseHeldByExact confirms a LIVE lease matching every field.
//
// The pre-existing ipLeaseHeldBy checks only (network, ip, owner tuple), which
// cannot distinguish two NICs of the same VM on the same network.
func leaseHeldByExact(ctx context.Context, db *corrosion.Client, l leaseIdentity) (bool, error) {
	rows, err := db.Query(ctx,
		`SELECT 1 AS ok FROM ip_allocations
		 WHERE network = ? AND ip = ? AND mac = ? AND vm_name = ?
		   AND owner_kind = ? AND owner_host = ?
		   AND COALESCE(netbox_ip_id, 0) = ? AND COALESCE(netbox_prefix_id, 0) = ?
		   AND deleted_at IS NULL`,
		l.Network, l.IP, l.MAC, l.Name, l.OwnerKind, l.OwnerHost, l.NetBoxIPID, l.PrefixID)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// validateClaim is the single scope check every claimed address passes, whether
// it came from this call's POST or from recovery lookup.
//
// One path for both, because the ways an address can be out of scope do not
// depend on how it was obtained: a re-CIDR between revalidation and claim, a
// VRF move, or a malformed address all reach either route.
func validateClaim(req ClaimRequest, ip netbox.IPAddress) error {
	if ip.ID == 0 {
		return fmt.Errorf("netbox returned no object id")
	}

	// EXACT, non-empty identity. An empty field is not "close enough": it is the
	// only handle the orphan sweeper has for reclaiming this object if the local
	// row is lost, so accepting a blank one creates an unreclaimable address.
	if ip.Identity != req.Identity {
		return fmt.Errorf("object %d carries identity %q, want %q", ip.ID, ip.Identity, req.Identity)
	}
	if ip.Identity == "" {
		return fmt.Errorf("object %d carries no litevirt identity", ip.ID)
	}

	// A bound VRF is REQUIRED. Plain equality would accept 0 == 0, which is the
	// global table — exactly what bind validation refuses, so accepting it here
	// would reopen that hole from a different direction.
	if req.VRFID == 0 {
		return fmt.Errorf("claim has no bound VRF")
	}
	if ip.VRFID != req.VRFID {
		return fmt.Errorf("object %d is in VRF %d, not the bound VRF %d", ip.ID, ip.VRFID, req.VRFID)
	}

	// ONE strict parser per input form. No stripping before validation, and no
	// bare-address fallback: NetBox returns ip-addresses in CIDR notation, so a
	// bare host means something unexpected produced it, and tolerating it is a
	// fail-open edge in a function whose whole job is to fail closed.
	addr, err := parseHostCIDR(ip.Address)
	if err != nil {
		return fmt.Errorf("object %d has an invalid address %q: %v", ip.ID, ip.Address, err)
	}

	// Scope is REQUIRED. An empty PrefixCIDR would otherwise mean "no
	// containment check", the opposite of fail-closed.
	if req.PrefixCIDR == "" {
		return fmt.Errorf("claim has no bound prefix CIDR to validate against")
	}
	_, prefix, perr := net.ParseCIDR(req.PrefixCIDR)
	if perr != nil {
		return fmt.Errorf("bound prefix %q is unparseable: %v", req.PrefixCIDR, perr)
	}
	if !prefix.Contains(addr) {
		return fmt.Errorf("address %s is outside the bound prefix %s", ip.Address, req.PrefixCIDR)
	}

	// An EXPLICIT claim must return the address that was asked for, compared
	// canonically. The REQUEST is parsed strictly too — stripping first would
	// let "10.0.5.50/bad" compare equal, because only the host part is read.
	if req.ExplicitIP != "" {
		want, werr := parseHostOrCIDR(req.ExplicitIP)
		if werr != nil {
			return fmt.Errorf("requested address %q is invalid: %v", req.ExplicitIP, werr)
		}
		if !want.Equal(addr) {
			return fmt.Errorf("requested %s but netbox returned %s", req.ExplicitIP, ip.Address)
		}
	}
	return nil
}

// parseHostCIDR accepts ONLY "host/prefixlen" and returns the host address.
// Used for what NetBox returns, where a bare address is not a valid shape.
func parseHostCIDR(v string) (net.IP, error) {
	addr, _, err := net.ParseCIDR(v)
	if err != nil {
		return nil, err
	}
	return addr, nil
}

// parseHostOrCIDR accepts either "host" or "host/prefixlen" and returns the
// host address. Used for OPERATOR input, where both forms are legitimate — but
// a malformed prefix length is still rejected rather than ignored.
func parseHostOrCIDR(v string) (net.IP, error) {
	if strings.Contains(v, "/") {
		return parseHostCIDR(v)
	}
	addr := net.ParseIP(v)
	if addr == nil {
		return nil, fmt.Errorf("not an IP address")
	}
	return addr, nil
}

func (a *netboxAllocator) Release(ctx context.Context, req ReleaseRequest) error {
	// Local tombstone FIRST and MANDATORY. A crash after this leaks an address
	// the sweeper reclaims; the reverse order would free an address in NetBox
	// that litevirt still believes it holds, letting another system take it.
	if err := ReleaseLease(ctx, a.db, req.Network, req.IP, req.MAC,
		req.OwnerKind, req.OwnerHost, req.Name); err != nil {
		return fmt.Errorf("local tombstone failed, NetBox delete skipped: %w", err)
	}
	if req.NetBoxIPID == 0 {
		return nil
	}
	return a.nb.ReleaseIP(ctx, req.NetBoxIPID)
}
