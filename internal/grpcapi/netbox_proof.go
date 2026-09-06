package grpcapi

import (
	"context"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// OrphanProof is one host's answer to "does anything here still claim this
// address". It is a NEGATIVE proof, so an incomplete scan is worthless: any
// probe error clears Complete and the sweeper must abort.
//
// The Holds* flags are the opposite kind of statement — each is only ever set
// from something the host actually found — so they stay meaningful even in an
// incomplete proof. Absence never does.
type OrphanProof struct {
	Host         string
	Complete     bool
	Errors       []string
	HoldsUUID    bool
	HoldsMAC     bool
	HoldsAddress bool
}

// Holds reports whether this host claims the candidate in any way.
func (p OrphanProof) Holds() bool { return p.HoldsUUID || p.HoldsMAC || p.HoldsAddress }

// failf records a scan gap. Complete is cleared for the whole proof, not for
// the individual probe, because the caller's question ("is this address free?")
// can only be answered by a scan that saw everything.
func (p *OrphanProof) failf(format string, args ...any) {
	p.Complete = false
	p.Errors = append(p.Errors, fmt.Sprintf(format, args...))
}

// collectOrphanProof scans this host's COMPLETE libvirt inventory and its LOCAL
// database.
//
// Both halves are required. Runtime alone misses a stopped VM row that has not
// replicated to the sweeper leader yet — replication is async by design — and
// that VM could be started later on its recorded address. The local DB alone
// misses a domain defined outside the DB's knowledge.
//
// It never returns a non-nil error: a probe failure is part of the ANSWER
// (Complete false plus the reason), and an error return would let a caller that
// only checks err treat a failed scan as no claim at all.
func (s *Server) collectOrphanProof(ctx context.Context, vmUUID, mac, address string) (OrphanProof, error) {
	p := OrphanProof{Host: s.hostName, Complete: true}
	address = normalizeProofAddress(&p, address)
	s.proveFromLibvirt(&p, vmUUID, mac)
	s.proveFromLocalRows(ctx, &p, vmUUID, mac, address)
	return p, nil
}

// normalizeProofAddress reduces address to the bare host form the local rows
// store. The proto documents a bare host address, but the external system this
// proof answers to carries addresses WITH a prefix ("10.0.5.100/24"); one
// arriving that way would match no row and read as "nothing holds it", which is
// the catastrophic direction for a negative proof.
//
// An address that parses as neither a CIDR nor an IP is NOT quietly reduced to
// nothing: it marks the proof incomplete and names itself, because a value
// nobody can interpret must never produce a confident HoldsAddress=false.
func normalizeProofAddress(p *OrphanProof, address string) string {
	if address == "" || !strings.Contains(address, "/") {
		return address
	}
	if ip, _, err := net.ParseCIDR(address); err == nil {
		return ip.String()
	}
	// Not a valid CIDR, but the host half may still be a real address carrying a
	// nonsense prefix length ("10.0.5.100/33"). That is a claim we can still
	// check, and checking it is the safe direction.
	if ip := net.ParseIP(strings.SplitN(address, "/", 2)[0]); ip != nil {
		return ip.String()
	}
	p.failf("address %q is neither a bare IP nor a CIDR — cannot prove it unclaimed", address)
	return ""
}

// proveFromLibvirt scans EVERY defined domain, in EVERY state, and reads BOTH
// views of each. ListDomains already passes ConnectListDomainsActive|Inactive,
// so a shut-off definition is included — and it has to be: libvirt will start
// that definition again on the MAC written in it, so a stopped domain holds its
// address just as firmly as a running one.
//
// Both views are read UNCONDITIONALLY, without consulting the domain's state,
// because litevirt's coarse state vocabulary cannot support that decision:
// libvirt.coarseDomainState folds DomainPaused and DomainPmsuspended in with
// DomainShutoff as "stopped", yet a paused domain is ACTIVE — a NIC hotplugged
// into it exists ONLY in its live XML. Any gate built on that string reads a MAC
// in active use as free. Reading both costs one extra call per domain and has no
// failure mode: real libvirt answers both in every state (a shut-off domain's
// "live" query returns its persistent config; a transient domain's "inactive"
// query returns its live definition), so a failure of EITHER is a genuine scan
// gap and marks the proof incomplete.
func (s *Server) proveFromLibvirt(p *OrphanProof, vmUUID, mac string) {
	// A host with NO libvirt client cannot answer at all, so its proof is
	// INCOMPLETE — not a clean bill of health. Skipping the scan silently would
	// turn "I cannot look" into "nothing is there".
	if s.virt == nil {
		p.failf("no libvirt client on this host — cannot scan for claimants")
		return
	}

	names, err := s.virt.ListDomains()
	if err != nil {
		// Whatever came back is partial at best. Still scan it — a positive hit
		// is real evidence — but the proof is already incomplete.
		p.failf("list domains: %v", err)
	}
	for _, n := range names {
		// The state is read as a PROBE only: a domain this host cannot classify
		// at all might be the claimant, so an error is a scan gap. The result
		// itself gates nothing — see the note above on why it cannot.
		if _, serr := s.virt.DomainState(n); serr != nil {
			p.failf("domain %s: read state: %v", n, serr)
		}

		// The PERSISTENT definition: what a cold boot loads.
		inactive, ierr := s.virt.DumpXMLInactive(n)
		if ierr != nil {
			p.failf("domain %s: read persistent XML: %v", n, ierr)
		} else {
			claimsInXML(p, inactive, vmUUID, mac)
		}

		// The LIVE definition, which an active domain can carry beyond its
		// persistent config: a hotplugged NIC exists only here until something
		// writes it back, so a persistent-only scan reads a MAC in active use as
		// free.
		live, lerr := s.virt.DumpXML(n)
		if lerr != nil {
			p.failf("domain %s: read live XML: %v", n, lerr)
			continue
		}
		claimsInXML(p, live, vmUUID, mac)
	}
}

// claimsInXML marks the identifiers this domain XML contains. Substring
// matching over the whole document is deliberate: it needs no schema knowledge,
// and it errs toward finding a claimant, which is the safe direction for a
// proof whose false negative frees an address someone is using.
func claimsInXML(p *OrphanProof, xml, vmUUID, mac string) {
	lower := strings.ToLower(xml)
	if mac != "" && strings.Contains(lower, strings.ToLower(mac)) {
		p.HoldsMAC = true
	}
	if vmUUID != "" && strings.Contains(lower, strings.ToLower(vmUUID)) {
		p.HoldsUUID = true
	}
}

// nicClaimTable is one local table recording a NIC's MAC and IP.
type nicClaimTable struct {
	name string
	sql  string
}

// nicClaimTables lists EVERY live table that records a NIC's MAC on this host.
// vm_nics and vm_interfaces are both current — the v42 hardware model
// dual-writes them, and a VM created through the plain InsertVM path has only
// vm_interfaces rows — and container_interfaces is the container twin. A proof
// that read just one of them would call an address free while a row still names
// it.
var nicClaimTables = []nicClaimTable{
	{"vm_nics", `SELECT COALESCE(mac, '') AS mac, COALESCE(ip, '') AS ip
	             FROM vm_nics WHERE deleted_at IS NULL`},
	{"vm_interfaces", `SELECT COALESCE(mac, '') AS mac, COALESCE(ip, '') AS ip
	                   FROM vm_interfaces WHERE deleted_at IS NULL`},
	{"container_interfaces", `SELECT COALESCE(mac, '') AS mac, COALESCE(ip, '') AS ip
	                          FROM container_interfaces WHERE deleted_at IS NULL`},
}

// proveFromLocalRows asks THIS host's database, which is the point: replication
// is asynchronous, so a row written here seconds ago may not have reached the
// sweeper leader, and the leader's absence of it is not evidence.
func (s *Server) proveFromLocalRows(ctx context.Context, p *OrphanProof, vmUUID, mac, address string) {
	if s.db == nil {
		p.failf("no local database on this host — cannot scan rows for claimants")
		return
	}

	if mac != "" || address != "" {
		for _, t := range nicClaimTables {
			rows, err := s.db.Query(ctx, t.sql)
			if err != nil {
				p.failf("query %s: %v", t.name, err)
				continue
			}
			for _, r := range rows {
				if mac != "" && strings.EqualFold(r.String("mac"), mac) {
					p.HoldsMAC = true
				}
				if address != "" && r.String("ip") == address {
					p.HoldsAddress = true
				}
			}
		}
	}

	// The lease table is the address's own record. It outlives the NIC row (a
	// half-finished delete leaves exactly this), and while it stands the address
	// is not free — for a container owner as much as a VM one.
	if address != "" {
		rows, err := s.db.Query(ctx,
			`SELECT 1 AS hit FROM ip_allocations WHERE ip = ? AND deleted_at IS NULL`, address)
		switch {
		case err != nil:
			p.failf("query ip_allocations: %v", err)
		case len(rows) > 0:
			p.HoldsAddress = true
		}
	}

	// The UUID lives inside the VM's spec JSON, which has no column of its own,
	// so this is a substring match on the spec. A LIKE metacharacter in vmUUID
	// could only BROADEN the match (a real UUID contains none), which is the
	// safe direction here.
	if vmUUID != "" {
		rows, err := s.db.Query(ctx,
			`SELECT 1 AS hit FROM vms WHERE spec LIKE ? AND deleted_at IS NULL`, "%"+vmUUID+"%")
		switch {
		case err != nil:
			p.failf("query vms: %v", err)
		case len(rows) > 0:
			p.HoldsUUID = true
		}
	}
}

// CollectOrphanProof serves this host's orphan proof to a peer. Peer-only
// (host-cert mTLS) — the same trust boundary as GetRuntimeInventory, and for
// the same reason: the answer discloses this host's runtime and local rows, and
// only a sweeper leader needs it.
func (s *Server) CollectOrphanProof(ctx context.Context, req *pb.OrphanProofRequest) (*pb.OrphanProofResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	p, err := s.collectOrphanProof(ctx, req.GetVmUuid(), req.GetMac(), req.GetAddress())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "collect orphan proof: %v", err)
	}
	return &pb.OrphanProofResponse{
		Host:         p.Host,
		Complete:     p.Complete,
		Errors:       p.Errors,
		HoldsUuid:    p.HoldsUUID,
		HoldsMac:     p.HoldsMAC,
		HoldsAddress: p.HoldsAddress,
	}, nil
}
