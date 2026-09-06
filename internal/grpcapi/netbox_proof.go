package grpcapi

import (
	"context"
	"fmt"
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
	s.proveFromLibvirt(&p, vmUUID, mac)
	s.proveFromLocalRows(ctx, &p, vmUUID, mac, address)
	return p, nil
}

// proveFromLibvirt scans EVERY defined domain, in EVERY state. ListDomains
// already passes ConnectListDomainsActive|Inactive, so a shut-off definition is
// included — and it has to be: libvirt will start that definition again on the
// MAC written in it, so a stopped domain holds its address just as firmly as a
// running one.
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
		// The state is consulted for two reasons: an UNREADABLE one is a scan
		// gap (a domain we cannot classify might be the claimant), and a domain
		// with a live instance needs its LIVE view read as well as its
		// persistent one.
		state, serr := s.virt.DomainState(n)
		if serr != nil {
			p.failf("domain %s: read state: %v", n, serr)
		}

		// The PERSISTENT definition: what a cold boot loads, and the only view a
		// shut-off domain has.
		inactive, ierr := s.virt.DumpXMLInactive(n)
		if ierr != nil {
			p.failf("domain %s: read persistent XML: %v", n, ierr)
		} else {
			claimsInXML(p, inactive, vmUUID, mac)
		}

		// The LIVE definition, which a RUNNING domain can carry beyond its
		// persistent config: a hotplugged NIC exists only here until something
		// writes it back, so a persistent-only scan reads a MAC in active use as
		// free. An unreadable state falls through to here too — unknown means
		// look harder, not look less.
		if !mayHaveLiveView(state) {
			continue
		}
		live, lerr := s.virt.DumpXML(n)
		if lerr != nil {
			p.failf("domain %s: read live XML: %v", n, lerr)
			continue
		}
		claimsInXML(p, live, vmUUID, mac)
	}
}

// mayHaveLiveView reports whether a domain in this state can have a live
// instance whose XML differs from its persistent config. Only a definitively
// inactive domain is excluded; "unknown" and an unreadable ("") state are not,
// because reading the live view of an inactive domain merely returns the
// persistent config again — harmless — whereas skipping it for a domain that
// IS running would hide a hotplugged claimant.
//
// The vocabulary spans both producers of this string: *libvirt.Client's coarse
// states (running | stopping | stopped | error | unknown) and libvirtfake's raw
// ones (running | shutoff | no-domain).
func mayHaveLiveView(state string) bool {
	switch state {
	case "stopped", "shutoff", "no-domain":
		return false
	}
	return true
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
