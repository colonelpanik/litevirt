package grpcapi

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const (
	proofMAC  = "52:54:00:aa:bb:cc"
	proofIP   = "10.0.5.100"
	proofUUID = "uuid-1"
)

// newProofServer returns a test server whose libvirt backend is a fake, plus a
// typed handle on that fake (s.virt is the LibvirtBackend interface, so the
// seeding helpers are only reachable through the concrete type).
func newProofServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServer(t)
	f := libvirtfake.New()
	s.virt = f
	return s, f
}

// insertTestNIC writes a LIVE vm_nics row — the local record of a NIC holding
// mac (and, when non-empty, ip).
func insertTestNIC(t *testing.T, db *corrosion.Client, vmName, mac, ip string) {
	t.Helper()
	if err := corrosion.UpsertNIC(context.Background(), db, corrosion.NICRecord{
		VMName: vmName, ID: "nic0", NetworkName: "net-a",
		MAC: mac, Ordinal: 0, IP: ip,
	}); err != nil {
		t.Fatalf("UpsertNIC(%s): %v", vmName, err)
	}
}

// insertTestLease writes a LIVE ip_allocations row: the lease that says this
// cluster holds ip, independent of any NIC row.
func insertTestLease(t *testing.T, db *corrosion.Client, network, ip, mac, owner string) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'vm', '', ?, ?)`,
		network, ip, mac, owner, db.NowWall(), db.NowTS()); err != nil {
		t.Fatalf("insert ip_allocations(%s): %v", ip, err)
	}
}

func TestProofCountsStoppedDefinedDomains(t *testing.T) {
	s, virt := newProofServer(t)
	// A crash can leave a persistent shut-off domain holding the MAC, and that
	// domain may later be STARTED. ListDomains already returns inactive
	// definitions, and runtime inventory treats stopped-but-defined as real
	// runtime state — the proof must too.
	virt.DefineStoppedDomain("vm-ghost", proofMAC)

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HoldsMAC {
		t.Fatal("a stopped-but-defined domain holding the MAC must block reclamation")
	}
	if !p.Complete {
		t.Fatalf("a scan with no probe error must be complete, got errors %v", p.Errors)
	}
	if p.Host != "test-host" {
		t.Fatalf("proof must name the host that produced it, got %q", p.Host)
	}
}

func TestProofIsIncompleteWithoutALibvirtClient(t *testing.T) {
	s, _ := newProofServer(t)
	s.virt = nil

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	// "I cannot look" is not "nothing is there".
	if p.Complete {
		t.Fatal("a host with no libvirt client must report an INCOMPLETE proof")
	}
}

func TestProofIsIncompleteOnDomainStateFailure(t *testing.T) {
	s, virt := newProofServer(t)
	virt.DefineStoppedDomain("vm-x", proofMAC)
	virt.FailDomainState = func(string) error { return errors.New("libvirtd: connection reset") }

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if p.Complete {
		t.Fatal("an unreadable domain state is a scan gap, not an absence")
	}
}

func TestProofIsIncompleteOnEnumerationFailure(t *testing.T) {
	s, virt := newProofServer(t)
	virt.FailListDomains = func() error { return errors.New("libvirtd: no connection") }

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if p.Complete {
		t.Fatal("an enumeration failure must mark the proof INCOMPLETE, not clean")
	}
}

func TestProofIsIncompleteOnDumpXMLFailure(t *testing.T) {
	s, virt := newProofServer(t)
	virt.DefineStoppedDomain("vm-live", proofMAC)
	virt.SetState("vm-live", libvirtfake.StateRunning)
	virt.FailDumpXML = func(string) error { return errors.New("libvirtd: domain xml read failed") }

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if p.Complete {
		t.Fatal("a domain whose LIVE XML could not be read is a scan gap, not an absence")
	}
}

func TestProofReadsLocalDBNotJustRuntime(t *testing.T) {
	s, _ := newProofServer(t)
	// No domain anywhere, but a row exists locally. Replication is async, so the
	// sweeper leader may not see this row at all — only this host does.
	insertTestNIC(t, s.db, "vm-1", proofMAC, proofIP)

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HoldsMAC {
		t.Fatal("a local DB row holding the MAC must block reclamation")
	}
}

func TestProofHoldsMACInLiveXMLOnly(t *testing.T) {
	s, virt := newProofServer(t)
	// A hotplugged NIC lives in the RUNNING domain's live XML and never reaches
	// the persistent config. A scan that only read the persistent definition
	// would call this address free while a running guest is using it.
	const name = "vm-hotplugged"
	virt.DefineStoppedDomain(name, "52:54:00:00:00:01") // persistent config: a DIFFERENT MAC
	virt.SetState(name, libvirtfake.StateRunning)
	virt.SetActiveXML(name, libvirtfake.StoppedDomainXML(name, libvirtfake.DomainUUIDFor(name), proofMAC))

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HoldsMAC {
		t.Fatal("a MAC present only in a running domain's LIVE XML must block reclamation")
	}
	if !p.Complete {
		t.Fatalf("a scan with no probe error must be complete, got errors %v", p.Errors)
	}
}

func TestProofHoldsAddressFromLocalLease(t *testing.T) {
	s, _ := newProofServer(t)
	// The lease is the address's own record: it can outlive the NIC row and the
	// domain, and while it stands the address is not free.
	insertTestLease(t, s.db, "net-a", proofIP, "52:54:00:00:00:09", "vm-gone")

	p, err := s.collectOrphanProof(context.Background(), proofUUID, proofMAC, proofIP)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HoldsAddress {
		t.Fatal("a live ip_allocations row for the address must block reclamation")
	}
	if p.HoldsMAC {
		t.Fatal("a lease under a DIFFERENT MAC must not report the queried MAC as held")
	}
}

// TestProofRPCIsPeerOnly pins the RPC's trust boundary to GetRuntimeInventory's:
// the proof discloses this host's runtime and local rows, so an operator bearer
// must not be able to ask for it.
func TestProofRPCIsPeerOnly(t *testing.T) {
	s, virt := newProofServer(t)
	virt.DefineStoppedDomain("vm-ghost", proofMAC)

	if _, err := s.CollectOrphanProof(adminCtx(), &pb.OrphanProofRequest{Mac: proofMAC}); err == nil {
		t.Fatal("CollectOrphanProof must reject a non-peer (admin) caller")
	}

	resp, err := s.CollectOrphanProof(peerCtxFor(t, s, "peer-1"), &pb.OrphanProofRequest{
		VmUuid: proofUUID, Mac: proofMAC, Address: proofIP,
	})
	if err != nil {
		t.Fatalf("peer call: %v", err)
	}
	if !resp.GetHoldsMac() || !resp.GetComplete() {
		t.Fatalf("peer proof lost the local answer: %+v", resp)
	}
}
