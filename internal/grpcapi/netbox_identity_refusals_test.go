package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The bind-time adoption refusals nothing pinned.
//
// planAdoption refuses these states, each named as a guarantee in the commit
// that introduced it and each reachable only from a specific local row shape.
// None of them had a test: every one would have passed as a silent SKIP, and a
// skip is exactly the invisible address adoption exists to remove. A skip is
// also what a refactor produces by accident, since the alternative to
// `return refusal` at each of these points is `continue`.

// TestBindRefusesANICWithNoMAC.
//
// A NetBox identity is (fingerprint, incarnation uuid, MAC). Without the MAC the
// identity names nothing findable: the recovery lookup could not resolve the
// object after an ambiguous claim, and the orphan sweep — whose whole authority
// is that identity — could never reclaim it.
func TestBindRefusesANICWithNoMAC(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMHoldingIP(t, s, "no-mac", "shared", "", "10.0.5.60",
		"aaaaaaaa-0000-0000-0000-000000000001")

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("an address held on a NIC with no MAC must refuse the bind, not be skipped")
	}
	if !strings.Contains(err.Error(), "no MAC") {
		t.Fatalf("the refusal must say the MAC is what is missing, got: %v", err)
	}
	if !strings.Contains(err.Error(), "10.0.5.60") || !strings.Contains(err.Error(), "no-mac") {
		t.Fatalf("the refusal must name the address and the VM holding it, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesAVMWithNoIncarnationUUID.
//
// The second half of the same identity. A spec with no uuid — a hand-edited row,
// or one from a path that never wrote one — cannot be identified across a
// delete-and-recreate under the same name, so an object minted for it would be
// attributed to whatever VM next holds that name.
func TestBindRefusesAVMWithNoIncarnationUUID(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// A spec with a name and NO uuid, which is what vmSpecUUID rejects.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "no-uuid", HostName: "test-host", State: "running",
		Spec: `{"name":"no-uuid"}`,
	}, []corrosion.InterfaceRecord{{
		VMName: "no-uuid", NetworkName: "shared",
		MAC: "aa:bb:cc:00:0a:01", IP: "10.0.5.61",
	}}, nil); err != nil {
		t.Fatalf("seed VM: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("an address held by a VM with no incarnation uuid must refuse the bind")
	}
	if !strings.Contains(err.Error(), "no-uuid") || !strings.Contains(err.Error(), "10.0.5.61") {
		t.Fatalf("the refusal must name the VM and the address, got: %v", err)
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Fatalf("the refusal must say no identity can be minted, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesTwoNICsRecordingOneAddress.
//
// `ip_allocations` is keyed (network, ip), so only ONE of the two could ever
// hold the lease. Adopting either would silently pick a winner and tell NetBox
// that VM is the owner — and the other guest, holding the same address right
// now, would be recorded nowhere.
func TestBindRefusesTwoNICsRecordingOneAddress(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMHoldingIP(t, s, "twin-a", "shared", "aa:bb:cc:00:0b:01", "10.0.5.62",
		"bbbbbbbb-0000-0000-0000-000000000001")
	seedVMHoldingIP(t, s, "twin-b", "shared", "aa:bb:cc:00:0b:02", "10.0.5.62",
		"bbbbbbbb-0000-0000-0000-000000000002")

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("one address on two NICs must refuse the bind, not pick a winner")
	}
	if !strings.Contains(err.Error(), "10.0.5.62") {
		t.Fatalf("the refusal must name the duplicated address, got: %v", err)
	}
	if !strings.Contains(err.Error(), "twin-a") || !strings.Contains(err.Error(), "twin-b") {
		t.Fatalf("the refusal must name BOTH VMs, or the operator cannot resolve it: %v", err)
	}
	assertNothingBound(t, s)
}

// TestBindRefusesAnUnparseableRecordedAddress.
//
// Fail closed. An address that will not parse cannot be tested for containment,
// so litevirt cannot say whether NetBox is about to hand it out again — and
// "unparseable" must not resolve to "outside the prefix", which is the SKIP the
// containment branch performs one line later.
func TestBindRefusesAnUnparseableRecordedAddress(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	seedVMHoldingIP(t, s, "garbled", "shared", "aa:bb:cc:00:0c:01", "10.0.5.not-an-ip",
		"cccccccc-0000-0000-0000-000000000001")

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("an unparseable recorded address must refuse the bind, not read as out-of-prefix")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("the refusal must say the address is unparseable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "garbled") {
		t.Fatalf("the refusal must name the VM, got: %v", err)
	}
	assertNothingBound(t, s)
}

// TestAdoptionRefusesAnEmptyClusterFingerprint.
//
// Every identity is built from the fingerprint, so an empty one produces an
// identity that names nothing: unfindable by the recovery lookup and
// unreclaimable by the sweep. Asserted on planAdoption directly, because the
// bind derives the fingerprint itself and refuses earlier — this is the guard
// that protects the OTHER two doors, which are handed a persisted binding row
// that could carry an empty pin.
func TestAdoptionRefusesAnEmptyClusterFingerprint(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	_, err := s.planAdoption(ctx, corrosion.BindingRecord{
		Network: "shared", PrefixID: adoptTestPrefix, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "",
	})
	if err == nil {
		t.Fatal("a binding with no cluster fingerprint must refuse adoption")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("the refusal must name the fingerprint, got: %v", err)
	}
	if !adoptionRefused(err) {
		t.Fatal("this is an operator-repairable state, so it must be FailedPrecondition")
	}
}

// TestAdoptionRefusesAnUnparseableBoundPrefix is the same fail-closed rule for
// the other input every containment test rests on.
func TestAdoptionRefusesAnUnparseableBoundPrefix(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	_, err := s.planAdoption(ctx, corrosion.BindingRecord{
		Network: "shared", PrefixID: adoptTestPrefix, ObservedCIDR: "not-a-cidr",
		VRFID: 3, ClusterFingerprint: "fp",
	})
	if err == nil {
		t.Fatal("an unparseable bound prefix must refuse adoption")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("the refusal must say so, got: %v", err)
	}
}

// TestBindReleasesThePrefixWhenTheSuspendWriteFails is the compensation for the
// one state that must not survive: a binding LIVE over addresses nothing has
// adopted.
//
// The claim lands, then the suspend that takes the binding out of service fails.
// Leaving it there would be a live binding allocating across a prefix whose
// existing occupants NetBox has never heard of — the exact defect the whole step
// closes — so the prefix is RELEASED instead, and the message says nothing was
// bound.
func TestBindReleasesThePrefixWhenTheSuspendWriteFails(t *testing.T) {
	s := newAdoptTestServer(t)
	ctx := context.Background()

	// Something to adopt, so the bind takes the suspend path at all.
	seedVMHoldingIP(t, s, "incumbent", "shared", "aa:bb:cc:00:0d:01", "10.0.5.70",
		"dddddddd-0000-0000-0000-000000000001")
	// …and the suspend write fails. Scoped with a WHEN clause to the update that
	// SETS the suspension: the release is itself an UPDATE (a soft delete), so an
	// unscoped trigger would break the compensation too and this would be testing
	// the "release also failed" branch instead of the one it names.
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER test_fail_binding_suspend BEFORE UPDATE ON netbox_bindings
		 WHEN NEW.suspended = 1
		 BEGIN SELECT RAISE(ABORT, 'induced suspend failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}

	err := s.validateAndBindPrefix(ctx, "shared", adoptTestPrefix, noDHCPNetworkDef)
	if err == nil {
		t.Fatal("a bind whose suspend write failed must not report success")
	}
	if !strings.Contains(err.Error(), "released") {
		t.Fatalf("the message must say the prefix was released, got: %v", err)
	}
	// The compensation itself: nothing is bound, so the prefix can be bound
	// again once the cause is repaired.
	assertNothingBound(t, s)
}
