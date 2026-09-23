package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireLeaseTermLedgerGate_TheMintTracksTheDurableLatch pins the one line
// that makes the whole term-ledger mechanism work.
//
// Every other test of this feature injects the gate directly with
// SetLeaseTermLedgerGate, and the corrosion test constructors hardcode it open,
// so deleting the production wiring left the corrosion, grpcapi AND daemon
// suites entirely green while production minted nothing, forever, with nothing
// in the logs.
//
// That silence is structural rather than bad luck. This is the one injected
// predicate on the corrosion client that fails CLOSED, so an unwired gate is
// indistinguishable from a legitimate mid-roll — and from a latch starved behind
// another token. There is no symptom to notice: the ledger is simply empty,
// which is exactly what a correct mid-roll looks like.
//
// So the test drives the REAL health.Checker to a real durable latch and asserts
// the mint gate follows it, in both directions. Asserting only the closed
// direction would prove nothing: an unwired gate is closed too.
func TestWireLeaseTermLedgerGate_TheMintTracksTheDurableLatch(t *testing.T) {
	ctx := context.Background()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("test client: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	// A single active host — itself — so the activation sweep is satisfiable.
	// Members() is empty on a test client, so the ReplicationGated union adds
	// nothing here; that path has its own test in internal/health.
	if err := corrosion.RegisterHost(ctx, db, corrosion.HostRecord{
		Name: "host-a", Address: "10.0.0.1", State: "active", Role: "worker",
	}); err != nil {
		t.Fatalf("register host: %v", err)
	}

	checker := health.NewChecker("host-a", "/etc/litevirt/pki", db)
	checker.SetActivationMarker(filepath.Join(t.TempDir(), "split_brain_activated"))
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return capabilities.Supported(), time.Time{}, nil
	})

	d := &Daemon{db: db, checker: checker, cfg: &Config{}}
	d.wireLeaseTermLedgerGate()

	// Before the latch: the pre-ledger behaviour. A term would be a statement
	// shape a previous-release peer cannot resolve.
	if db.MayMintLeaseTerm() {
		t.Fatal("the mint gate is open before lease_term_ledger_v1 has durably latched")
	}

	// Drive the real latch, durably.
	if !checker.Enforced(ctx, capabilities.LeaseTermLedgerV1) {
		t.Fatal("Enforced did not latch with the only host advertising the token")
	}
	if !checker.DurablyLatched(capabilities.LeaseTermLedgerV1) {
		t.Fatal("the latch did not persist; the rest of this test is vacuous")
	}

	// This is the assertion the missing wiring escaped: the gate must OPEN.
	if !db.MayMintLeaseTerm() {
		t.Error("the mint gate stayed closed after lease_term_ledger_v1 durably latched. " +
			"Unwired, this predicate fails closed and no term is ever minted, which is " +
			"indistinguishable from a legitimate mid-roll — so nothing surfaces and " +
			"lease_term_v1 withholds readiness forever")
	}
}
