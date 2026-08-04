package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// fakeFailoverGate is a configurable FailoverGate: DecisionGate/QuorumProof/Enforced
// all report "healthy + enforced" so a test can isolate the PeerSupports (mint-site
// destination) decision.
type fakeFailoverGate struct {
	supports map[string]bool
	// enforced maps token → enforcement decision. A nil map means "all enforced"
	// (back-compat for tests that only exercise the mint-site PeerSupports path).
	enforced map[string]bool
}

func (f fakeFailoverGate) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (f fakeFailoverGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 2, 2
}
func (f fakeFailoverGate) Enforced(_ context.Context, token string) bool {
	if f.enforced == nil {
		return true
	}
	return f.enforced[token]
}
func (f fakeFailoverGate) PeerSupportsFresh(_ context.Context, peer, _ string) bool {
	return f.supports[peer]
}

// destAdvertisesGate is the fail-closed pre-mint check (Phase 1): the coordinator
// stamps a proof for a destination ONLY when a fresh Ping confirms it advertises
// the gate. A regressed/replaced target that no longer advertises is refused, and a
// nil gate fails closed — so a latched coordinator can never stamp a proof a target
// can't honor.
func TestDestAdvertisesGate(t *testing.T) {
	ctx := context.Background()
	c := &Coordinator{hostName: "node-a", Gate: fakeFailoverGate{supports: map[string]bool{"node-b": true}}}

	if !c.destAdvertisesGate(ctx, "node-b") {
		t.Fatal("a peer advertising the gate must pass")
	}
	if c.destAdvertisesGate(ctx, "node-c") {
		t.Fatal("a peer NOT advertising the gate must be refused (fail closed)")
	}
	// A nil gate fails closed.
	if (&Coordinator{hostName: "node-a"}).destAdvertisesGate(ctx, "node-b") {
		t.Fatal("nil gate must fail closed")
	}
	// A self-fenced coordinator never reports ITSELF as gate-capable (it de-advertises),
	// so it can't stamp a self-targeted proof — even if this build advertised the token.
	fenced := &Coordinator{hostName: "node-a", Gate: fakeFailoverGate{}, SelfFenced: func() bool { return true }}
	if fenced.destAdvertisesGate(ctx, "node-a") {
		t.Fatal("a self-fenced node must not report itself gate-capable")
	}
}

// The coordinator must bind image-recreate relocation authorization to the
// exact container ownership generation it observed. Otherwise a prepared proof
// can survive an ownership ABA cycle and authorize a later recreation.
func TestImageRecreateProofCarriesOwnerEpoch(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "ct1", State: "running", Image: "alpine:3.19",
		OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE containers SET owner_epoch = 7 WHERE host_name = 'dead' AND name = 'ct1'`); err != nil {
		t.Fatalf("seed owner epoch: %v", err)
	}
	ct, err := corrosion.GetContainer(ctx, db, "dead", "ct1")
	if err != nil || ct == nil {
		t.Fatalf("GetContainer: %v / nil=%v", err, ct == nil)
	}
	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.imageRecreateOrSkip(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, "live")

	rows, err := db.Query(ctx, `SELECT owner_epoch, relocation_token FROM runtime_action_proofs WHERE target_name = 'ct1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("proof rows=%d err=%v; want one", len(rows), err)
	}
	if rows[0].String("owner_epoch") != "7" || rows[0].String("relocation_token") == "" {
		t.Fatalf("proof owner/token=%q/%q; want 7/non-empty",
			rows[0].String("owner_epoch"), rows[0].String("relocation_token"))
	}
}

// VM reschedule uses a different mint path (proof + pending pointer in one
// transaction), so pin the same ownership-generation binding there too.
func TestVMRescheduleProofCarriesOwnerEpoch(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []string{"dead", "live"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
		t.Fatalf("seed owner epoch: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"coord", "live"}, "dead")

	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.run(ctx)

	rows, err := db.Query(ctx, `SELECT owner_epoch, dest_host FROM runtime_action_proofs WHERE target_name = 'vm1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("proof rows=%d err=%v; want one", len(rows), err)
	}
	if rows[0].String("owner_epoch") != "7" || rows[0].String("dest_host") != "live" {
		t.Fatalf("proof owner/dest=%q/%q; want 7/live",
			rows[0].String("owner_epoch"), rows[0].String("dest_host"))
	}
}
