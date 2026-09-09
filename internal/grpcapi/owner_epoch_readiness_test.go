package grpcapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Every readiness predicate must INDEPENDENTLY withhold advertisement — the
// latch requires every node, so one node's blind spot must be enough to keep
// the whole regime from forming.

func stampVMEpoch(t *testing.T, s *Server, name string, epoch int64) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`UPDATE vms SET vm_owner_epoch = ? WHERE name = ?`, epoch, name); err != nil {
		t.Fatalf("stamp epoch: %v", err)
	}
}

func readinessServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := inventoryServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	return s, fake
}

func requireWithheld(t *testing.T, s *Server, wantSubstr string) {
	t.Helper()
	s.invalidateInventoryCache()
	ready, reason := s.OwnerEpochReadiness(context.Background())
	if ready {
		t.Fatalf("readiness advertised, want withheld (%s)", wantSubstr)
	}
	if wantSubstr != "" && !stringsContains(reason, wantSubstr) {
		t.Fatalf("withhold reason = %q, want it to mention %q", reason, wantSubstr)
	}
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestOwnerEpochReadiness_CleanNodeAdvertises(t *testing.T) {
	s, fake := readinessServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm1", 3)
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 3); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	ready, reason := s.OwnerEpochReadiness(ctx)
	if !ready {
		t.Fatalf("clean node withheld: %s", reason)
	}
}

func TestOwnerEpochReadiness_EachPredicateWithholds(t *testing.T) {
	// 1. Incomplete local inventory.
	s, _ := readinessServer(t)
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	requireWithheld(t, s, "inventory incomplete")

	// 2. An owned workload still at epoch 0.
	s, fake := readinessServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "legacy", HostName: s.hostName, Spec: "{}", State: "stopped", OwnerEpoch: 0,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	requireWithheld(t, s, "epoch 0")

	// 3. A running workload whose marker is MISSING.
	s, fake = readinessServer(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-nomark", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm-nomark", 2)
	fake.SetState("vm-nomark", libvirtfake.StateRunning)
	requireWithheld(t, s, "missing")

	// 4. A running workload whose marker DISAGREES with the DB epoch.
	s, fake = readinessServer(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-drift", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm-drift", 5)
	fake.SetState("vm-drift", libvirtfake.StateRunning)
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm-drift", 4); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	requireWithheld(t, s, "marker epoch 4 != DB epoch 5")

	// 5. An active ownership condition anywhere in the cluster.
	s, _ = readinessServer(t)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "runtime_owner_mismatch", SubjectKind: "vm", SubjectID: "elsewhere",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
	}); err != nil {
		t.Fatalf("seed condition: %v", err)
	}
	requireWithheld(t, s, "active ownership condition")
}

// cleanAdvertisingNode is the state TestOwnerEpochReadiness_CleanNodeAdvertises
// establishes: one owned, running VM whose marker matches its DB epoch. The two
// tie tests below both start here, so the only variable between them is WHICH
// TABLE the unresolved tie lands on.
func cleanAdvertisingNode(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, fake := readinessServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm1", 3)
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 3); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if ready, reason := s.OwnerEpochReadiness(ctx); !ready {
		t.Fatalf("fixture is not a clean advertising node: %s", reason)
	}
	return s, fake
}

// peerClient is a second, independent node: its own in-memory DB with the full
// schema, no gossip. Anything it writes reaches s.db only through a real
// anti-entropy merge, which is what makes the ties below the ties production
// produces rather than hand-built rows.
func peerClient(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("peer client: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("peer InitSchema: %v", err)
	}
	return c
}

// TestOwnerEpochReadiness_ContestedLeaseTermDoesNotWithhold: a tie on
// leader_lease_terms must not withhold owner_epoch_v1.
//
// Two nodes each minting term 1 for one lease key is the NORMAL path under
// partition — it is the event the term ledger exists to record, not a fault. The
// rows are immutable, so the tie it raises never converges and never clears.
// Reading the FLEET-WIDE unresolved-tie count here therefore withheld this
// capability on both nodes until a daemon restart, and because the latch is the
// fleet AND, the whole regime never formed cluster-wide.
//
// A tie on that table is not evidence about any VM's owner epoch, which is the
// only thing this predicate reasons about.
func TestOwnerEpochReadiness_ContestedLeaseTermDoesNotWithhold(t *testing.T) {
	ctx := context.Background()
	s, _ := cleanAdvertisingNode(t)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	// This node takes term 1 for the failover key.
	held, term, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, "failover", s.hostName, 30*time.Second, now)
	if err != nil || !held || term != 1 {
		t.Fatalf("local acquire: held=%v term=%d err=%v", held, term, err)
	}
	// A partitioned peer takes what it sees as the same free lease and also
	// computes term 1 — a fresh client has an empty ledger.
	peer := peerClient(t)
	held, term, err = corrosion.AcquireLeaseWithTerm(ctx, peer, "failover", "host-peer", 30*time.Second, now)
	if err != nil || !held || term != 1 {
		t.Fatalf("peer acquire: held=%v term=%d err=%v", held, term, err)
	}
	// The partition heals and this node repairs from the peer.
	if err := s.db.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy peer→local: %v", err)
	}
	if n := s.db.UnresolvedTieTables()["leader_lease_terms"]; n == 0 {
		t.Fatalf("fixture produced no contested-term tie (tables=%v); the assertion below "+
			"would pass vacuously", s.db.UnresolvedTieTables())
	}

	s.invalidateInventoryCache()
	if ready, reason := s.OwnerEpochReadiness(ctx); !ready {
		t.Errorf("a contested LEASE TERM withheld owner_epoch_v1: %q. That tie is not evidence "+
			"about any VM's owner epoch, and the row never converges — so reading the "+
			"fleet-wide count here withholds the whole regime, on every node that saw the "+
			"contest, until restart", reason)
	}

	// The narrowing is only safe while the BROAD count still reaches the operator.
	// This node is genuinely divergent and the state digest must keep saying so —
	// what changed is which question the readiness predicate asks, not what the
	// digest reports. Nothing else in this package pins the fleet-wide count, so
	// without this the population could be deleted silently.
	inv := s.collectRuntimeInventory(ctx)
	if inv.UnresolvedTies == 0 {
		t.Error("the fleet-wide unresolved-tie count is 0 with a contested term outstanding; " +
			"the state digest and the dual-run finding both read it and must still see the " +
			"divergence")
	}
	if inv.OwnershipTies != 0 {
		t.Errorf("OwnershipTies = %d for a leader_lease_terms tie, want 0 — only the tables in "+
			"ownershipTieTables may count toward it", inv.OwnershipTies)
	}
	if got := inventoryToProto(inv).GetUnresolvedTieCount(); got == 0 {
		t.Error("the proto digest reports 0 unresolved ties; peers would see a divergent node " +
			"as clean")
	}
}

// TestOwnerEpochReadiness_OwnershipTieStillWithholds is the other half, and the
// reason the fix is a narrowing rather than a deletion: a tie on a table that
// really can hide a divergent ownership row must still withhold.
//
// The fixture is a host_name split at an exact updated_at tie — two nodes each
// believing they own vm1. capabilityMap resolves that as runtime_owned and
// deliberately refuses to pick a winner (resolver.go), which is precisely the
// "a tie can hide a divergent ownership row" case the predicate exists for.
//
// The two rows must carry the SAME vm_owner_epoch. The anti-entropy authority
// guard runs ahead of the LWW resolver and treats a higher owner epoch as the
// semantic ABA order, so a differing epoch applies the incoming row outright and
// never reaches the tie resolver at all.
func TestOwnerEpochReadiness_OwnershipTieStillWithholds(t *testing.T) {
	ctx := context.Background()
	s, _ := cleanAdvertisingNode(t)

	// Pin both sides to one timestamp: the resolver only consults the table's
	// rule chain on an EXACT tie.
	const ts = "2026-06-03T18:40:00Z"
	if err := s.db.Execute(ctx, `UPDATE vms SET updated_at = ? WHERE name = ?`, ts, "vm1"); err != nil {
		t.Fatalf("pin the local row's updated_at: %v", err)
	}

	peer := peerClient(t)
	if err := corrosion.InsertVM(ctx, peer, corrosion.VMRecord{
		Name: "vm1", HostName: "host-peer", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("peer InsertVM: %v", err)
	}
	if err := peer.Execute(ctx,
		`UPDATE vms SET vm_owner_epoch = ?, updated_at = ? WHERE name = ?`, 3, ts, "vm1"); err != nil {
		t.Fatalf("align the peer's row: %v", err)
	}
	if err := s.db.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy peer→local: %v", err)
	}
	if n := s.db.UnresolvedTieTables()["vms"]; n == 0 {
		t.Fatalf("fixture produced no vms tie (tables=%v); the assertion below would pass "+
			"for the wrong reason", s.db.UnresolvedTieTables())
	}

	requireWithheld(t, s, "ownership")
}

// TestOwnershipTieCategory_FailsClosedOnAnUnknownCategory is the property that
// makes the category filter safe to add categories to.
//
// A category nobody classified must withhold. This latch is monotone and never
// re-opens, so a wrongly-withheld capability is recoverable by classifying the
// category, while a capability latched over a live ownership dispute is not.
func TestOwnershipTieCategory_FailsClosedOnAnUnknownCategory(t *testing.T) {
	for _, category := range []string{"", "brand_new_category", "typo_runtime_owned"} {
		if !ownershipTieCategory(category) {
			t.Errorf("category %q did not withhold; an unclassified category must fail closed", category)
		}
	}
}

// TestOwnershipTieCategory_ClassifiesTheCategoriesCorrosionEmits pins the verdict
// for every category the resolver and the merges actually produce today, with
// the four Task 0 got wrong called out.
//
// The category strings are the contract between the two packages. A rename in
// corrosion without a change here would silently reclassify a tie — in the
// fail-closed direction, which is why this is a table rather than a derivation:
// see the note in the test body.
func TestOwnershipTieCategory_ClassifiesTheCategoriesCorrosionEmits(t *testing.T) {
	// Deriving this list dynamically — driving every capabilityMap chain with an
	// all-columns-differ rowView — was considered and rejected. It is possible
	// (newRowView is reachable from a corrosion test), but the only drift it
	// would catch beyond the table below is a NEW category that should have been
	// non-ownership being left unclassified, and that direction fails closed:
	// it over-withholds, which is visible and recoverable. The dangerous
	// direction — a table that carries an owner epoch not being recognised — is
	// caught in corrosion by
	// TestOwnershipBearingTables_CoverEveryOwnerEpochColumn, derived from
	// schemaDDL.
	for _, tc := range []struct {
		category  string
		withholds bool
		why       string
	}{
		{"runtime_owned", true, "vms.host_name / pending_action_id, containers"},
		{"tenancy", true, "a project ownership split"},
		{"control_plane", true, "hosts.state IS the voting roster this latch is derived from"},
		{"immutable_ownership_conflict", true, "operations, operation_steps — owner_epoch is in the PK"},
		{"identity_content_conflict", true, "a workload identity conflict"},
		{"workload_identity_conflict", true, "the anti-entropy authority guard's identity fault"},
		{"uncategorized", true, "the resolver could not classify it ⇒ unknown ⇒ closed"},

		{"immutable_ledger_conflict", false, "a contested lease term is not evidence about a workload's owner epoch"},
		{"opaque", false, "a differing spec/create_spec blob, no ownership column"},
		{"content", false, "benign content convergence"},
		{"policy", false, "a policy blob"},
	} {
		if got := ownershipTieCategory(tc.category); got != tc.withholds {
			t.Errorf("ownershipTieCategory(%q) = %v, want %v — %s",
				tc.category, got, tc.withholds, tc.why)
		}
	}
}
