package health

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/network"
)

func ctLeaseOwner(t *testing.T, db *corrosion.Client, ctName string) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT owner_host FROM ip_allocations WHERE owner_kind='ct' AND vm_name=? AND deleted_at IS NULL`, ctName)
	if err != nil {
		t.Fatalf("lease query: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("owner_host")
}

// ctRekeyFixture: ct1 runs locally on node-a's runtime, but the only live DB row
// is owned by node-b. Active worker hosts node-a/b/c. Controllable clock.
func ctRekeyFixture(t *testing.T) (*ContainerChecker, *corrosion.Client, *time.Time, map[string]string) {
	t.Helper()
	db := testLogicDB(t)
	ctx := context.Background()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node-b", Name: "ct1", State: "running", Image: "alpine", CreateSpec: `{"image":"alpine"}`,
	})
	for i, h := range []string{"node-a", "node-b", "node-c"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: fmt.Sprintf("10.0.0.%d", i+1), State: "active",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateRunning // running locally on node-a
	c := NewContainerChecker("node-a", db, rt)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return clock }
	results := map[string]string{}
	c.SetContainerRekeyObserver(func(n, res string) { results[n] = res })
	return c, db, &clock, results
}

func liveCt(t *testing.T, db *corrosion.Client, host, name string) *corrosion.ContainerRecord {
	t.Helper()
	ct, err := corrosion.GetContainer(context.Background(), db, host, name)
	if err != nil {
		t.Fatalf("GetContainer(%s,%s): %v", host, name, err)
	}
	return ct
}

// No other host runs ct1 → after the debounce, re-key ownership to node-a (PK
// change: node-b row tombstoned, node-a row live+running with the rekey marker).
func TestCtRekey_NoneRunningReclaims(t *testing.T) {
	ctx := context.Background()
	c, db, clock, results := ctRekeyFixture(t)
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })

	c.assertContainerOwnership(ctx) // seed debounce
	if liveCt(t, db, "node-b", "ct1") == nil {
		t.Fatal("node-b row must still be live before the debounce elapses")
	}
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)

	if liveCt(t, db, "node-b", "ct1") != nil {
		t.Fatal("node-b row must be tombstoned after re-key")
	}
	got := liveCt(t, db, "node-a", "ct1")
	if got == nil || got.State != "running" || got.StateDetail != corrosion.ContainerRuntimeRekeyDetail {
		t.Fatalf("node-a row must be live/running with the rekey marker, got %+v", got)
	}
	if got.CreateSpec != `{"image":"alpine"}` {
		t.Fatalf("create_spec must be carried to the new row, got %q", got.CreateSpec)
	}
	if results["ct1"] != "rekeyed" {
		t.Fatalf("result = %q, want rekeyed", results["ct1"])
	}
	if n := auditCount(t, db, "ct.runtime-owner-rekey"); n != 1 {
		t.Fatalf("want 1 rekey audit row, got %d", n)
	}
}

// Re-key must move the WHOLE ownership footprint: the container_interfaces rows
// and the IPAM leases follow the row to the repaired host (regression — PR 2a
// made those part of CT ownership).
func TestCtRekey_MovesInterfacesAndLeases(t *testing.T) {
	ctx := context.Background()
	db := testLogicDB(t)
	specJSON, _ := json.Marshal(corrosion.ContainerCreateSpec{
		Networks: []corrosion.ContainerNetwork{{NetworkName: "net1", MAC: "52:54:00:aa:bb:cc", IP: "10.0.0.5"}},
	})
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node-b", Name: "ct1", State: "running", Image: "alpine", CreateSpec: string(specJSON),
	})
	// Managed interface row + IPAM lease on the stale owner (node-b).
	if err := corrosion.UpsertContainerInterface(ctx, db, corrosion.ContainerInterfaceRecord{
		HostName: "node-b", CtName: "ct1", NetworkName: "net1", Ordinal: 0,
		MAC: "52:54:00:aa:bb:cc", IP: "10.0.0.5", VethDevice: corrosion.ContainerVethName("ct1", 0),
	}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}
	if ok, err := network.ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "52:54:00:aa:bb:cc", "node-b", "ct1"); err != nil || !ok {
		t.Fatalf("ReserveContainerIP: ok=%v err=%v", ok, err)
	}
	for i, h := range []string{"node-a", "node-b", "node-c"} {
		_ = corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: h, Address: fmt.Sprintf("10.9.0.%d", i+1), State: "active"})
	}
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateRunning
	c := NewContainerChecker("node-a", db, rt)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return clock }
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })

	c.assertContainerOwnership(ctx)
	clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)

	// Interface row moved node-b → node-a.
	if ifs, _ := corrosion.GetContainerInterfaces(ctx, db, "node-b", "ct1"); len(ifs) != 0 {
		t.Fatalf("source interface rows must be tombstoned, got %d", len(ifs))
	}
	ifs, _ := corrosion.GetContainerInterfaces(ctx, db, "node-a", "ct1")
	if len(ifs) != 1 || ifs[0].NetworkName != "net1" {
		t.Fatalf("interface row must be rebuilt on node-a, got %+v", ifs)
	}
	// Lease owner_host moved node-b → node-a.
	if owner := ctLeaseOwner(t, db, "ct1"); owner != "node-a" {
		t.Fatalf("lease owner_host must be node-a after re-key, got %q", owner)
	}
}

// A stale soft-deleted target row must not leak old create_spec into the
// resurrected row (the dedicated re-key write replaces, never keep-existing).
func TestCtRekey_StaleTargetRowReplaced(t *testing.T) {
	ctx := context.Background()
	c, db, clock, _ := ctRekeyFixture(t)
	// A leftover soft-deleted (node-a, ct1) row with STALE metadata.
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node-a", Name: "ct1", State: "stopped", CreateSpec: `{"image":"STALE"}`})
	if err := db.Execute(ctx, `UPDATE containers SET deleted_at = ? WHERE host_name='node-a' AND name='ct1'`, db.NowTS()); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)

	got := liveCt(t, db, "node-a", "ct1")
	if got == nil || got.CreateSpec != `{"image":"alpine"}` {
		t.Fatalf("resurrected row must carry the SOURCE create_spec, not the stale one, got %+v", got)
	}
}

// The orphan-lease GC must NOT release a local lease for a container that exists
// in the local RUNTIME but whose DB row points elsewhere (the divergence case) —
// even when no re-key happens (peers inconclusive). One sweep keeps the lease.
func TestCtRekey_LeaseNotGCdBeforeRepair(t *testing.T) {
	ctx := context.Background()
	c, db, _, _ := ctRekeyFixture(t)
	// An aged local lease for ct1 (owner node-a) with no live node-a DB row.
	if ok, err := network.ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac", "node-a", "ct1"); err != nil || !ok {
		t.Fatalf("ReserveContainerIP: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE ip_allocations SET allocated_at = ? WHERE vm_name='ct1'`, "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("age lease: %v", err)
	}
	// Peers inconclusive → no re-key — isolates the GC-live-set fix.
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeUnknown, nil })

	c.SweepOnce(ctx)

	if owner := ctLeaseOwner(t, db, "ct1"); owner != "node-a" {
		t.Fatalf("a runtime-present container's lease must NOT be GC'd before repair, owner now %q", owner)
	}
}

// The guarded re-key transaction must DECLINE (write nothing) when a precondition
// changes between the caller's observation and the write — the read→probe→write
// race the reconciler can't otherwise close.
func TestRekeyContainerOwner_GuardRejectsRaces(t *testing.T) {
	ctx := context.Background()

	// (a) source updated_at changed since observed (it was touched / re-homed).
	db := testLogicDB(t)
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node-b", Name: "ct1", State: "running", Image: "alpine"})
	remote, _ := corrosion.GetContainer(ctx, db, "node-b", "ct1")
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node-b", Name: "ct1", State: "running", Image: "alpine2"}) // bumps updated_at
	if applied, err := corrosion.RekeyContainerOwner(ctx, db, *remote, "node-a"); err != nil || applied {
		t.Fatalf("stale-source re-key must be declined, applied=%v err=%v", applied, err)
	}
	if liveCt(t, db, "node-a", "ct1") != nil {
		t.Fatal("declined re-key must not create a target row")
	}
	if liveCt(t, db, "node-b", "ct1") == nil {
		t.Fatal("declined re-key must leave the source live")
	}

	// (b) a LIVE target row appeared → abort, never clobber it.
	db2 := testLogicDB(t)
	insertCt(t, db2, corrosion.ContainerRecord{HostName: "node-b", Name: "ct1", State: "running", Image: "alpine"})
	remote2, _ := corrosion.GetContainer(ctx, db2, "node-b", "ct1")
	insertCt(t, db2, corrosion.ContainerRecord{HostName: "node-a", Name: "ct1", State: "running", Image: "LIVE-LOCAL"})
	if applied, _ := corrosion.RekeyContainerOwner(ctx, db2, *remote2, "node-a"); applied {
		t.Fatal("re-key must abort when a live target row exists")
	}
	if got := liveCt(t, db2, "node-a", "ct1"); got == nil || got.Image != "LIVE-LOCAL" {
		t.Fatalf("a live target row must NOT be clobbered, got %+v", got)
	}

	// (c) source entered relocation since observed.
	db3 := testLogicDB(t)
	insertCt(t, db3, corrosion.ContainerRecord{HostName: "node-b", Name: "ct1", State: "running", Image: "alpine"})
	remote3, _ := corrosion.GetContainer(ctx, db3, "node-b", "ct1")
	insertCt(t, db3, corrosion.ContainerRecord{
		HostName: "node-b", Name: "ct1", State: "relocating", Image: "alpine",
		StateDetail: corrosion.RelocateRestoreDetail("node-a", "tok"),
	})
	if applied, _ := corrosion.RekeyContainerOwner(ctx, db3, *remote3, "node-a"); applied {
		t.Fatal("re-key must abort when the source entered relocation")
	}

	// (d) a managed NIC IP with no source lease → refuse (never assert an unowned IP).
	db4 := testLogicDB(t)
	specJSON, _ := json.Marshal(corrosion.ContainerCreateSpec{
		Networks: []corrosion.ContainerNetwork{{NetworkName: "net1", IP: "10.0.0.5"}},
	})
	insertCt(t, db4, corrosion.ContainerRecord{HostName: "node-b", Name: "ct1", State: "running", Image: "alpine", CreateSpec: string(specJSON)})
	remote4, _ := corrosion.GetContainer(ctx, db4, "node-b", "ct1")
	if applied, _ := corrosion.RekeyContainerOwner(ctx, db4, *remote4, "node-a"); applied {
		t.Fatal("re-key must refuse a managed NIC IP the source holds no lease for")
	}
	if liveCt(t, db4, "node-a", "ct1") != nil {
		t.Fatal("refused re-key must not create a target row")
	}

	// (e) a lease exists for the SAME ip on a DIFFERENT network than the managed
	// NIC claims → refuse (ip_allocations is keyed by (network, ip); a net-b lease
	// does not back a net-a NIC).
	db5 := testLogicDB(t)
	spec5, _ := json.Marshal(corrosion.ContainerCreateSpec{
		Networks: []corrosion.ContainerNetwork{{NetworkName: "net-a", IP: "10.0.0.5"}},
	})
	insertCt(t, db5, corrosion.ContainerRecord{HostName: "node-b", Name: "ct1", State: "running", Image: "alpine", CreateSpec: string(spec5)})
	remote5, _ := corrosion.GetContainer(ctx, db5, "node-b", "ct1")
	// Lease is for net-b/10.0.0.5 — the WRONG network.
	if ok, err := network.ReserveContainerIP(ctx, db5, "net-b", "10.0.0.5", "mac", "node-b", "ct1"); err != nil || !ok {
		t.Fatalf("ReserveContainerIP: %v", err)
	}
	if applied, _ := corrosion.RekeyContainerOwner(ctx, db5, *remote5, "node-a"); applied {
		t.Fatal("re-key must refuse: the lease is for a different network than the managed NIC")
	}
	if liveCt(t, db5, "node-a", "ct1") != nil {
		t.Fatal("wrong-network lease re-key must not create a target row")
	}
}

// Another host reports the container running → split-brain → never re-key.
func TestCtRekey_SplitBrainRefuses(t *testing.T) {
	ctx := context.Background()
	c, db, clock, results := ctRekeyFixture(t)
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-b" {
			return RuntimeRunning, nil
		}
		return RuntimeAbsent, nil
	})
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)

	if liveCt(t, db, "node-b", "ct1") == nil {
		t.Fatal("split-brain must NOT tombstone the remote row")
	}
	if liveCt(t, db, "node-a", "ct1") != nil {
		t.Fatal("split-brain must NOT create a local row")
	}
	if results["ct1"] != "split_brain" {
		t.Fatalf("result = %q, want split_brain", results["ct1"])
	}
}

// A peer reporting defined_stopped (stale leftover) does NOT block; an
// unreachable/unknown peer does (inconclusive).
func TestCtRekey_DefinedStoppedAllowed_UnknownBlocks(t *testing.T) {
	ctx := context.Background()

	// defined_stopped on a peer → still re-keys.
	c, db, clock, results := ctRekeyFixture(t)
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-b" {
			return RuntimeDefinedStopped, nil
		}
		return RuntimeAbsent, nil
	})
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)
	if results["ct1"] != "rekeyed" || liveCt(t, db, "node-a", "ct1") == nil {
		t.Fatalf("a peer's defined-stopped leftover must NOT block re-key, result=%q", results["ct1"])
	}

	// unknown on a peer → inconclusive, no re-key.
	c2, db2, clock2, results2 := ctRekeyFixture(t)
	c2.SetPeerContainerRuntimeChecker(func(_ context.Context, host, _ string) (string, error) {
		if host == "node-c" {
			return RuntimeUnknown, nil
		}
		return RuntimeAbsent, nil
	})
	c2.assertContainerOwnership(ctx)
	*clock2 = clock2.Add(ownershipAssertDebounce + time.Minute)
	c2.assertContainerOwnership(ctx)
	if results2["ct1"] != "inconclusive" || liveCt(t, db2, "node-a", "ct1") != nil {
		t.Fatalf("an unknown peer must block re-key (inconclusive), result=%q", results2["ct1"])
	}
}

// A container under an active relocation (relocate_token set, or relocating/
// pending markers) is never touched.
func TestCtRekey_RelocationMarkerSkips(t *testing.T) {
	ctx := context.Background()
	c, db, clock, results := ctRekeyFixture(t)
	// Mark the node-b row as a restore-relocation in flight.
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node-b", Name: "ct1", State: "relocating", Image: "alpine",
		StateDetail: corrosion.RelocateRestoreDetail("node-a", "tok123"),
	})
	probed := false
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { probed = true; return RuntimeAbsent, nil })
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)
	if probed {
		t.Fatal("a container under relocation must not be probed")
	}
	if liveCt(t, db, "node-a", "ct1") != nil || results["ct1"] != "" {
		t.Fatalf("a relocating container must not be re-keyed, result=%q", results["ct1"])
	}
}

// A live self row, multiple remote rows, or a local witness all stand down.
func TestCtRekey_GuardsStandDown(t *testing.T) {
	ctx := context.Background()

	// (a) a live self row already exists → skip (normal sweep owns it).
	c, db, clock, results := ctRekeyFixture(t)
	insertCt(t, db, corrosion.ContainerRecord{HostName: "node-a", Name: "ct1", State: "running", Image: "alpine"})
	c.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	c.assertContainerOwnership(ctx)
	*clock = clock.Add(ownershipAssertDebounce + time.Minute)
	c.assertContainerOwnership(ctx)
	if results["ct1"] != "" {
		t.Fatalf("a live self row must short-circuit, result=%q", results["ct1"])
	}

	// (b) two remote rows → ambiguous → skip.
	c2, db2, clock2, results2 := ctRekeyFixture(t)
	insertCt(t, db2, corrosion.ContainerRecord{HostName: "node-c", Name: "ct1", State: "running", Image: "alpine"})
	c2.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	c2.assertContainerOwnership(ctx)
	*clock2 = clock2.Add(ownershipAssertDebounce + time.Minute)
	c2.assertContainerOwnership(ctx)
	if results2["ct1"] != "" || liveCt(t, db2, "node-a", "ct1") != nil {
		t.Fatalf("two remote rows must be ambiguous (skip), result=%q", results2["ct1"])
	}

	// (c) local host is a witness → stand down.
	c3, db3, clock3, results3 := ctRekeyFixture(t)
	if err := corrosion.UpdateHostRole(ctx, db3, "node-a", "witness"); err != nil {
		t.Fatalf("UpdateHostRole: %v", err)
	}
	c3.SetPeerContainerRuntimeChecker(func(_ context.Context, _, _ string) (string, error) { return RuntimeAbsent, nil })
	c3.assertContainerOwnership(ctx)
	*clock3 = clock3.Add(ownershipAssertDebounce + time.Minute)
	c3.assertContainerOwnership(ctx)
	if results3["ct1"] != "" || liveCt(t, db3, "node-a", "ct1") != nil {
		t.Fatalf("a witness local host must not re-key, result=%q", results3["ct1"])
	}
}
