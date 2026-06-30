package health

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

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
