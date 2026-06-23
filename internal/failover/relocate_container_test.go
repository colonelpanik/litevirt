package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRelocateContainers: on a fenced host, containers with a re-pullable image
// and an image-recreate policy are re-keyed to a healthy host (pending +
// relocate-recreate); policy=none and non-re-pullable containers are left in
// place (the latter loudly audited).
func TestRelocateContainers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	mk := func(name, image, policy string) {
		if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
			HostName: "dead", Name: name, State: "running", Image: image,
			CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: policy,
		}); err != nil {
			t.Fatalf("UpsertContainer %s: %v", name, err)
		}
	}
	mk("web", "alpine:3.19", "image-recreate") // relocates
	mk("novol", "", "image-recreate")          // skipped: no re-pullable image
	mk("noop", "alpine:3.19", "none")          // skipped: policy none

	c := newTestCoordinator("coord", db)
	idx := 0
	candidates := []corrosion.HostRecord{{Name: "live", State: "active"}}
	c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead"}, candidates, &idx)

	// web → relocated to live, pending+relocate-recreate, source row gone.
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "web"); g != nil {
		t.Errorf("web source row still present: %+v", g)
	}
	web, _ := corrosion.GetContainer(ctx, db, "live", "web")
	if web == nil || web.State != "pending" || web.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Errorf("web not relocated correctly: %+v", web)
	}
	// novol + noop stay on dead (not relocated).
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "novol"); g == nil {
		t.Error("novol should not have been relocated (no re-pullable image)")
	}
	if g, _ := corrosion.GetContainer(ctx, db, "dead", "noop"); g == nil {
		t.Error("noop should not have been relocated (policy=none)")
	}
	if g, _ := corrosion.GetContainer(ctx, db, "live", "novol"); g != nil {
		t.Errorf("novol wrongly relocated: %+v", g)
	}

	// The skip was audited (ct.relocate.skipped).
	rows, _ := db.Query(ctx, `SELECT action FROM audit_log WHERE target = 'novol' AND action = 'ct.relocate.skipped'`)
	if len(rows) == 0 {
		t.Error("expected a ct.relocate.skipped audit row for novol")
	}
}
