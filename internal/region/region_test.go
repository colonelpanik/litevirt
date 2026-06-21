package region

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func newTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestList_EmptyClusterFallback(t *testing.T) {
	db := newTestDB(t)
	regions, err := List(context.Background(), db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(regions) != 1 || regions[0] != Default {
		t.Errorf("empty cluster regions = %v, want [%q]", regions, Default)
	}
}

func TestList_DistinctRegions(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	for _, h := range []corrosion.HostRecord{
		{Name: "ny-1", Address: "10.0.0.1", State: "active", FenceStrategy: "best-effort"},
		{Name: "ny-2", Address: "10.0.0.2", State: "active", FenceStrategy: "best-effort"},
		{Name: "lon-1", Address: "10.0.1.1", State: "active", FenceStrategy: "best-effort"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "ny-1", "ny"); err != nil {
		t.Fatalf("UpdateHostRegion ny-1: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "ny-2", "ny"); err != nil {
		t.Fatalf("UpdateHostRegion ny-2: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "lon-1", "lon"); err != nil {
		t.Fatalf("UpdateHostRegion lon-1: %v", err)
	}
	regions, err := List(ctx, db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(regions) != 2 || regions[0] != "lon" || regions[1] != "ny" {
		t.Errorf("regions = %v, want [lon ny]", regions)
	}
}

func TestStatusAll_RollsUpHostsAndVMs(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "ny-1", Address: "10.0.0.1", State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "ny-1", "ny"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", StackName: "stack1", HostName: "ny-1", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	statuses, err := StatusAll(ctx, db)
	if err != nil {
		t.Fatalf("StatusAll: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("want 1 status, got %d", len(statuses))
	}
	st := statuses[0]
	if st.Name != "ny" || st.HostCount != 1 || st.ActiveHosts != 1 || st.VMCount != 1 {
		t.Errorf("status = %+v", st)
	}
}

func TestValidateCrossRegion_RejectsSameRegion(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	for _, h := range []corrosion.HostRecord{
		{Name: "ny-1", Address: "10.0.0.1", State: "active", FenceStrategy: "best-effort"},
		{Name: "ny-2", Address: "10.0.0.2", State: "active", FenceStrategy: "best-effort"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
		if err := corrosion.UpdateHostRegion(ctx, db, h.Name, "ny"); err != nil {
			t.Fatalf("UpdateHostRegion: %v", err)
		}
	}
	_, _, err := ValidateCrossRegion(ctx, db, "ny-1", "ny-2")
	if !errors.Is(err, ErrSameRegion) {
		t.Errorf("want ErrSameRegion, got %v", err)
	}
}

func TestValidateCrossRegion_AcceptsDifferentRegions(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	for _, hr := range []struct{ name, region string }{
		{"ny-1", "ny"},
		{"lon-1", "lon"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: hr.name, Address: "10.0.0.1", State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
		if err := corrosion.UpdateHostRegion(ctx, db, hr.name, hr.region); err != nil {
			t.Fatalf("UpdateHostRegion: %v", err)
		}
	}
	src, dst, err := ValidateCrossRegion(ctx, db, "ny-1", "lon-1")
	if err != nil {
		t.Fatalf("ValidateCrossRegion: %v", err)
	}
	if src != "ny" || dst != "lon" {
		t.Errorf("regions = (%q, %q), want (ny, lon)", src, dst)
	}
}

func TestValidateCrossRegion_RejectsInactive(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "ny-1", Address: "10.0.0.1", State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost ny-1: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "ny-1", "ny"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "lon-1", Address: "10.0.1.1", State: "draining", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost lon-1: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "lon-1", "lon"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}
	_, _, err := ValidateCrossRegion(ctx, db, "ny-1", "lon-1")
	if err == nil {
		t.Fatal("want error for non-active target")
	}
}
