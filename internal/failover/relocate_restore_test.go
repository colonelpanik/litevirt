package failover

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeRestorer records RestoreContainerFromBackup calls and, on success,
// simulates RestoreContainer having created the target row (its mandatory,
// post-import row write).
type fakeRestorer struct {
	calls int
	err   error
	// createThenErr models RestoreContainer's "row written, then start failed":
	// the target row is created AND an error is returned.
	createThenErr bool
	db            *corrosion.Client
}

func (f *fakeRestorer) RestoreContainerFromBackup(ctx context.Context, ctName, target string) error {
	f.calls++
	if f.err == nil || f.createThenErr {
		_ = corrosion.UpsertContainer(ctx, f.db, corrosion.ContainerRecord{
			HostName: target, Name: ctName, State: "stopped", Image: "alpine:3.19",
			OnHostFailure: "image-recreate",
		})
	}
	return f.err
}

// relocateSetup builds a fenced source host + a survivor and a container on the
// source. survivorSchema controls the survivor's advertised schema_version
// (>= CurrentSchemaVersion ⇒ tier-2 eligible). image is the container's image.
func relocateSetup(t *testing.T, image string, survivorSchema int) (*corrosion.Client, *corrosion.HostRecord, []corrosion.HostRecord) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "src", Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443, State: "fenced", CertSerial: "s",
	}); err != nil {
		t.Fatalf("InsertHost src: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "surv", Address: "10.0.0.2", SSHUser: "root", GRPCPort: 7443, State: "active", CertSerial: "v",
	}); err != nil {
		t.Fatalf("InsertHost surv: %v", err)
	}
	// UpdateHostStartup stamps schema_version = CurrentSchemaVersion. Only call it
	// when we want the survivor schema-compatible; otherwise it stays 0 (< current).
	if survivorSchema >= corrosion.CurrentSchemaVersion {
		if err := corrosion.UpdateHostStartup(ctx, db, "surv", "active", "v1", 8, 16384, 100, true); err != nil {
			t.Fatalf("UpdateHostStartup surv: %v", err)
		}
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "src", Name: "ct1", State: "running", Image: image, OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	src, _ := corrosion.GetHost(ctx, db, "src")
	surv, _ := corrosion.GetHost(ctx, db, "surv")
	return db, src, []corrosion.HostRecord{*surv}
}

func TestRelocate_RestorePreferred(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	fr := &fakeRestorer{db: db}
	c.Restorer = fr

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	if fr.calls != 1 {
		t.Fatalf("restorer called %d times, want 1", fr.calls)
	}
	if srcRow, _ := corrosion.GetContainer(ctx, db, "src", "ct1"); srcRow != nil {
		t.Fatal("source row must be tombstoned after a successful restore")
	}
	if tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1"); tgt == nil {
		t.Fatal("target row must exist after restore")
	}
}

func TestRelocate_FallbackToImageRecreateOnRestoreError(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	c.Restorer = &fakeRestorer{db: db, err: errors.New("no manifest")}

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	// Image-recreate: source soft-deleted, fresh target row pending+relocate-recreate.
	if srcRow, _ := corrosion.GetContainer(ctx, db, "src", "ct1"); srcRow != nil {
		t.Fatal("source row should be soft-deleted by image-recreate fallback")
	}
	tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1")
	if tgt == nil || tgt.State != "pending" || tgt.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("expected pending+relocate-recreate target row, got %+v", tgt)
	}
}

func TestRelocate_SkipWhenNeitherRestoreNorImage(t *testing.T) {
	db, src, cands := relocateSetup(t, "", corrosion.CurrentSchemaVersion) // empty image = non-re-pullable
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	c.Restorer = &fakeRestorer{db: db, err: errors.New("no manifest")}

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	// Restore failed + non-re-pullable → skip; the row is LEFT VISIBLE for operator
	// recovery (not tombstoned), with a terminal relocate-skipped detail.
	row, _ := corrosion.GetContainer(ctx, db, "src", "ct1")
	if row == nil {
		t.Fatal("skipped container must remain visible for operator recovery, not be tombstoned")
	}
	if row.StateDetail != corrosion.ContainerRelocateSkippedDetail {
		t.Fatalf("skipped row detail = %q, want %q", row.StateDetail, corrosion.ContainerRelocateSkippedDetail)
	}
	if tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1"); tgt != nil {
		t.Fatal("no target row should be created when skipping")
	}

	// A second pass must NOT re-process the skipped row (no loop).
	c.relocateContainers(ctx, src, cands, &idx)
	row2, _ := corrosion.GetContainer(ctx, db, "src", "ct1")
	if row2 == nil || row2.StateDetail != corrosion.ContainerRelocateSkippedDetail {
		t.Fatalf("skipped row should be untouched on a second pass, got %+v", row2)
	}
}

// TestRelocate_RestoreRowExistsDespiteError covers a restore that wrote the
// target row but then errored (e.g. start failed): the coordinator must treat it
// as complete (tombstone source) — NOT image-recreate over the good restored row.
func TestRelocate_RestoreRowExistsDespiteError(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	c.Restorer = &fakeRestorer{db: db, err: errors.New("restored but start failed"), createThenErr: true}

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	if srcRow, _ := corrosion.GetContainer(ctx, db, "src", "ct1"); srcRow != nil {
		t.Fatal("source must be tombstoned: the restore landed (target row exists) despite the error")
	}
	tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1")
	if tgt == nil || tgt.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("target should be the restored row, not an image-recreate, got %+v", tgt)
	}
}

func TestRelocate_SchemaIncompatibleSurvivorImageRecreates(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", 0) // survivor schema 0 < current
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	fr := &fakeRestorer{db: db}
	c.Restorer = fr

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	if fr.calls != 0 {
		t.Fatalf("restore must NOT run against a schema-behind survivor; calls=%d", fr.calls)
	}
	tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1")
	if tgt == nil || tgt.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("expected image-recreate fallback, got %+v", tgt)
	}
}

// --- crash-window recovery ---

func TestRelocate_ResumeRestoredThenCrashBeforeTombstone(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	fr := &fakeRestorer{db: db}
	c.Restorer = fr

	// Simulate: marker set + restore already created the target row, but the
	// coordinator crashed before tombstoning the source.
	if err := corrosion.SetContainerStateDetail(ctx, db, "src", "ct1", "relocating", corrosion.ContainerRelocateRestorePrefix+"surv"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "surv", Name: "ct1", State: "stopped", Image: "alpine:3.19", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	if fr.calls != 0 {
		t.Fatalf("must NOT re-restore when the target row already exists; calls=%d", fr.calls)
	}
	if srcRow, _ := corrosion.GetContainer(ctx, db, "src", "ct1"); srcRow != nil {
		t.Fatal("resume should tombstone the source row once the target exists")
	}
}

func TestRelocate_ResumeFreshMarkerSkips(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	fr := &fakeRestorer{db: db}
	c.Restorer = fr
	c.RelocateRestoreTimeout = time.Hour // marker just written ⇒ fresh

	if err := corrosion.SetContainerStateDetail(ctx, db, "src", "ct1", "relocating", corrosion.ContainerRelocateRestorePrefix+"surv"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	if fr.calls != 0 {
		t.Fatalf("a fresh in-flight marker must be skipped (no duplicate restore); calls=%d", fr.calls)
	}
	row, _ := corrosion.GetContainer(ctx, db, "src", "ct1")
	if row == nil || row.State != "relocating" {
		t.Fatalf("source should remain relocating while fresh, got %+v", row)
	}
}

func TestRelocate_ResumeStaleMarkerFallsBack(t *testing.T) {
	db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	fr := &fakeRestorer{db: db}
	c.Restorer = fr
	c.RelocateRestoreTimeout = time.Nanosecond // any marker is immediately stale

	if err := corrosion.SetContainerStateDetail(ctx, db, "src", "ct1", "relocating", corrosion.ContainerRelocateRestorePrefix+"surv"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	time.Sleep(2 * time.Millisecond) // ensure now-updated_at > timeout

	idx := 0
	c.relocateContainers(ctx, src, cands, &idx)

	// Stale + no target row → image-recreate fallback.
	if srcRow, _ := corrosion.GetContainer(ctx, db, "src", "ct1"); srcRow != nil {
		t.Fatal("stale marker should fall back to image-recreate (source soft-deleted)")
	}
	tgt, _ := corrosion.GetContainer(ctx, db, "surv", "ct1")
	if tgt == nil || tgt.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("expected image-recreate fallback after stale marker, got %+v", tgt)
	}
}
