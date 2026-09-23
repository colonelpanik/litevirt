package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestPublishVMRunning_MarksBeforeItCommits: for a NON-minting transition the
// markers must be on disk before the row says running.
//
// Observed from INSIDE commit, because the end state is identical either way —
// which is exactly why nothing local would otherwise notice the ordering.
func TestPublishVMRunning_MarksBeforeItCommits(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	var fileAtCommit, domAtCommit int64
	err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 5,
		func(context.Context) error {
			fileAtCommit, _, _ = ReadVMOwnerEpochMarker(dir, "vm1")
			domAtCommit, _, _ = fake.GetDomainOwnerEpoch("vm1")
			return nil
		})
	if err != nil {
		t.Fatalf("PublishVMRunning: %v", err)
	}
	if fileAtCommit != 5 || domAtCommit != 5 {
		t.Errorf("markers at commit = file %d / domain %d, want 5/5 — a running row must never "+
			"exist without a marker naming its generation", fileAtCommit, domAtCommit)
	}
}

// TestPublishVMRunning_NoMarkerAtAllDoesNotCommit is mark-then-commit's core
// refusal: a VM that can prove NOTHING must not be published as running.
//
// Both writes have to fail for this, because either marker alone is enough to
// prove the generation — see writeBothMarkers on why neither half is a
// precondition for the other.
func TestPublishVMRunning_NoMarkerAtAllDoesNotCommit(t *testing.T) {
	fake := libvirtfake.New() // no domain, so SetDomainOwnerEpoch fails
	// And a dataDir whose marker tree cannot be created: a FILE where the
	// directory needs to be, which is what MkdirAll fails on.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vms"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	committed := false
	err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil })
	if err == nil {
		t.Error("losing BOTH markers must be returned, not swallowed")
	}
	if committed {
		t.Error("the state write ran with no marker at all; that publishes an unprovable VM")
	}
}

// TestPublishVMRunning_APreEpochRowStillPublishes: a SUCCESSFUL read of 0 is a
// fact about a row the backfill has not graduated.
//
// Marking it would create the marker-against-an-epoch-0-row state convergence
// returns early on and never repairs. Refusing would strand every un-graduated
// VM on a fleet that has not enabled enforcement.owner_epoch, which is default.
func TestPublishVMRunning_APreEpochRowStillPublishes(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	committed := false
	if err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 0,
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("a pre-epoch row must still publish: %v", err)
	}
	if !committed {
		t.Error("the state write was skipped for a pre-epoch row")
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a marker was written for a pre-epoch row")
	}
}

// TestPublishVMRunning_ANilConcreteClientDoesNotPanic is the typed-nil trap.
//
// A nil *libvirtfake.Fake (or *lv.Client) passed as DomainEpochSetter is a
// NON-nil interface holding a nil pointer: a `virt != nil` guard passes and the
// method call then dereferences nil. VMChecker.virt is exactly that shape and is
// nil in ~70 tests, so this is the normal case, not a corner one.
func TestPublishVMRunning_ANilConcreteClientDoesNotPanic(t *testing.T) {
	var nilClient *libvirtfake.Fake // concrete nil; non-nil once boxed
	committed := false
	err := PublishVMRunning(context.Background(), nilClient, t.TempDir(), "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil })
	if err != nil {
		t.Fatalf("a nil backend must skip the domain marker, not fail: %v", err)
	}
	if !committed {
		t.Error("a nil backend must not block the transition")
	}
}

// TestPublishVMRunning_ReturnsTheCommitError: the callback's error is the
// caller's to handle, unchanged.
func TestPublishVMRunning_ReturnsTheCommitError(t *testing.T) {
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	want := errors.New("state write refused")
	if got := PublishVMRunning(context.Background(), fake, t.TempDir(), "vm1", "running", 5,
		func(context.Context) error { return want }); !errors.Is(got, want) {
		t.Errorf("err = %v, want the commit's own error", got)
	}
}

// TestPublishVMRunning_SkipsTheFileMarkerWithoutADataDir matches readVMMarker's
// treatment of an empty dataDir, so no marker lands on a path no reader resolves.
func TestPublishVMRunning_SkipsTheFileMarkerWithoutADataDir(t *testing.T) {
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	t.Chdir(t.TempDir())
	if err := PublishVMRunning(context.Background(), fake, "", "vm1", "running", 5,
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("PublishVMRunning: %v", err)
	}
	if _, err := os.Stat(filepath.Join("vms", "vm1", "owner_epoch")); err == nil {
		t.Error("a marker was written to a relative path")
	}
}

// TestPublishVMRunningMinted_MarksTheEpochTheCommitProduced is the finding that
// forced two orderings.
//
// TransferVMOwner sets state='running' AND vm_owner_epoch = vm_owner_epoch + 1
// in one statement. Marking before it stamps the SUPERSEDED generation — the
// exact marker/row disagreement condition 7 reports. The marker must name what
// the commit produced, so it is written after.
func TestPublishVMRunningMinted_MarksTheEpochTheCommitProduced(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 6 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	if err := PublishVMRunningMinted(ctx, fake, db, dir, "node-a", "vm1", func(ctx context.Context) error {
		return corrosion.TransferVMOwner(ctx, db, "vm1", "node-a", "running", 6)
	}); err != nil {
		t.Fatalf("PublishVMRunningMinted: %v", err)
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.OwnerEpoch != 7 {
		t.Fatalf("row epoch = %d, want 7 (the transfer mints)", row.OwnerEpoch)
	}
	epoch, ok, err := ReadVMOwnerEpochMarker(dir, "vm1")
	if err != nil || !ok || epoch != 7 {
		t.Errorf("file marker = (%d,%v,%v), want (7,true,nil) — marking before a minting commit "+
			"names the generation the row just left", epoch, ok, err)
	}
	if e, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || e != 7 {
		t.Errorf("domain marker = (%d,%v), want (7,true)", e, ok)
	}
}

// TestPublishVMRunningMinted_AFailedCommitMarksNothing
func TestPublishVMRunningMinted_AFailedCommitMarksNothing(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	want := errors.New("mint refused")
	if got := PublishVMRunningMinted(ctx, fake, db, dir, "node-a", "vm1",
		func(context.Context) error { return want }); !errors.Is(got, want) {
		t.Errorf("err = %v, want the commit's error", got)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a marker was written although the minting commit failed")
	}
}

// TestPublishVMRunningMinted_AMarkerFailureIsNotFatal is the opposite of the
// non-minting contract, deliberately.
//
// The commit has landed and the guest is running, so refusing undoes nothing —
// and a positive epoch with a missing marker is precisely
// convergeOwnerEpochMarker's repair case, whose call site fires for any
// confirmed-running VM regardless of the enforcement flag.
func TestPublishVMRunningMinted_AMarkerFailureIsNotFatal(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node-a"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New() // NO domain, so the domain marker write fails

	if err := PublishVMRunningMinted(ctx, fake, db, t.TempDir(), "node-a", "vm1",
		func(ctx context.Context) error {
			return corrosion.UpdateVMState(ctx, db, "vm1", "running", "test")
		}); err != nil {
		t.Errorf("a marker failure after a landed commit must not be reported as failure "+
			"(convergence repairs it): %v", err)
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" {
		t.Errorf("state = %q, want running — the commit had already landed", row.State)
	}
}

// TestPublishVMRunningMinted_AReadBackFailureIsNotTheCommitsFailure.
//
// The read-back happens AFTER the commit has landed, so returning it as an error
// tells the caller its write failed when it did not. Three of the four call sites
// then abort the rest of their sequence: a promotion skipped its disk re-point,
// and repair-owner and owner-assert skipped their audit records, for ownership
// changes that had actually succeeded. Convergence can repair an unmarked running
// VM; it cannot reconstruct the durable writes an aborted caller never made.
func TestPublishVMRunningMinted_AReadBackFailureIsNotTheCommitsFailure(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	committed := false
	err := PublishVMRunningMinted(ctx, fake, db, t.TempDir(), "node-a", "vm1",
		func(context.Context) error { committed = true; db.Close(); return nil })
	if err != nil {
		t.Errorf("a read-back failure after a landed commit must not be reported as a failed "+
			"transition — the caller aborts its remaining durable writes: %v", err)
	}
	if !committed {
		t.Fatal("the commit never ran, so this test proves nothing about the read-back")
	}
}

// TestPublishVMRunning_ANonRunningStateWritesNoMarkers is the state gate.
//
// Several routed sites write a state that is dynamic at the call but provably
// never "running" — classifyStop's output, a drift heal toward libvirt — and one
// is genuinely either. Without the gate a uniform wrap stamps a RUNNING marker
// (and a LIVE domain write, which libvirt rejects on an inactive domain) on an
// out-of-band STOP, and PublishVMRunning's fatal contract then drops the stop
// sync entirely: the row stays "running" for a VM that is down.
func TestPublishVMRunning_ANonRunningStateWritesNoMarkers(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New() // no domain: a marker write would fail
	committed := false
	if err := PublishVMRunning(context.Background(), fake, dir, "vm1", "stopped", 5,
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("a non-running publish must not be gated on markers: %v", err)
	}
	if !committed {
		t.Error("the stop sync was dropped because a running-marker write failed")
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a running marker was written for a stopped publish")
	}
}

// TestPublishVMRunningMinted_OwnershipMovedLeavesTheMarkersAlone.
//
// A second ownership transition landing between our commit and our read-back
// hands us the NEXT owner's generation. Stamping our own runtime with it makes a
// superseded runtime look current — the one direction of this race that is not
// fail-safe, because runtimeSuperseded then sees a marker that agrees with the
// row and declines to refuse a runtime it should have refused.
func TestPublishVMRunningMinted_OwnershipMovedLeavesTheMarkersAlone(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node-a"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	// We are node-a. Our commit lands, then node-b takes the VM before our
	// read-back — so the row we read names node-b's generation, not ours.
	err := PublishVMRunningMinted(ctx, fake, db, dir, "node-a", "vm1",
		func(ctx context.Context) error {
			if cerr := corrosion.UpdateVMState(ctx, db, "vm1", "running", "ours"); cerr != nil {
				return cerr
			}
			return corrosion.TransferVMOwnerFresh(ctx, db, "vm1", "node-b", "running")
		})
	if err != nil {
		t.Fatalf("PublishVMRunningMinted: %v", err)
	}
	row, gerr := corrosion.GetVM(ctx, db, "vm1")
	if gerr != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, gerr)
	}
	if row.HostName != "node-b" {
		t.Fatalf("owner = %q, want node-b — the test did not reproduce the race", row.HostName)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Errorf("node-a stamped its own runtime with node-b's generation %d; a superseded "+
			"runtime must not be made to look current", row.OwnerEpoch)
	}
	if _, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
		t.Error("the domain marker was stamped with the new owner's generation")
	}
}

// TestRowForPublish_RetriesATransientReadFailure.
//
// The state write persistVMState guards already retries 4 times, and its two
// running callers only log and continue. An unretried read in front of it would
// turn one transient store error into a DROPPED state write — a regression the
// old code did not have.
func TestRowForPublish_RetriesATransientReadFailure(t *testing.T) {
	calls := 0
	row, err := rowForPublish(context.Background(), "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("database is locked")
			}
			return &corrosion.VMRecord{Name: "vm1", OwnerEpoch: 4}, nil
		})
	if err != nil {
		t.Fatalf("a transient read failure must be retried, not fatal: %v", err)
	}
	if row == nil || row.OwnerEpoch != 4 {
		t.Errorf("row = %v, want one at epoch 4", row)
	}
	if calls != 2 {
		t.Errorf("read attempted %d time(s), want 2 — the retry never happened", calls)
	}
}

// TestRowForPublish_AMissingRowDoesNotRetry: a successful read finding no
// row is an answer, not a transient failure. Retrying cannot conjure a row.
func TestRowForPublish_AMissingRowDoesNotRetry(t *testing.T) {
	calls := 0
	_, err := rowForPublish(context.Background(), "gone",
		func(context.Context) (*corrosion.VMRecord, error) { calls++; return nil, nil })
	if err == nil {
		t.Error("a missing row must refuse the publish")
	}
	if calls != 1 {
		t.Errorf("read attempted %d time(s), want 1 — a definite answer must not be retried", calls)
	}
}

// TestPublishRunningVia_RefusesWhenOwnershipHasMoved closes the non-minting
// twin of the race PublishVMRunningMinted already guarded against.
//
// A routed publish is often reached from a list snapshot taken seconds earlier
// (the reconciler lists its VMs, then acts on each), so a transfer can land
// before the read rather than merely between the read and the commit. Stamping
// the row's CURRENT epoch onto THIS host's runtime then makes a superseded
// runtime look current: runtimeSuperseded decides by `row.OwnerEpoch > marker`,
// so a marker EQUAL to the row reads as up to date, and the marker comparison is
// defeated for exactly the split-ownership case it exists for.
func TestPublishRunningVia_RefusesWhenOwnershipHasMoved(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-b", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node-b"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	// We are node-a, still running the domain, but the row names node-b.
	committed := false
	err := PublishRunningVia(ctx, fake, db, dir, "node-a", "vm1", "running",
		func(context.Context) error { committed = true; return nil })
	if !errors.Is(err, ErrOwnershipMoved) {
		t.Fatalf("err = %v, want ErrOwnershipMoved", err)
	}
	if committed {
		t.Error("a row another host owns was published as running here; that is a stale write")
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("node-a stamped its own runtime with the generation node-b's row carries; " +
			"runtimeSuperseded compares row > marker, so an EQUAL marker reads as current " +
			"and this host's superseded runtime stops being refused")
	}
}

// TestPublishRunningVia_PublishesWhenTheRowStillNamesUs is the other half: the
// host check must not refuse the ordinary case.
func TestPublishRunningVia_PublishesWhenTheRowStillNamesUs(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node-a"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	committed := false
	if err := PublishRunningVia(ctx, fake, db, dir, "node-a", "vm1", "running",
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("PublishRunningVia: %v", err)
	}
	if !committed {
		t.Error("the host check refused a publish for a row that still names us")
	}
	if epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v), want (1,true)", epoch, ok)
	}
}

// TestPublishVMRunning_AFileMarkerFailureStillPublishes is a deliberate
// asymmetry between the two markers.
//
// The file marker is a real filesystem write, so a full or read-only data
// volume fails it PERSISTENTLY. Making that fatal wedges every running publish
// on the host: the row stays "stopped" while the guest runs, and the self-heal
// that would fix it routes through this same chokepoint and refuses for the same
// reason — unrecoverable, and visible only as one log line per attempt. A
// missing file marker instead costs at most one reconcile interval of
// unprovability, which convergeOwnerEpochMarker repairs for any confirmed-running
// VM regardless of the enforcement flag.
func TestPublishVMRunning_AFileMarkerFailureStillPublishes(t *testing.T) {
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	// A dataDir that cannot be written: an existing FILE where the marker tree
	// needs a directory, which is what MkdirAll fails on.
	dir := t.TempDir()
	blocked := filepath.Join(dir, "vms")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	committed := false
	if err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("a file-marker failure must not refuse the publish: %v", err)
	}
	if !committed {
		t.Error("the running write was wedged by a file-marker failure; on a full or " +
			"read-only data volume that condition persists and no self-heal can clear it")
	}
	// The domain marker, whose contract IS fatal, still landed.
	if e, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || e != 5 {
		t.Errorf("domain marker = (%d,%v), want (5,true)", e, ok)
	}
}

// TestPublishVMRunning_ADomainMarkerFailureStillWritesTheFileMarker is the
// regression a review caught in the first version of this split.
//
// Returning early on the domain write skipped the FILE marker — the durable one.
// Undefining a domain destroys its metadata with it, so a metadata-only marker is
// unreadable exactly when it is needed, and the hand-rolled write-through this
// code replaced warned on the domain write and wrote the file marker anyway.
// Short-circuiting left a VM with NEITHER marker where the old code left the one
// that survives.
func TestPublishVMRunning_ADomainMarkerFailureStillWritesTheFileMarker(t *testing.T) {
	fake := libvirtfake.New() // no domain, so the domain marker write fails
	dir := t.TempDir()
	committed := false
	if err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("one marker landing is enough to publish: %v", err)
	}
	if !committed {
		t.Error("the publish was refused although the durable marker landed")
	}
	if epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); !ok || epoch != 5 {
		t.Errorf("file marker = (%d,%v), want (5,true) — a failed domain write must not skip "+
			"the marker that survives the domain being undefined", epoch, ok)
	}
}

// TestRowForPublish_ACancelledContextAbandonsTheRetries.
//
// VMChecker.sweep publishes its VMs SEQUENTIALLY, so an unwaited backoff meant a
// shutdown mid-sweep still paid the full retry budget for every remaining VM in
// turn. The wait now selects on ctx, and the error keeps context.Canceled
// reachable so a caller can tell a cancelled shutdown from a store fault.
func TestRowForPublish_ACancelledContextAbandonsTheRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	start := time.Now()
	_, err := rowForPublish(ctx, "vm1", func(context.Context) (*corrosion.VMRecord, error) {
		calls++
		cancel() // the store faults, and the daemon is going down
		return nil, errors.New("database is locked")
	})
	if err == nil {
		t.Fatal("a lookup that never succeeded must refuse the publish")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled reachable so a shutdown is not read as a store fault", err)
	}
	if calls != 1 {
		t.Errorf("read attempted %d time(s), want 1 — the cancelled backoff kept retrying", calls)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("returned after %v, want promptly — the backoff ignored cancellation", elapsed)
	}
}

// TestRowForPublish_DoesNotSleepAfterTheFinalAttempt.
//
// The backoff belongs BEFORE a retry, not after a failure. Sleeping after the
// last attempt bought nothing and cost every caller an extra 400ms: a fully
// failed lookup took 1s where 600ms is the whole wait it actually needs.
func TestRowForPublish_DoesNotSleepAfterTheFinalAttempt(t *testing.T) {
	calls := 0
	start := time.Now()
	_, err := rowForPublish(context.Background(), "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			calls++
			return nil, errors.New("database is locked")
		})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a lookup that never succeeded must refuse the publish")
	}
	if calls != 4 {
		t.Errorf("read attempted %d time(s), want 4", calls)
	}
	// 100+200+300 = 600ms of real waiting; the removed trailing sleep was 400ms.
	if elapsed >= 900*time.Millisecond {
		t.Errorf("took %v, want under 900ms — a sleep still follows the final failed attempt", elapsed)
	}
	if elapsed < 500*time.Millisecond {
		t.Errorf("took %v, want at least ~600ms — the backoff between retries is gone", elapsed)
	}
}

// TestPublishVMRunning_RefusesWhenNoMarkerCouldEvenBeAttempted.
//
// Both markers failing was already refused. NEITHER being possible — a nil
// libvirt backend together with an empty dataDir — returned (nil, nil) and
// committed a running row at a positive generation with no marker and no
// warning. That is the same "proves nothing" state, reached by a configuration
// instead of a fault, and therefore silent on every single publish.
func TestPublishVMRunning_RefusesWhenNoMarkerCouldEvenBeAttempted(t *testing.T) {
	committed := false
	err := PublishVMRunning(context.Background(), nil, "", "vm1", "running", 3,
		func(context.Context) error { committed = true; return nil })
	if err == nil {
		t.Fatal("a publish that can write no marker at all must be refused")
	}
	if committed {
		t.Error("the commit ran — a running row was published that can prove nothing")
	}
}

// TestPublishVMRunning_ADomainMarkerFailureIsNotReportedAsAFileFailure.
//
// writeBothMarkers used to return `(partial error, fatal error)`, two same-typed
// returns told apart only by position. The minted caller bound the first to a
// variable named fileErr and logged it as "file_error" — so a libvirt metadata
// failure sent an operator to check a full data volume. The named result keeps
// the two apart by field.
func TestPublishVMRunning_ADomainMarkerFailureIsNotReportedAsAFileFailure(t *testing.T) {
	fake := libvirtfake.New() // no domain, so SetDomainOwnerEpoch fails

	res := writeBothMarkers(fake, t.TempDir(), "vm1", 3)
	if res.domainErr == nil {
		t.Error("domainErr is nil — the libvirt failure was not recorded as a domain failure")
	}
	if res.fileErr != nil {
		t.Errorf("fileErr = %v, want nil — the file marker succeeded", res.fileErr)
	}
	if !res.landed {
		t.Error("landed is false — the file marker did land, so the publish may proceed")
	}
	if res.unproven() {
		t.Error("unproven() is true — one marker landed, which is enough to publish")
	}
}

// TestWriteBothMarkers_APreEpochRowIsSkippedNotUnproven: epoch 0 has no
// generation to name, so writing nothing is correct — and must not be confused
// with failing to write anything, which is refused.
func TestWriteBothMarkers_APreEpochRowIsSkippedNotUnproven(t *testing.T) {
	res := writeBothMarkers(nil, "", "vm1", 0)
	if !res.skipped {
		t.Error("skipped is false for a pre-epoch row")
	}
	if res.unproven() {
		t.Error("unproven() is true — a pre-epoch row publishes unmarked by design")
	}
	if res.failures() != nil {
		t.Errorf("failures() = %v, want nil", res.failures())
	}
}

// TestPublishVMRunningMinted_RetriesTheReadBack.
//
// This is the one read that decides whether a freshly minted generation is ever
// marked, and its failure is deliberately silent — the commit has landed, so
// returning an error would abort durable writes the caller still owes. Unretried,
// a single SQLITE_BUSY therefore dropped the markers for a brand-new generation
// with no error reaching anyone. RowForPublish existed 40 lines away, with a doc
// comment giving exactly this reason, and this read was the only one not using it.
func TestPublishVMRunningMinted_RetriesTheReadBack(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	calls := 0
	err := publishVMRunningMinted(context.Background(), fake, dir, "node-a", "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("database is locked")
			}
			return &corrosion.VMRecord{Name: "vm1", HostName: "node-a", OwnerEpoch: 4}, nil
		},
		func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("publishVMRunningMinted: %v", err)
	}
	if calls != 2 {
		t.Errorf("read attempted %d time(s), want 2 — the read-back was not retried", calls)
	}
	epoch, ok, rerr := ReadVMOwnerEpochMarker(dir, "vm1")
	if rerr != nil || !ok || epoch != 4 {
		t.Errorf("file marker = (%d, %v, %v), want 4 — a transient read dropped the markers for a "+
			"generation that had just been minted", epoch, ok, rerr)
	}
}

// TestPublishVMRunningMinted_ADeletedRowIsNotAReadFailure: collapsing the two
// logged a concurrently deleted row as a "read-back failure" with error=<nil>,
// naming no cause at all.
func TestPublishVMRunningMinted_ADeletedRowIsNotAReadFailure(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	err := publishVMRunningMinted(context.Background(), fake, dir, "node-a", "vm1",
		func(context.Context) (*corrosion.VMRecord, error) { return nil, nil },
		func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("a deleted row must not fail the transition: %v", err)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a marker was written for a row that no longer exists")
	}
}
