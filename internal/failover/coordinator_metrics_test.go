package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeMetrics is a no-dependency Metrics sink that counts calls by label tuple,
// so failover tests can assert observability without importing Prometheus.
type fakeMetrics struct {
	attempts map[string]int
	vm       map[string]int
	ct       map[string]int
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{attempts: map[string]int{}, vm: map[string]int{}, ct: map[string]int{}}
}

func foKey(a, b, c string) string { return a + "|" + b + "|" + c }

func (f *fakeMetrics) Attempt(p, r, e string)         { f.attempts[foKey(p, r, e)]++ }
func (f *fakeMetrics) VMAction(a, r, e string)        { f.vm[foKey(a, r, e)]++ }
func (f *fakeMetrics) ContainerAction(a, r, e string) { f.ct[foKey(a, r, e)]++ }

// TestFailoverMetrics_SkipUpgrading: a recently-'upgrading' host is skipped, and
// that skip is observable.
func TestFailoverMetrics_SkipUpgrading(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "upg", Address: "10.0.0.51", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "upgrading", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "upg", "h1", "h2", "h3")

	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseSkip, ResultSkipped, ErrUpgrading)]; got != 1 {
		t.Errorf("skip-upgrading counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
}

// A self-fenced coordinator refuses to drive failover: run() returns before the lease/
// fence logic, so a down host is NOT fenced and the skip is observable. A doomed node
// must not arbitrate cluster ownership during its fence-timeout window.
func TestFailoverMetrics_SelfFencedSkips(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")

	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.SelfFenced = func() bool { return true }
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseSkip, ResultSkipped, ErrSelfFenced)]; got != 1 {
		t.Errorf("self-fenced skip counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
	// No fence attempt should have run at all.
	if got := fm.attempts[foKey(PhaseFence, ResultSuccess, errClassNone)]; got != 0 {
		t.Errorf("a self-fenced coordinator must not fence; fence-success=%d", got)
	}
}

// TestFailoverMetrics_FenceSuccess: a successful fence is counted (no VMs → no
// reschedule, but the fence outcome is observable).
func TestFailoverMetrics_FenceSuccess(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")

	c := newTestCoordinator("coordinator", db) // stubFencer(true)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseFence, ResultSuccess, errClassNone)]; got != 1 {
		t.Errorf("fence-success counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
}

// TestFailoverMetrics_ManualUnconfirmedRefused: a manual fence with no operator
// confirmation reports a partial fence AND a split-brain refusal — the safety
// rail is observable.
func TestFailoverMetrics_ManualUnconfirmedRefused(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")

	c := NewCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseFence, ResultPartial, ErrFenceFailed)]; got != 1 {
		t.Errorf("fence-partial counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
	if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 1 {
		t.Errorf("manual-unconfirmed-refused counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
}

// TestFailoverMetrics_NoCandidates: a successful fence with no healthy host to
// reschedule onto is refused with no_candidates (NOT misclassified as a DB error).
func TestFailoverMetrics_NoCandidates(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	// Single observer "coordinator" (not a host row), so "bad" is the only host →
	// no healthy candidate after fencing it.
	for i := 0; i < offlineThreshold; i++ {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			"coordinator", "bad", offlineThreshold); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCoordinator("coordinator", db) // stubFencer(true)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseFence, ResultSuccess, errClassNone)]; got != 1 {
		t.Errorf("fence-success = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
	if got := fm.attempts[foKey(PhaseFence, ResultRefused, ErrNoCandidates)]; got != 1 {
		t.Errorf("no-candidates = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
}

// TestFailoverMetrics_FirmwareSkip: a Secure-Boot/vTPM VM can't be auto-failed-over
// (firmware state died with the host) and that skip is observable.
func TestFailoverMetrics_FirmwareSkip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3") // h1-3 are healthy candidates
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "fwvm", HostName: "bad", State: "running", CPUActual: 1, MemActual: 512,
		Spec: `{"secure_boot":true}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}

	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.vm[foKey(ActionReschedule, ResultSkipped, ErrFirmwareState)]; got != 1 {
		t.Errorf("firmware-skip = %d, want 1 (vm=%v)", got, fm.vm)
	}
}

// TestFailoverMetrics_Relocate: a relocatable container's relocation is counted.
func TestFailoverMetrics_Relocate(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "dead", Name: "web", State: "running", Image: "alpine:3.19",
		CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	idx := 0
	c.relocateContainers(ctx, &corrosion.HostRecord{Name: "dead"},
		[]corrosion.HostRecord{{Name: "live", State: "active"}}, &idx)

	if got := fm.ct[foKey(ActionRelocate, ResultSuccess, errClassNone)]; got != 1 {
		t.Errorf("relocate-success = %d, want 1 (ct=%v)", got, fm.ct)
	}
}

// TestFailoverMetrics_FenceLogWriteFailureProceeds pins the non-blocking
// invariant: if the fence_log write fails (the fence physically happened), the
// failure is COUNTED but failover STILL proceeds to mark the host fenced — a lost
// audit row must never strand VMs.
func TestFailoverMetrics_FenceLogWriteFailureProceeds(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")
	// Make InsertFenceLog fail (table gone) without touching control flow.
	if _, err := db.DB().ExecContext(ctx, `DROP TABLE fencing_log`); err != nil {
		t.Fatalf("drop fencing_log: %v", err)
	}

	c := newTestCoordinator("coordinator", db) // stubFencer(true)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseFence, ResultError, ErrFenceLogWrite)]; got != 1 {
		t.Errorf("fence-log-write-failed = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
	// Proceeded despite the failed audit write: the host is marked fenced.
	if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "fenced" {
		t.Errorf("failover did not proceed past fence-log failure: host=%+v (want state=fenced)", h)
	}
}

// TestFailoverMetrics_RecoveryQuorumQueryErrorObservable: a DB error on the
// recovery quorum query must not be silently folded into "not enough healthy
// observers" — it's counted as a recovery error (fail-open behavior unchanged).
func TestFailoverMetrics_RecoveryQuorumQueryErrorObservable(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// An 'offline' host with no fencing_log row reaches the quorum query.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "offline",
	}); err != nil {
		t.Fatal(err)
	}
	// Force the quorum query to error (the recovery health source is gone) while
	// ListHosts / recentlyFenced still work.
	if _, err := db.DB().ExecContext(ctx, `DROP TABLE host_health`); err != nil {
		t.Fatalf("drop host_health: %v", err)
	}

	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.recoverHosts(ctx, 1)

	if got := fm.attempts[foKey(PhaseRecovery, ResultError, ErrDBError)]; got != 1 {
		t.Errorf("recovery-query-error counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
}

// TestFailoverMetrics_FenceLogReadErrorObservable: a fencing_log read error in
// the recent-fence / manual-confirmation check fails open (returns false) but is
// now counted, so a store fault on the safety path is visible.
func TestFailoverMetrics_FenceLogReadErrorObservable(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.DB().ExecContext(ctx, `DROP TABLE fencing_log`); err != nil {
		t.Fatalf("drop fencing_log: %v", err)
	}

	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm

	if c.fenceWithinWindow(ctx, "anyhost", false) {
		t.Error("fenceWithinWindow should fail open (false) on a read error")
	}
	if got := fm.attempts[foKey(PhaseHealth, ResultError, ErrDBError)]; got != 1 {
		t.Errorf("fence-log-read-error counter = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
}
