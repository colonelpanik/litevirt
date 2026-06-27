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
