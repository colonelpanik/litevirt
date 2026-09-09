package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestVMNeedsFailover pins the rule for "would this coordinator ever move this VM
// off a dead host".
//
// It exists as a named predicate rather than two inline conditions because the
// stranded-workload sweep has to ask the same question the reschedule loop asks.
// When the two disagree the sweep either spins forever on a VM nothing will ever
// move, or gives up on one that was recoverable. Both were reachable while the
// rule lived only inside the loop.
func TestVMNeedsFailover(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want bool
	}{
		{name: "restart-any", spec: `{"on_host_failure":"restart-any"}`, want: true},
		{name: "restart-same", spec: `{"on_host_failure":"restart-same"}`, want: true},
		{name: "policy none is a permanent opt-out",
			spec: `{"on_host_failure":"none"}`, want: false},
		{name: "no policy at all is the same opt-out",
			spec: `{}`, want: false},
		{name: "empty spec", spec: ``, want: false},
		// Secure Boot / vTPM state was host-local and died with the host. No
		// reschedule or disk-only promotion can recover it, so it is not work the
		// sweep should keep waiting on — recovery is an operator restore.
		{name: "secure boot cannot be failed over",
			spec: `{"on_host_failure":"restart-any","secure_boot":true}`, want: false},
		{name: "vTPM cannot be failed over",
			spec: `{"on_host_failure":"restart-any","tpm":true}`, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vmNeedsFailover(corrosion.VMRecord{Name: "vm1", Spec: tc.spec})
			if got != tc.want {
				t.Errorf("vmNeedsFailover = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestContainerNeedsFailover is the container half of the same rule.
func TestContainerNeedsFailover(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		detail string
		want   bool
	}{
		{name: "image-recreate", policy: "image-recreate", want: true},
		{name: "policy none", policy: "none", want: false},
		{name: "no policy", policy: "", want: false},
		// Already triaged as unrecoverable on an earlier pass and deliberately left
		// visible for an operator. Re-processing it would loop.
		{name: "already triaged to skipped",
			policy: "image-recreate", detail: corrosion.ContainerRelocateSkippedDetail, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := containerNeedsFailover(corrosion.ContainerRecord{
				Name: "ct1", OnHostFailure: tc.policy, StateDetail: tc.detail,
			})
			if got != tc.want {
				t.Errorf("containerNeedsFailover = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRecoverStrandedWorkloads_RetriesAfterARefusal is the whole point of the
// task: a refusal after the fence must not abandon the workload.
//
// The defect this closes cannot be seen from a unit test on any single check. It
// lives in the interaction between an early return, c.fenced, and the PERSISTED
// host state — the host is powered off and marked offline, and run() then skips
// it on every later cycle and on every other coordinator too, so nothing ever
// comes back for the VM.
func TestRecoverStrandedWorkloads_RetriesAfterARefusal(t *testing.T) {
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
	fenceQuorum(t, ctx, db, []string{"coord", "live"}, "dead")

	c := newTestCoordinator("coord", db)
	// Enforce lease terms, then supersede this coordinator's term so the stamp
	// site refuses. Any of the post-fence refusals would do; this is the one this
	// work added, and it is the cheapest to induce deterministically.
	c.LeaseTermEnforce = true
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{
			capabilities.SplitBrainGateV1: true,
			capabilities.LeaseTermV1:      true,
		},
	}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	seedLeaseTerm(t, db, c.LeaseTerm()+499, "node-b")

	dead, err := corrosion.GetHost(ctx, db, "dead")
	if err != nil || dead == nil {
		t.Fatalf("GetHost dead: %v", err)
	}
	c.failover(ctx, dead)

	// Precondition: the fence happened and the VM was abandoned on the dead host.
	after, err := corrosion.GetHost(ctx, db, "dead")
	if err != nil || after == nil {
		t.Fatalf("GetHost dead after fence: %v", err)
	}
	if after.State != "offline" && after.State != "fenced" {
		t.Fatalf("host state after fence = %q, want offline or fenced — this test's premise is "+
			"that the fence completed before the refusal", after.State)
	}
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "dead" {
		t.Fatalf("vm1 is on %q; the refusal did not strand it, so this test proves nothing", vm.HostName)
	}

	// The blocker clears: this coordinator now holds the newest term. Set both
	// sides directly rather than going through acquireLease — the lease
	// classification has its own tests, and this test's subject is what the sweep
	// does once the refusal condition is gone.
	seedLeaseTerm(t, db, 1000, "coord")
	c.leaseTerm.Store(1000)
	if !c.leaseTermStampAllowed(ctx) {
		t.Fatal("the precheck still refuses; this test cannot show the sweep recovering anything")
	}

	// A later cycle. run() would skip the offline host entirely, so the sweep is
	// the only thing that can still recover this VM.
	c.recoverStrandedWorkloads(ctx)

	vm, err = corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM after sweep: %v", err)
	}
	if vm.HostName == "dead" {
		t.Errorf("vm1 is still assigned to the fenced host after the blocker cleared. The host is "+
			"powered off and run() skips it forever, so nothing else will ever come back for this "+
			"VM: state=%q detail=%q", vm.State, vm.StateDetail)
	}
}

// TestRecoverStrandedWorkloads_QuiescesOnWorkloadsThatStay: the sweep must go
// quiet once only un-failoverable workloads remain.
//
// A policy=none VM stays on its host by design and a fenced host stays offline,
// so "this host still has VMs" is true forever. A sweep keyed on that alone would
// re-run recovery every cycle for the life of the cluster, burning queries and
// emitting refusal metrics for work nobody asked for.
func TestRecoverStrandedWorkloads_QuiescesOnWorkloadsThatStay(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "dead", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "offline", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// Two workloads that legitimately stay: an opted-out VM and a Secure Boot VM.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "optout", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"none"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM optout: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "sb", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any","secure_boot":true}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM sb: %v", err)
	}
	recordFence(t, ctx, db, "dead")

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}

	// Drive the SWEEP, not the predicate. Asserting on the helper alone would pass
	// just as well with the sweep's call to it deleted, which is the mutation this
	// has to catch.
	for i := 0; i < 3; i++ {
		c.recoverStrandedWorkloads(ctx)
	}

	if n := fm.attempts[foKey(PhaseRecovery, ResultRecovered, "")]; n != 0 {
		t.Errorf("the sweep ran recovery %d time(s) for a host whose only workloads are a "+
			"policy=none VM and a Secure Boot VM. Both stay by design and the host stays "+
			"offline, so that condition never goes false and the sweep would re-run every "+
			"cycle for the life of the cluster", n)
	}
}

// TestRecoverStrandedWorkloads_IgnoresAHostItNeverFenced: being offline is not
// authority to evacuate.
//
// The sweep's whole premise is "we powered this host off and did not finish
// moving its workloads". A host that is merely offline — shut down by an
// operator, or never yet fenced — is not that, and moving its VMs would be this
// coordinator inventing an eviction nobody ordered.
func TestRecoverStrandedWorkloads_IgnoresAHostItNeverFenced(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "quiet", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "offline", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost quiet: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost live: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "quiet", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Deliberately NO fencing_log row for "quiet".

	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{supports: map[string]bool{"live": true}}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}

	c.recoverStrandedWorkloads(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "quiet" {
		t.Errorf("the sweep moved vm1 to %q off a host this cluster never fenced. Nothing "+
			"powered that host off and nothing asked for its workloads to move", vm.HostName)
	}
}

// recordFence writes the successful fence the sweep requires as evidence that
// this host was fenced rather than merely offline. Result "fenced" is
// fencing_log's spelling of success; "partial" is its spelling of failure.
func recordFence(t *testing.T, ctx context.Context, db *corrosion.Client, host string) {
	t.Helper()
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "f-" + host, HostName: host, Method: "ipmi", Result: "fenced", Detail: "test",
	}); err != nil {
		t.Fatalf("InsertFenceLog %s: %v", host, err)
	}
}

// TestRecoverStrandedWorkloads_HonoursTheSplitBrainAuthorization is the safety
// test for the retry path, and it pins a bypass this work nearly shipped.
//
// The safe-fence and split-brain gates used to sit inline in failover ABOVE the
// recovery steps, so they were not part of the function the sweep calls. A sweep
// that went straight to recoverWorkloads would have evacuated a host whose fence
// never succeeded and whose operator confirmation never arrived — the exact
// split-brain the safe-fence default exists to prevent, reintroduced by the retry
// that was supposed to make recovery safer.
func TestRecoverStrandedWorkloads_HonoursTheSplitBrainAuthorization(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// strategy=manual with no operator confirmation: the split-brain guard must
	// refuse, on the first pass and on every retry.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "dead", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "offline", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost dead: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost live: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The fence was ATTEMPTED and did not succeed. "partial" is fencing_log's
	// spelling of that, and it is what the guard keys on.
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "f1", HostName: "dead", Method: "manual", Result: "partial", Detail: "unconfirmed",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}

	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{supports: map[string]bool{"live": true}}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}

	c.recoverStrandedWorkloads(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "dead" {
		t.Errorf("the sweep moved vm1 to %q off a host whose manual fence was never confirmed. "+
			"Nothing proved that host is powered off, so the VM may now be running in two "+
			"places — the split-brain the safe-fence policy exists to prevent, reintroduced by "+
			"the retry path", vm.HostName)
	}
}

// MUTATION RESULTS (2026-09-09). Applied to coordinator.go, run, reverted.
//
//	# | mutation                                        | outcome
//	--+-------------------------------------------------+--------------------------------
//	1 | sweep calls recoverWorkloads without clearing   | KILLED HonoursTheSplitBrain-
//	  |   recoveryAuthorized                            |   Authorization
//	2 | sweep ignores whether a fence was ever recorded | SURVIVED at first, then KILLED
//	3 | sweep drops the hostHasRecoverableWorkloads     | SURVIVED at first, then KILLED
//	  |   check                                         |
//	4 | vmNeedsFailover ignores firmware state          | KILLED VMNeedsFailover × 2
//	5 | containerNeedsFailover ignores the triage       | KILLED ContainerNeedsFailover
//	  |   marker                                        |
//	6 | recordedFenceOutcome reads "partial" as success | KILLED HonoursTheSplitBrain-
//	  |                                                 |   Authorization
//
// Mutations 2 and 3 both survived the first run, and both were the tests' fault
// rather than the code's.
//
// 3 is the sharper lesson. QuiescesOnWorkloadsThatStay originally asserted on
// hostHasRecoverableWorkloads DIRECTLY, so deleting the sweep's call to it
// changed nothing the test could see: it was testing the predicate, not the
// behaviour that depends on it. State assertions cannot catch it either — running
// recovery on a host whose every workload legitimately stays produces no state
// change at all, which is the whole point. It now drives the sweep three times
// and asserts on the PhaseRecovery metric, because "did no work" is only
// observable as an absence of work.
//
// 2 had no test at all: nothing asserted that a host which is merely offline —
// shut down by an operator, never fenced — is left alone. Being offline is not
// authority to evacuate, and the sweep would have invented an eviction nobody
// ordered.
