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
			db := newTestDB(t)
			c := newTestCoordinator("coord", db)
			got := c.vmNeedsFailover(context.Background(), corrosion.VMRecord{Name: "vm1", Spec: tc.spec})
			if got != tc.want {
				t.Errorf("vmNeedsFailover = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestVMNeedsFailover_AutoPromoteOverridesPolicyNone: a VM whose owner opted into
// replica auto-promotion is recoverable even with on_host_failure=none.
//
// The reschedule loop attempts promotion BEFORE it consults on_host_failure, so
// judging this VM on policy alone made the sweep's predicate NARROWER than what
// the loop acts on — and narrower means stranded, because the sweep is the only
// thing that comes back. It stranded exactly the VMs whose owners had opted into
// the stronger recovery mechanism.
func TestVMNeedsFailover_AutoPromoteOverridesPolicyNone(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)

	vm := corrosion.VMRecord{Name: "vm1", Spec: `{"on_host_failure":"none"}`}

	// No promoter wired: nothing can promote, so there is nothing to wait for.
	if c.vmNeedsFailover(ctx, vm) {
		t.Error("policy=none with no Promoter wired is not recoverable work")
	}

	c.Promoter = stubPromoter{}
	if c.vmNeedsFailover(ctx, vm) {
		t.Error("policy=none with a Promoter but no replication schedule is not recoverable work")
	}

	// Enrol it in replication with auto-promote.
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "live", KeepReplicas: 3,
		AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}
	if !c.vmNeedsFailover(ctx, vm) {
		t.Error("a VM enrolled in replication with auto_promote is recoverable by PROMOTION " +
			"regardless of on_host_failure, and the reschedule loop reaches promotion first. " +
			"Reporting no work here retires its host from the sweep for good")
	}
}

// TestVMNeedsFailover_UnreadableSchedulesAssumeWork pins the direction this
// predicate fails in.
//
// autoPromoteEnabled reports "not enrolled" when it cannot read the schedules,
// which is right for the reschedule loop: it falls through and reschedules the VM
// anyway, so the VM is still recovered. It is wrong here. The sweep is the only
// thing that ever comes back to a fenced host, so answering "no work" on a
// transient read error retires that host permanently — turning a DB blip into the
// exact stranding this sweep exists to end.
//
// The rule is that this predicate must never be NARROWER than what
// recoverWorkloads will act on. Too broad costs one no-op pass; too narrow strands
// the workload forever.
func TestVMNeedsFailover_UnreadableSchedulesAssumeWork(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c := newTestCoordinator("coord", db)
	c.Promoter = stubPromoter{}

	// policy=none, so the answer hinges entirely on the schedule read.
	vm := corrosion.VMRecord{Name: "vm1", Spec: `{"on_host_failure":"none"}`}
	if c.vmNeedsFailover(ctx, vm) {
		t.Fatal("premise check: with readable schedules and no enrolment there is no work")
	}

	if err := db.Execute(ctx, `DROP TABLE backup_schedules`); err != nil {
		t.Fatalf("drop backup_schedules: %v", err)
	}
	if _, err := c.autoPromoteEnabled(ctx, "vm1"); err == nil {
		t.Fatal("schedule read still succeeds; this test is not injecting the error it claims to")
	}

	if !c.vmNeedsFailover(ctx, vm) {
		t.Error("an unreadable schedule was read as 'no work'. The sweep is the only thing " +
			"that returns to a fenced host, so this retires it permanently and strands any " +
			"auto-promote VM on it — a transient DB error turned into the stranding this " +
			"sweep exists to end")
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
	fm := newFakeMetrics()
	c.Metrics = fm
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

	// The recovery must be attributable. phase="recovery" is a HOST returning to
	// active and fires routinely; this signal is the one an operator alerts on,
	// because a nonzero value means workloads were abandoned on a powered-off
	// machine until the sweep came back for them. Emitting it under the routine
	// phase would bury it.
	if n := fm.attempts[foKey(PhaseStranded, ResultRecovered, "")]; n != 1 {
		t.Errorf("stranded-recovery attempts = %d, want 1. Without its own phase label this "+
			"event is indistinguishable from a host coming back healthy, which happens all "+
			"the time — so the alert that should catch a stranding would be unusable", n)
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

	if n := fm.attempts[foKey(PhaseStranded, ResultRecovered, "")]; n != 0 {
		t.Errorf("the sweep ran recovery %d time(s) for a host whose only workloads are a "+
			"policy=none VM and a Secure Boot VM. Both stay by design and the host stays "+
			"offline, so that condition never goes false and the sweep would re-run every "+
			"cycle for the life of the cluster", n)
	}
}

// TestRecoverStrandedWorkloads_OfflineIsNotAuthorityToEvacuate covers both ways
// the earlier fencing_log-based admission was wrong.
//
// The sweep keys on hosts.state == "fenced", which the fence path writes only when
// the fence actually succeeded on a non-manual strategy. State "offline" covers a
// fence that FAILED, a manual fence, and an operator's own shutdown — none of
// which authorize this coordinator to move anything.
//
// The stale-evidence case is the dangerous one and the reason the rule changed. A
// host fenced successfully in an EARLIER outage, returned to service by
// recoverHosts, and then hit by a second outage whose fence failed still carries
// that old success in fencing_log. An admission reading the newest logged attempt
// would evacuate a host nothing had powered off — one still running the VMs it was
// about to be evacuated of. hosts.state cannot lie that way: a failed fence writes
// "offline".
func TestRecoverStrandedWorkloads_OfflineIsNotAuthorityToEvacuate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		withStale bool
	}{
		{name: "never fenced at all", withStale: false},
		{name: "stale success from an earlier outage", withStale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			if tc.withStale {
				// A successful fence on record, from an outage that is over.
				recordFence(t, ctx, db, "quiet")
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
			if vm.HostName != "quiet" {
				t.Errorf("the sweep moved vm1 to %q off a host in state offline. Nothing "+
					"proved that host is powered off — its fence may have failed, or an "+
					"operator may simply have shut it down — so its VMs may now be "+
					"running in two places", vm.HostName)
			}
		})
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
// that went straight to recoverWorkloads would have evacuated a host on the
// strength of its state alone — the exact split-brain the safe-fence default
// exists to prevent, reintroduced by the retry meant to make recovery safer.
//
// The gate exercised here is the safe-fence one, because it is the gate that
// survives a state=="fenced" admission. A best-effort fence reports success even
// when the power-off never landed (lenient SSH), so under the safe-fence policy it
// needs an operator fence-confirm before anything moves.
func TestRecoverStrandedWorkloads_HonoursTheSplitBrainAuthorization(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "dead", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "fenced", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost dead: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "live", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost live: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	recordFence(t, ctx, db, "dead")

	c := newTestCoordinator("coord", db)
	// Safe-fence policy enforced, and no operator has confirmed the power-off.
	c.SafeFenceEnforce = true
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SafeFenceDefaultV1: true},
	}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}

	c.recoverStrandedWorkloads(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "dead" {
		t.Errorf("the sweep moved vm1 to %q off a host whose best-effort fence was never "+
			"confirmed under the safe-fence policy. A lenient SSH fence reports success "+
			"without proving the power-off, so the VM may now be running in two places — "+
			"the split-brain the policy exists to prevent, reintroduced by the retry path",
			vm.HostName)
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
//	6 | recordedFenceOutcome reads "partial" as success | (rule replaced — see below)
//	7 | sweep admits state=="offline" as well as        | KILLED OfflineIsNotAuthority-
//	  |   "fenced"                                      |   ToEvacuate, both cases
//	8 | vmNeedsFailover ignores auto-promote enrolment  | KILLED AutoPromoteOverrides-
//	  |                                                 |   PolicyNone
//	9 | an unreadable schedule reports "no work"        | SURVIVED at first, then KILLED
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

// stubPromoter satisfies ReplicaPromoter without doing anything. The predicate
// only asks whether a promoter EXISTS, so nothing here needs to work.
type stubPromoter struct{}

func (stubPromoter) AutoPromoteReplica(ctx context.Context, vmName, fenceEpoch string) error {
	return nil
}

//
// Mutations 7-9 come from a second crossexam, of the commit these tests first
// shipped in. It upheld three findings, and the first two were the same mistake
// seen from both sides: the admission rule read fencing_log, which this package
// treats as a best-effort audit trail whose write is explicitly allowed to fail.
// Requiring a row stranded any host whose row was lost; trusting the newest row
// was not scoped to an outage, so a host fenced months ago, recovered, and then
// hit by a second outage whose fence FAILED still presented that old success —
// and the sweep would have evacuated a live host. Both collapse into keying on
// hosts.state == "fenced", which the fence path writes only on real success and
// which, being the current state, is scoped to the current outage for free.
// Mutation 6 tested the rule that replaced.
//
// The third finding was a predicate narrower than the loop it had to agree with.
// recoverWorkloads tries replica auto-promotion BEFORE consulting
// on_host_failure, so a VM with auto_promote and the default policy of "none" is
// recoverable by promotion; judging it on policy alone stranded exactly the VMs
// whose owners had opted into the stronger mechanism. The invariant is now
// written down: this predicate may be broader than the loop but never narrower,
// because broad costs one no-op pass and narrow strands forever. Mutation 9 is
// that invariant on the error path, and it needed its own test — the review found
// the gap, but nothing was asserting the direction.
//
// Mutation 10: point the sweep's success at PhaseRecovery instead of
// PhaseStranded. SURVIVED at first and then KILLED, for the same reason
// mutation 3 did — QuiescesOnWorkloadsThatStay asserts the count is ZERO, and
// zero stays zero when the label moves. Only a POSITIVE assertion on the
// success path can see it, so RetriesAfterARefusal now checks the label it
// actually emits. The distinction is not cosmetic: PhaseRecovery+recovered is a
// host returning to active and fires routinely, so an operator alerting on it
// would drown the one event that means workloads were abandoned on a
// powered-off machine.
