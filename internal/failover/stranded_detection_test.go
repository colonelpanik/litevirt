package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestVMNeedsFailover pins the rule for "would this coordinator ever move this VM
// off a dead host".
//
// autoPromote is a parameter rather than a lookup because the reschedule loop
// reaches AutoPromoteReplica BEFORE it consults on_host_failure: a VM enrolled in
// replication with the default policy of "none" is recoverable by promotion, and
// judging it on policy alone would under-count exactly the workloads whose owners
// opted into the stronger mechanism.
func TestVMNeedsFailover(t *testing.T) {
	cases := []struct {
		name        string
		spec        string
		autoPromote bool
		want        bool
	}{
		{name: "restart-any", spec: `{"on_host_failure":"restart-any"}`, want: true},
		{name: "restart-same", spec: `{"on_host_failure":"restart-same"}`, want: true},
		{name: "policy none is a permanent opt-out",
			spec: `{"on_host_failure":"none"}`, want: false},
		{name: "no policy at all is the same opt-out", spec: `{}`, want: false},
		{name: "empty spec", spec: ``, want: false},
		{name: "policy none but enrolled in auto-promote",
			spec: `{"on_host_failure":"none"}`, autoPromote: true, want: true},
		// Secure Boot / vTPM state was host-local and died with the host. No
		// reschedule or disk-only promotion recovers it, and enrolment does not
		// change that.
		{name: "secure boot cannot be failed over",
			spec: `{"on_host_failure":"restart-any","secure_boot":true}`, want: false},
		{name: "vTPM cannot be failed over",
			spec: `{"on_host_failure":"restart-any","tpm":true}`, want: false},
		{name: "secure boot outranks auto-promote enrolment",
			spec: `{"secure_boot":true}`, autoPromote: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vmNeedsFailover(corrosion.VMRecord{Name: "vm1", Spec: tc.spec}, tc.autoPromote)
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
		state  string
		detail string
		want   bool
	}{
		{name: "image-recreate", policy: "image-recreate", want: true},
		{name: "policy none", policy: "none", want: false},
		{name: "no policy", policy: "", want: false},
		{name: "already triaged to skipped",
			policy: "image-recreate", detail: corrosion.ContainerRelocateSkippedDetail, want: false},
		// A relocate-restore marker has an active owner: resolvePendingRelocations
		// retries it every cycle. The third case below is the one that would
		// invert the truth — the restore LANDED and only the source tombstone
		// failed, so the container is running on the target while this row waits
		// to be reaped.
		{name: "restore in flight is not stranded", policy: "image-recreate",
			state: "relocating", detail: corrosion.RelocateRestoreDetail("target", "tok"), want: false},
		{name: "restore marker with a different policy is still not stranded",
			policy: "restart-any", state: "relocating",
			detail: corrosion.RelocateRestoreDetail("target", "tok"), want: false},
		// The marker only counts as one while state says 'relocating' — the same
		// condition RelocateRestoreMarker itself applies. A stale detail string on
		// a stopped row is a strand.
		{name: "restore detail without relocating state is a strand",
			policy: "image-recreate", state: "stopped",
			detail: corrosion.RelocateRestoreDetail("target", "tok"), want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := containerNeedsFailover(corrosion.ContainerRecord{
				Name: "ct1", OnHostFailure: tc.policy, State: tc.state, StateDetail: tc.detail,
			})
			if got != tc.want {
				t.Errorf("containerNeedsFailover = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRun_ReportsStrandedWorkloads drives a whole run() cycle, because the
// production wiring is the part most worth pinning: a detection signal nothing
// calls is worse than none, since it reads as "no problem" forever.
//
// The fixture seeds the END STATE rather than producing it: the host is already
// 'fenced' with a VM still pointing at it, which is what the tree looks like
// after a post-fence refusal — and equally after `lv host fence-confirm`. run()
// skips the host as terminal either way, so nothing revisits it. What is pinned
// here is the reporting, not the refusal that can lead to it; the refusal paths
// have their own tests.
func TestRun_ReportsStrandedWorkloads(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// 'offline' counts as well as 'fenced', and it is the state the likeliest
	// real case lands in: failover writes it and returns above recoverWorkloads
	// when a fence is unconfirmed or failed.
	for _, h := range []struct{ name, state string }{
		{"dead", "fenced"}, {"unconfirmed", "offline"}, {"live", "active"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	// Stranded: would be moved, wasn't.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "stranded", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM stranded: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "stranded-offline", HostName: "unconfirmed", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM stranded-offline: %v", err)
	}
	// Staying by design: must NOT be counted, or the signal cries wolf on every
	// fenced host that ever held an opted-out VM.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "optout", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"none"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM optout: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "secureboot", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any","secure_boot":true}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM secureboot: %v", err)
	}
	// A VM on a HEALTHY host is not stranded however its policy reads.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "healthy", HostName: "live", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM healthy: %v", err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}

	c.run(ctx)

	if fm.stranded != 2 {
		t.Errorf("stranded gauge = %d, want 2 (`stranded` on the fenced host and "+
			"`stranded-offline` on the offline one). 0 means the condition is invisible and "+
			"reads as healthy forever; 1 means one of the two down states is not counted — "+
			"and 'offline' is the one the likeliest real case uses; above 2 means the "+
			"opted-out and Secure Boot VMs are being reported as problems, and an operator "+
			"who is paged for them will stop trusting the signal", fm.stranded)
	}
}

// TestRun_StrandedGaugeClearsWhenNothingIsStranded: the gauge must return to zero,
// or it is a one-way latch an operator cannot use to confirm a fix.
func TestRun_StrandedGaugeClearsWhenNothingIsStranded(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, state string }{
		{"dead", "fenced"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm

	c.run(ctx)
	if fm.stranded != 1 {
		t.Fatalf("premise: gauge = %d, want 1 before the operator acts", fm.stranded)
	}

	// The operator recovers it — here, by re-homing the row as a reschedule would.
	if err := corrosion.UpdateVMHost(ctx, db, "vm1", "coord", "pending"); err != nil {
		t.Fatalf("UpdateVMHost: %v", err)
	}

	c.run(ctx)
	if fm.stranded != 0 {
		t.Errorf("gauge = %d after the workload was recovered, want 0. A gauge that does not "+
			"come back down cannot be alerted on: the operator has no way to tell a fixed "+
			"condition from a live one", fm.stranded)
	}
}

// TestRun_StrandedGaugeClearsWhenNotTheLeader: every node runs a coordinator and
// every node serves /metrics, but only the lease holder measures anything. A node
// that is not driving failover must publish 0.
//
// Without this, a demoted leader pins its last value forever — Prometheus gauges
// retain — and keeps paging the fleet after the condition heals, while every node
// that never held the lease reports a permanent 0 that hides a real one. The same
// contract the dual-run detector already keeps with stepDownDualRun.
func TestRun_StrandedGaugeClearsWhenNotTheLeader(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, state string }{
		{"dead", "fenced"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm

	// It is the leader first, and measures the real condition.
	c.run(ctx)
	if fm.stranded != 1 {
		t.Fatalf("premise: gauge = %d while leader, want 1", fm.stranded)
	}

	// A peer takes the lease out from under it.
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'peer', strftime('%Y-%m-%dT%H:%M:%SZ','now','+60 seconds'),
		         strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
	); err != nil {
		t.Fatalf("hand the lease to a peer: %v", err)
	}

	c.run(ctx)
	if fm.stranded != 0 {
		t.Errorf("gauge = %d after losing the lease, want 0. A demoted leader that keeps "+
			"exporting its last value pages the fleet for a condition it is no longer "+
			"measuring, and no amount of aggregation can tell that apart from a live one",
			fm.stranded)
	}
}

// TestRun_StrandedCountsAutoPromoteEnrolledVM drives the auto-promote lookup end
// to end through run(), rather than passing autoPromote to the predicate as a
// literal.
//
// This is the wiring TestVMNeedsFailover cannot reach: the schedules read, the
// c.Promoter guard, and the map key all sit in strandedWorkloads. A `lv run` VM
// defaults to on_host_failure "none", so if any of that is wrong the VM the
// reschedule loop WOULD have promoted is silently uncounted — an under-report,
// which is the direction that hides real outages.
func TestRun_StrandedCountsAutoPromoteEnrolledVM(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, state string }{
		{"dead", "fenced"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	// Policy "none" — invisible to the policy check on its own.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "enrolled", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"none"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM enrolled: %v", err)
	}
	// Enrolment needs BOTH conditions, so each gets a VM that satisfies only the
	// other. A single fixture satisfying neither lets either half of the
	// predicate rot unnoticed — it passes whichever one you delete.
	//
	// Replication, but the owner never opted into promotion: autoPromoteEnabled
	// requires the flag, so the reschedule loop would not promote this one.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "replica-no-promote", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"none"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM replica-no-promote: %v", err)
	}
	// The flag, but on a plain backup schedule — there is no replica standing by
	// on a target to promote.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "backup-flagged", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"none"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM backup-flagged: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "enrolled", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "coord", KeepReplicas: 3,
		Incremental: true, AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule enrolled: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "replica-no-promote", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "coord", KeepReplicas: 3,
		Incremental: true, AutoPromote: false,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule replica-no-promote: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "backup-flagged", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "backup", TargetPool: "dr", KeepReplicas: 3, AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule backup-flagged: %v", err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.Promoter = &dbPromoter{db: db, target: "coord"}

	c.run(ctx)

	if fm.stranded != 1 {
		t.Errorf("stranded gauge = %d, want 1 (only `enrolled`). 0 means the auto-promote "+
			"lookup is not wired and every promotable VM with the default policy is an "+
			"invisible strand; 2 means one of the two enrolment conditions is not being "+
			"checked — either a replication schedule without auto_promote, or the flag on "+
			"a plain backup schedule, is being read as promotable", fm.stranded)
	}

	// And the guard must mirror the reschedule loop's: no Promoter, no promotion,
	// so nothing to count.
	c2 := newTestCoordinator("coord", db)
	fm2 := newFakeMetrics()
	c2.Metrics = fm2
	c2.run(ctx)
	if fm2.stranded != 0 {
		t.Errorf("stranded gauge = %d with no Promoter, want 0: the reschedule loop gates "+
			"promotion on c.Promoter != nil, so counting a promotable VM here would report "+
			"work the coordinator would never have attempted", fm2.stranded)
	}
}

// TestRun_StrandedGaugeUntouchedOnReadError: a read failure must leave the last
// measured value in place, not publish 0.
//
// 0 is the all-clear on the one gauge an operator alerts on, and a store outage
// is exactly when workloads get stranded. Publishing it from a failed read
// clears the alert during the incident it exists to report.
func TestRun_StrandedGaugeUntouchedOnReadError(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, state string }{
		{"dead", "fenced"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "dead", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm

	c.run(ctx)
	if fm.stranded != 1 || fm.strandedSets != 1 {
		t.Fatalf("premise: gauge = %d after %d sets, want 1 after 1", fm.stranded, fm.strandedSets)
	}

	// Break the container read specifically, so the failure lands INSIDE
	// strandedWorkloads rather than in one of run()'s earlier reads.
	if err := db.Execute(ctx, `DROP TABLE containers`); err != nil {
		t.Fatalf("drop containers: %v", err)
	}

	c.run(ctx)

	if fm.strandedSets != 1 {
		t.Errorf("gauge was written %d times, want 1: a failed read must not publish a "+
			"number nobody measured", fm.strandedSets)
	}
	if fm.stranded != 1 {
		t.Errorf("gauge = %d after the read failed, want the last measured value 1", fm.stranded)
	}
	if got := fm.attempts[foKey(PhaseRecovery, ResultError, ErrDBError)]; got != 1 {
		t.Errorf("db-error counter = %d, want 1: a read failure that does not move the gauge "+
			"has to be observable somewhere, or it is silent (attempts=%v)", got, fm.attempts)
	}
}

// TestRun_StrandedGaugeClearsOnMidCycleLeaseLoss: losing the lease partway
// through a cycle is a step-down too, and the gauge has to follow.
//
// This path is the one that fires without any host failing: a single skipped
// renewal from a store blip hands the lease to a peer while this node is still
// mid-cycle. If it returns without clearing, it keeps exporting a value it is no
// longer entitled to measure — and the peer now measuring the same fleet cannot
// override it, because these are separate series on separate instances.
//
// Reaching it needs two fence candidates: the first candidate's fence flips the
// lease row to a peer, so the second candidate's holdLease check fails.
func TestRun_StrandedGaugeClearsOnMidCycleLeaseLoss(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, state string }{
		{"stale", "fenced"}, {"down1", "active"}, {"down2", "active"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	// A workload already stranded on the previously-fenced host, so the gauge has
	// a non-zero value to lose.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "stale", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm

	c.run(ctx)
	if fm.stranded != 1 {
		t.Fatalf("premise: gauge = %d while leader, want 1", fm.stranded)
	}

	// Now make two hosts fenceable, and have the first fence steal the lease —
	// standing in for a renewal this node lost to a peer mid-cycle.
	fenceQuorum(t, ctx, db, []string{"coord", "down1", "down2"}, "down1")
	fenceQuorum(t, ctx, db, []string{"coord", "down1", "down2"}, "down2")
	stolen := false
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		if !stolen {
			stolen = true
			if err := db.Execute(ctx,
				`INSERT OR REPLACE INTO leader_election (key, holder, expires_at, updated_at)
				 VALUES ('failover', 'peer', strftime('%Y-%m-%dT%H:%M:%SZ','now','+60 seconds'),
				         strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
			); err != nil {
				t.Errorf("steal the lease: %v", err)
			}
		}
		return fence.Result{Method: "test", Detail: "stub", Success: true}
	})

	c.run(ctx)

	// At least one, not exactly one: a fence candidate is now checked against
	// the lease TWICE — holdLeaseAtLeast(minFenceLease) before the fence, and
	// holdLease at the top of the next candidate — so one steal is reported by
	// both call sites. The premise this guards is that the abort path ran at
	// all; pinning the exact count would just re-break the day a third check is
	// added, and the gauge assertion below is the real one.
	if got := fm.attempts[foKey(PhaseFence, ResultRefused, ErrLeaseLost)]; got < 1 {
		t.Fatalf("premise: lease-lost counter = %d, want at least 1 — the run did not take "+
			"the mid-cycle abort path, so this test is not exercising it (attempts=%v)",
			got, fm.attempts)
	}
	if fm.stranded != 0 {
		t.Errorf("gauge = %d after losing the lease mid-cycle, want 0. The peer that took "+
			"the lease publishes its own series; this node's stale value sits alongside it "+
			"and no aggregation can distinguish them", fm.stranded)
	}
}
