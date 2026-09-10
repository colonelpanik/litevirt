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
		detail string
		want   bool
	}{
		{name: "image-recreate", policy: "image-recreate", want: true},
		{name: "policy none", policy: "none", want: false},
		{name: "no policy", policy: "", want: false},
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

// TestRun_ReportsStrandedWorkloads drives a whole run() cycle, because the
// production wiring is the part most worth pinning: a detection signal nothing
// calls is worse than none, since it reads as "no problem" forever.
//
// The scenario is the real one. A host is fenced and its VM's recovery was
// refused after the fence, so the VM still points at a powered-off machine.
// run()'s fence loop skips the host as terminal, so nothing revisits it — which
// is exactly why the condition needs reporting.
func TestRun_ReportsStrandedWorkloads(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, state string }{
		{"dead", "fenced"}, {"live", "active"}, {"coord", "active"},
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

	if fm.stranded != 1 {
		t.Errorf("stranded gauge = %d, want 1 (only `stranded`). A count of 0 means the "+
			"condition is invisible and reads as healthy forever; a count above 1 means the "+
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
