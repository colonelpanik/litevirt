package failover

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A lease-term stamp refusal ABANDONS the workload. strandedWorkloads' own doc
// says so: "a fenced host is processed only once, so refusing here does not
// defer the work — it abandons it", and run() short-circuits the host on every
// later cycle. So the refusal is a permanent, per-workload outage.
//
// It was recorded only in two counters. The branch did `noteGateRefused` +
// `mVM` + `continue` — no log, no audit row — and it fires immediately after
// `slog.Info("failover: rescheduling VM", ...)`, so the journal reads as a
// reschedule that simply ended. Every sibling abandonment branch in the same
// loop logs, and most also write a `failover.skip` audit row naming the
// workload.
//
// The counters cannot answer the question an operator actually has at 3am,
// which is WHICH workloads were abandoned. One superseded term strands every
// VM on the host at once, and a metric increments to 40 without naming one.
func TestLeaseTermRefusal_NamesEveryAbandonedWorkload(t *testing.T) {
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
	for _, vm := range []string{"vm1", "vm2"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm, HostName: "dead", State: "running",
			Spec: `{"on_host_failure":"restart-any"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm, err)
		}
	}
	fenceQuorum(t, ctx, db, []string{"coord", "live"}, "dead")

	c := newTestCoordinator("coord", db)
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

	// Hold the lease with NO usable term. This is one of the two causes
	// leaseTermStampAllowed's own comment names — "holdLease cleared it on a
	// loss path" — and it is the one that leaves the coordinator still driving
	// recovery, which is what makes the refusal reachable per workload.
	//
	// recoverWorkloads is called directly rather than through run() because
	// run() re-acquires the lease on entry and would mint a fresh term, which is
	// precisely the state this test needs to NOT be in.
	c.leaseTerm.Store(0)

	dead, err := corrosion.GetHost(ctx, db, "dead")
	if err != nil || dead == nil {
		t.Fatalf("GetHost dead: %v", err)
	}
	c.recoverWorkloads(ctx, dead)

	// Precondition: the refusal actually happened. Without this the test would
	// pass on a tick that rescheduled both VMs normally.
	proofs, err := db.Query(ctx, `SELECT id FROM runtime_action_proofs`)
	if err != nil {
		t.Fatalf("read proofs: %v", err)
	}
	if len(proofs) != 0 {
		t.Fatalf("proofs=%d; want 0 — the stamp was not refused, so this test is vacuous",
			len(proofs))
	}

	rows, err := db.Query(ctx,
		`SELECT target, detail, result FROM audit_log WHERE action = 'failover.skip'`)
	if err != nil {
		t.Fatalf("read audit_log: %v", err)
	}

	named := map[string]bool{}
	for _, r := range rows {
		named[r.String("target")] = true
	}
	for _, vm := range []string{"vm1", "vm2"} {
		if !named[vm] {
			t.Errorf("no failover.skip audit row names %q\n"+
				"the VM was abandoned permanently — a fenced host is processed once — and "+
				"the only trace is a counter. An operator cannot learn which workloads "+
				"were stranded.\ngot rows: %d", vm, len(rows))
		}
	}
	for _, r := range rows {
		if d := r.String("detail"); d != "" && !strings.Contains(strings.ToLower(d), "lease term") {
			t.Errorf("audit detail %q does not name the lease term as the cause", d)
		}
	}
}
