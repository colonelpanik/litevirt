package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/metrics"
)

// recordingVirt is a minimal LibvirtBackend that answers ListDomains/DomainState from a
// map and COUNTS any destructive call — the dual-run detector must never destroy. listErr
// and stateErrOn inject failures for the partial-snapshot tests.
type recordingVirt struct {
	LibvirtBackend
	domains    map[string]string // name -> coarse state ("running" / "stopped")
	listErr    error             // if set, ListDomains fails
	stateErrOn map[string]bool   // domains whose DomainState fails
	destroys   int
	undefines  int
}

func (r *recordingVirt) ListDomains() ([]string, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	names := make([]string, 0, len(r.domains))
	for n := range r.domains {
		names = append(names, n)
	}
	return names, nil
}

func (r *recordingVirt) DomainState(name string) (string, error) {
	if r.stateErrOn[name] {
		return "", fmt.Errorf("injected state error for %q", name)
	}
	if st, ok := r.domains[name]; ok {
		return st, nil
	}
	return "", fmt.Errorf("no domain %q", name)
}

func (r *recordingVirt) DestroyDomain(string) error                 { r.destroys++; return nil }
func (r *recordingVirt) UndefineDomain(string, bool) error          { r.undefines++; return nil }
func (r *recordingVirt) UndefineDomainPreservingState(string) error { r.undefines++; return nil }

// fixedGather is a gatherRuntimeOverride returning a canned per-host snapshot map plus a
// canned UNREACHABLE-host set (no unsupported/older-binary hosts).
func fixedGather(snaps map[string]runtimeSnapshot, unreachable ...string) func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string) {
	return func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string) {
		return snaps, append([]string(nil), unreachable...), nil
	}
}

// gatherWith is a gatherRuntimeOverride that also returns UNSUPPORTED (older-binary) hosts.
func gatherWith(snaps map[string]runtimeSnapshot, unreachable, unsupported []string) func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string) {
	return func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string) {
		return snaps, append([]string(nil), unreachable...), append([]string(nil), unsupported...)
	}
}

// dualRunTestServer builds a test server with hosts h1..hN (all active), self = h1.
func dualRunTestServer(t *testing.T, n int) *Server {
	t.Helper()
	s := testServer(t)
	s.hostName = "h1"
	ctx := context.Background()
	for i := 1; i <= n; i++ {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: fmt.Sprintf("h%d", i), Address: fmt.Sprintf("10.0.0.%d", i), State: "active",
		}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	return s
}

func seedVM(t *testing.T, s *Server, name, owner, state string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: name, HostName: owner, State: state,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

func seedContainer(t *testing.T, s *Server, name, owner, state string) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		Name: name, HostName: owner, State: state,
	}); err != nil {
		t.Fatalf("UpsertContainer(%s): %v", name, err)
	}
}

// captureDualRun subscribes to the event bus and returns a drain function that reports how
// many "ha.dualrun" set events and "ha.dualrun.cleared" clear events landed for a target.
func captureDualRun(t *testing.T, s *Server) (sets func(target string) int, clears func(target string) int, stop func()) {
	t.Helper()
	ch, unsub := s.events.Subscribe()
	setCount := map[string]int{}
	clearCount := map[string]int{}
	drain := func() {
		for {
			select {
			case e := <-ch:
				switch e.Action {
				case "ha.dualrun":
					setCount[e.Target]++
				case "ha.dualrun.cleared":
					clearCount[e.Target]++
				}
			default:
				return
			}
		}
	}
	sets = func(target string) int { drain(); return setCount[target] }
	clears = func(target string) int { drain(); return clearCount[target] }
	return sets, clears, unsub
}

func confirmed(st *dualRunState, kind, target string) bool {
	return st.confirmed[finding{kind: kind, target: target}]
}

// TestDualRun_VMOnTwoHosts_PagesAfterDebounce: a VM that is an active disk-holder on two
// hosts pages only after the debounce threshold, and pages exactly once.
func TestDualRun_VMOnTwoHosts_PagesAfterDebounce(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	sets, _, stop := captureDualRun(t, s)
	defer stop()
	ctx := context.Background()
	st := newDualRunState()

	s.detectDualRunPass(ctx, st) // pass 1 — below threshold
	if confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("confirmed on pass 1 — debounce not applied")
	}
	if got := sets("ha.dualrun.vm:vmA"); got != 0 {
		t.Fatalf("paged %d times on pass 1, want 0", got)
	}

	s.detectDualRunPass(ctx, st) // pass 2 — confirm
	if !confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("not confirmed on pass 2")
	}
	if got := sets("ha.dualrun.vm:vmA"); got != 1 {
		t.Fatalf("paged %d times through pass 2, want 1", got)
	}

	s.detectDualRunPass(ctx, st) // pass 3 — still present, no re-page (set-transition only)
	if got := sets("ha.dualrun.vm:vmA"); got != 1 {
		t.Fatalf("paged %d times through pass 3, want 1 (set-transition only)", got)
	}
}

// TestDualRun_StuckMigrationTwoDiskHolders_Pages: a DB state of "migrating"/"pending" must
// NOT suppress the multi-holder finding — a stuck/failed failover where BOTH hosts actively
// run (and write) the VM is precisely the split-brain this check exists for. (A healthy live
// migration keeps the target PAUSED → only one disk-holder → no finding; the debounce covers
// the brief cutover overlap.)
func TestDualRun_StuckMigrationTwoDiskHolders_Pages(t *testing.T) {
	for _, state := range []string{"migrating", "pending", "relocating", "starting"} {
		s := dualRunTestServer(t, 2)
		seedVM(t, s, "vmA", "h1", state)
		s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
			"h1": {diskHolderVMs: []string{"vmA"}},
			"h2": {diskHolderVMs: []string{"vmA"}},
		})
		ctx := context.Background()
		st := newDualRunState()
		s.detectDualRunPass(ctx, st)
		s.detectDualRunPass(ctx, st)
		if !confirmed(st, kindDualRunVM, "vmA") {
			t.Fatalf("state %q: two active disk-holders must page regardless of DB migration state", state)
		}
	}
}

// TestDualRun_OwnerMismatch_MigrationExempt: the migration-state exemption still applies to
// OWNER-MISMATCH (cutover lag) — a migrating VM with a SINGLE holder that isn't the DB owner
// is legitimate mid-move and must not page.
func TestDualRun_OwnerMismatch_MigrationExempt(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "migrating")
	// Sole holder is h2 (the migration target), DB owner still h1 — legitimate cutover lag.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if confirmed(st, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must stay exempt for a migrating VM (cutover lag)")
	}
	if confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("single holder is not a dual-run")
	}
}

// TestDualRun_VIPOnTwoHosts: a VIP kernel-assigned on two hosts pages; on one host it does
// not (a VRRP master + backup where only the master holds the address).
func TestDualRun_VIPOnTwoHosts(t *testing.T) {
	ctx := context.Background()

	// One holder -> no alert.
	s1 := dualRunTestServer(t, 2)
	s1.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {kernelVIPs: []string{"10.0.0.9"}},
		"h2": {},
	})
	st1 := newDualRunState()
	s1.detectDualRunPass(ctx, st1)
	s1.detectDualRunPass(ctx, st1)
	if confirmed(st1, kindDualRunVIP, "10.0.0.9") {
		t.Fatal("single VIP holder should not page")
	}

	// Two holders -> alert.
	s2 := dualRunTestServer(t, 2)
	s2.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {kernelVIPs: []string{"10.0.0.9"}},
		"h2": {kernelVIPs: []string{"10.0.0.9"}},
	})
	st2 := newDualRunState()
	s2.detectDualRunPass(ctx, st2)
	s2.detectDualRunPass(ctx, st2)
	if !confirmed(st2, kindDualRunVIP, "10.0.0.9") {
		t.Fatal("dual VIP holder should page")
	}
}

// TestDualRun_OwnerMismatch_CoverageGated: a VM whose sole runtime holder is not its DB
// owner pages ONLY when the owner was probed-and-absent (or full coverage). Under partial
// coverage (owner unprobed) it must NOT page — the coverage signal fires instead.
func TestDualRun_OwnerMismatch_CoverageGated(t *testing.T) {
	ctx := context.Background()

	// Partial coverage: owner h3 is unprobed (in failed). No owner-mismatch; a coverage
	// finding for h3 instead.
	sPartial := dualRunTestServer(t, 3)
	seedVM(t, sPartial, "vmA", "h3", "running")
	sPartial.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {diskHolderVMs: []string{"vmA"}},
	}, "h3")
	stP := newDualRunState()
	sPartial.detectDualRunPass(ctx, stP)
	sPartial.detectDualRunPass(ctx, stP)
	if confirmed(stP, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must be suppressed when the DB owner was not probed (partial coverage)")
	}
	if !confirmed(stP, kindDualRunCoverage, "h3") {
		t.Fatal("expected a coverage finding for the unprobed owner h3")
	}

	// Full coverage: owner h3 probed and reported the VM absent; sole holder is h2.
	sFull := dualRunTestServer(t, 3)
	seedVM(t, sFull, "vmA", "h3", "running")
	sFull.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {diskHolderVMs: []string{"vmA"}},
		"h3": {},
	})
	stF := newDualRunState()
	sFull.detectDualRunPass(ctx, stF)
	sFull.detectDualRunPass(ctx, stF)
	if !confirmed(stF, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch should page under full coverage with owner probed-and-absent")
	}
}

// TestDualRun_CrossNodeTies: the leader surfaces unresolved LWW ties reported by ANOTHER
// node (the per-node in-memory count is only visible via the peer report).
func TestDualRun_CrossNodeTies(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {unresolvedTies: 3},
	})
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if !confirmed(st, kindLWWUnresolved, "h2") {
		t.Fatal("expected an unresolved-ties finding for the peer h2")
	}
}

// TestDualRun_ProbeFailure_SurfacedNotSilent: a host that can't be probed becomes a
// debounced coverage finding — never a silent skip.
func TestDualRun_ProbeFailure_SurfacedNotSilent(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
	}, "h2")
	sets, _, stop := captureDualRun(t, s)
	defer stop()
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	if confirmed(st, kindDualRunCoverage, "h2") {
		t.Fatal("coverage finding confirmed on pass 1 — debounce not applied")
	}
	s.detectDualRunPass(ctx, st)
	if !confirmed(st, kindDualRunCoverage, "h2") {
		t.Fatal("unprobed host must surface as a coverage finding")
	}
	if got := sets("ha.dualrun.coverage:h2"); got != 1 {
		t.Fatalf("coverage paged %d times, want 1", got)
	}
}

// TestDualRun_HealClearsConfirmed: when a dual-run heals, the confirmed set drops it and a
// cleared event fires.
func TestDualRun_HealClearsConfirmed(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	_, clears, stop := captureDualRun(t, s)
	defer stop()
	ctx := context.Background()
	st := newDualRunState()

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if !confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("precondition: should be confirmed")
	}

	// Heal: only one holder now.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {},
	})
	s.detectDualRunPass(ctx, st)
	if confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("healed dual-run must clear from confirmed")
	}
	if got := clears("ha.dualrun.vm:vmA"); got != 1 {
		t.Fatalf("cleared event fired %d times, want 1", got)
	}
}

// TestDualRun_NeverDestroys: across passes with a live dual-run, the detector never calls
// any destructive libvirt operation. Uses the REAL self-gather (recordingVirt) with h1 as
// the only workload-capable host.
func TestDualRun_NeverDestroys(t *testing.T) {
	s := testServer(t)
	s.hostName = "h1"
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "h1", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	rv := &recordingVirt{domains: map[string]string{"vmA": "running", "vmB": "stopped"}}
	s.virt = rv
	seedVM(t, s, "vmA", "h1", "running")

	st := newDualRunState()
	for i := 0; i < 3; i++ {
		s.detectDualRunPass(ctx, st) // real gather → localRuntimeSnapshot(self)
	}
	if rv.destroys != 0 || rv.undefines != 0 {
		t.Fatalf("detector performed destructive ops: destroys=%d undefines=%d", rv.destroys, rv.undefines)
	}
}

// TestReportRuntime_PeerOnly: the RPC rejects a non-peer caller and, for a peer, returns
// this host's local runtime snapshot.
func TestReportRuntime_PeerOnly(t *testing.T) {
	s := testServer(t)
	s.virt = &recordingVirt{domains: map[string]string{"run": "running", "stop": "stopped"}}

	if _, err := s.ReportRuntime(adminCtx(), &pb.ReportRuntimeRequest{}); err == nil {
		t.Fatal("ReportRuntime must reject a non-peer (admin) caller")
	}

	ctx := peerCtxFor(t, s, "peer-1")
	resp, err := s.ReportRuntime(ctx, &pb.ReportRuntimeRequest{})
	if err != nil {
		t.Fatalf("ReportRuntime(peer): %v", err)
	}
	if len(resp.GetDiskHolderVms()) != 1 || resp.GetDiskHolderVms()[0] != "run" {
		t.Fatalf("disk_holder_vms = %v, want [run]", resp.GetDiskHolderVms())
	}
}

// TestLocalRuntimeSnapshot_OnlyRunningVMsAreDiskHolders: only DomainState=="running"
// (RUNNING|BLOCKED) counts as an active disk-holder; a stopped/paused domain does not.
func TestLocalRuntimeSnapshot_OnlyRunningVMsAreDiskHolders(t *testing.T) {
	s := testServer(t)
	s.virt = &recordingVirt{domains: map[string]string{"run": "running", "stop": "stopped"}}
	snap := s.localRuntimeSnapshot(context.Background())
	if len(snap.diskHolderVMs) != 1 || snap.diskHolderVMs[0] != "run" {
		t.Fatalf("disk-holders = %v, want [run] only", snap.diskHolderVMs)
	}
}

// TestDualRunProbeTargets_IncludesFencedExcludesWitness: draining/offline/upgrading AND
// fenced are INCLUDED (without a real STONITH a fenced host may still be writing a disk —
// exactly where a dual-run hides); only witnesses are excluded.
func TestDualRunProbeTargets_IncludesFencedExcludesWitness(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "a", State: "active"},
		{Name: "b", State: "draining"},
		{Name: "c", State: "offline"},
		{Name: "f", State: "fenced"},
		{Name: "w", State: "active", Role: "witness"},
	}
	got := dualRunProbeTargets(hosts)
	want := "a,b,c,f"
	if strings.Join(got, ",") != want {
		t.Fatalf("dualRunProbeTargets = %v, want [%s]", got, want)
	}
}

// TestDualRun_FencedHostStillRunning_Detected: the canonical split-brain — a fenced host
// (no real STONITH) still holds a VM's disk that failover has restarted elsewhere. The
// fenced host must be probed and the dual-run flagged.
func TestDualRun_FencedHostStillRunning_Detected(t *testing.T) {
	s := testServer(t)
	s.hostName = "h1"
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "h1", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost h1: %v", err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "h2", Address: "10.0.0.2", State: "fenced"}); err != nil {
		t.Fatalf("InsertHost h2: %v", err)
	}
	// DB says failover moved vmA to h1, but fenced h2 is still running it.
	seedVM(t, s, "vmA", "h1", "running")
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if !confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("a fenced host still running the VM must be detected as a dual-run")
	}
}

// TestDualRun_ContainerOnTwoHosts: same container running on two hosts pages; a migrating
// container (DB state "migrating") does not.
func TestDualRun_ContainerOnTwoHosts(t *testing.T) {
	ctx := context.Background()

	s := dualRunTestServer(t, 2)
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {runningCTs: []string{"ctA"}},
		"h2": {runningCTs: []string{"ctA"}},
	})
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if !confirmed(st, kindDualRunCT, "ctA") {
		t.Fatal("a container running on two hosts should page")
	}

	// A DB "migrating" state does NOT suppress the multi-holder finding: cold CT migration
	// stops the source before starting the target, so two RUNNING holders is a real dual-run
	// (a stuck/failed move), not a legitimate cutover.
	sMig := dualRunTestServer(t, 2)
	seedContainer(t, sMig, "ctB", "h1", "migrating")
	sMig.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {runningCTs: []string{"ctB"}},
		"h2": {runningCTs: []string{"ctB"}},
	})
	stMig := newDualRunState()
	sMig.detectDualRunPass(ctx, stMig)
	sMig.detectDualRunPass(ctx, stMig)
	if !confirmed(stMig, kindDualRunCT, "ctB") {
		t.Fatal("two running containers must page regardless of DB migration state")
	}
}

// TestDualRun_UnsupportedPeer_NotPagedAsCoverage: a peer on an older binary (ReportRuntime
// Unimplemented) is surfaced in the probe_failed gauge but must NOT page as a coverage gap
// — that is expected version skew during a rolling upgrade, not a segmentation.
func TestDualRun_UnsupportedPeer_NotPagedAsCoverage(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.gatherRuntimeOverride = gatherWith(map[string]runtimeSnapshot{"h1": {}}, nil, []string{"h2"})
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if confirmed(st, kindDualRunCoverage, "h2") {
		t.Fatal("an older-binary peer must not page as a coverage gap")
	}
}

// TestDualRun_OwnerMismatch_UnprobedOwnerDeferred: an owner that was NOT positively probed
// (e.g. unreachable / outside the probe set) must never produce an owner-mismatch page.
func TestDualRun_OwnerMismatch_UnprobedOwnerDeferred(t *testing.T) {
	s := dualRunTestServer(t, 3)
	seedVM(t, s, "vmA", "h3", "running")
	// h3 (the DB owner) is unreachable; vmA runs solely on h2.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {diskHolderVMs: []string{"vmA"}},
	}, "h3")
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if confirmed(st, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must be deferred when the DB owner was not positively probed")
	}
}

// TestDualRun_DebounceReArmsOnFlap: a finding that disappears for a pass must reset its
// counter — reappearing does not immediately re-confirm.
func TestDualRun_DebounceReArmsOnFlap(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	ctx := context.Background()
	st := newDualRunState()

	present := fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	absent := fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {},
	})

	s.gatherRuntimeOverride = present
	s.detectDualRunPass(ctx, st) // seen=1
	s.gatherRuntimeOverride = absent
	s.detectDualRunPass(ctx, st) // gone -> reset
	s.gatherRuntimeOverride = present
	s.detectDualRunPass(ctx, st) // seen=1 again (must NOT confirm)
	if confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("a flapping finding must not confirm on its first pass back (counter must reset)")
	}
	s.detectDualRunPass(ctx, st) // seen=2 -> confirm
	if !confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("should confirm after two consecutive passes back")
	}
}

// TestAcquireDualRunLease_SingleLeader: two nodes sharing a DB — only one holds the lease.
func TestAcquireDualRunLease_SingleLeader(t *testing.T) {
	s1 := dualRunTestServer(t, 2)
	s2 := &Server{hostName: "h2", db: s1.db, events: events.NewBus()}
	ctx := context.Background()

	if !s1.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h1 should acquire the lease")
	}
	if s2.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h2 must not acquire while h1 holds a valid lease")
	}
	if !s1.acquireDualRunLease(ctx, 60*time.Second) {
		t.Fatal("h1 should renew its own lease")
	}
}

// TestDetectedLabels_ExcludesCoverage: coverage findings are not exported to the
// detected gauge, and kinds map to their short labels.
func TestDetectedLabels_ExcludesCoverage(t *testing.T) {
	confirmed := map[finding]bool{
		{kind: kindDualRunVM, target: "vmA"}:      true,
		{kind: kindOwnerMismatch, target: "vmB"}:  true,
		{kind: kindLWWUnresolved, target: "h3"}:   true,
		{kind: kindDualRunCoverage, target: "h2"}: true,
	}
	labels := detectedLabels(confirmed)
	if len(labels) != 3 {
		t.Fatalf("detectedLabels returned %d labels, want 3 (coverage excluded): %v", len(labels), labels)
	}
	got := map[string]string{}
	for _, l := range labels {
		got[l.Kind] = l.Target
	}
	if got["vm"] != "vmA" || got["owner_mismatch"] != "vmB" || got["lww_unresolved"] != "h3" {
		t.Fatalf("label mapping wrong: %v", got)
	}
	if _, ok := got["coverage"]; ok {
		t.Fatal("coverage must not appear in the detected gauge labels")
	}
	if _, ok := got[kindDualRunCoverage]; ok {
		t.Fatal("coverage kind leaked into detected labels")
	}
}

// TestLocalRuntimeSnapshot_PartialOnProbeError: a probe error marks the snapshot partial
// (so ABSENCE is not trusted) rather than being swallowed into a false-empty result. A
// per-item state error still reports the healthy siblings — one wedged domain must not
// blind the whole host.
func TestLocalRuntimeSnapshot_PartialOnProbeError(t *testing.T) {
	// Enumeration failure → partial, no VMs.
	s := testServer(t)
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	snap := s.localRuntimeSnapshot(context.Background())
	if !snap.partial {
		t.Fatal("ListDomains error must mark the snapshot partial")
	}

	// Per-item state error → partial, but the readable sibling is still reported.
	s2 := testServer(t)
	s2.virt = &recordingVirt{
		domains:    map[string]string{"ok": "running", "wedged": "running"},
		stateErrOn: map[string]bool{"wedged": true},
	}
	snap2 := s2.localRuntimeSnapshot(context.Background())
	if !snap2.partial {
		t.Fatal("a per-item DomainState error must mark the snapshot partial")
	}
	if len(snap2.diskHolderVMs) != 1 || snap2.diskHolderVMs[0] != "ok" {
		t.Fatalf("healthy sibling must still be reported despite a wedged domain: %v", snap2.diskHolderVMs)
	}

	// Clean host → not partial.
	s3 := testServer(t)
	s3.virt = &recordingVirt{domains: map[string]string{"ok": "running"}}
	if s3.localRuntimeSnapshot(context.Background()).partial {
		t.Fatal("a clean host must not be marked partial")
	}
}

// TestReportRuntime_CarriesPartial: the partial flag rides the RPC response.
func TestReportRuntime_CarriesPartial(t *testing.T) {
	s := testServer(t)
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	resp, err := s.ReportRuntime(peerCtxFor(t, s, "peer-1"), &pb.ReportRuntimeRequest{})
	if err != nil {
		t.Fatalf("ReportRuntime: %v", err)
	}
	if !resp.GetPartial() {
		t.Fatal("ReportRuntime must report partial=true when a local probe errored")
	}
}

// TestDualRun_PartialOwner_NoFalseOwnerMismatch: a DB owner whose snapshot is PARTIAL must
// not be used as absence proof — its VM running solely elsewhere must NOT page owner-mismatch
// (its own runtime is unreliable); instead the partial owner raises a coverage gap.
func TestDualRun_PartialOwner_NoFalseOwnerMismatch(t *testing.T) {
	s := dualRunTestServer(t, 3)
	seedVM(t, s, "vmA", "h3", "running")
	// h3 (DB owner) returned a PARTIAL snapshot (absence unreliable); vmA runs solely on h2.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {},
		"h2": {diskHolderVMs: []string{"vmA"}},
		"h3": {partial: true},
	})
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if confirmed(st, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must be deferred when the owner's snapshot is partial")
	}
	if !confirmed(st, kindDualRunCoverage, "h3") {
		t.Fatal("a partial host must raise a coverage finding")
	}
}

// TestDualRun_PartialHost_PositiveHoldersStillCounted: a partial host's REPORTED holders are
// still real — a VM it reports running that also runs elsewhere is a genuine dual-run.
func TestDualRun_PartialHost_PositiveHoldersStillCounted(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}, partial: true},
	})
	ctx := context.Background()
	st := newDualRunState()
	s.detectDualRunPass(ctx, st)
	s.detectDualRunPass(ctx, st)
	if !confirmed(st, kindDualRunVM, "vmA") {
		t.Fatal("a partial host's positive holder must still count toward a dual-run")
	}
}

// seriesCount counts the active series of a metric family in a gathered registry.
func seriesCount(t *testing.T, reg *prometheus.Registry, name string) int {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return len(mf.GetMetric())
		}
	}
	return 0
}

// TestStepDownDualRun_ClearsProbeFailedGauge: on leadership loss a former leader must clear
// BOTH gauges — including probe_failed set by unsupported-only peers (which populate neither
// seen nor confirmed), so no stale series is stranded after a handoff.
func TestStepDownDualRun_ClearsProbeFailedGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := testServer(t)
	s.dualRunMetrics = metrics.NewDualRunMetricsWith(reg)

	// Simulate a former leader whose only output was a probe_failed series (unsupported peer).
	s.dualRunMetrics.SetProbeFailed([]string{"old-peer"})
	s.dualRunMetrics.SetDetected([]metrics.DualRunLabel{{Kind: "vm", Target: "vmA"}})
	if seriesCount(t, reg, "litevirt_dual_run_probe_failed") != 1 {
		t.Fatal("precondition: probe_failed should have 1 series")
	}

	s.stepDownDualRun()

	if got := seriesCount(t, reg, "litevirt_dual_run_probe_failed"); got != 0 {
		t.Fatalf("probe_failed series = %d after step-down, want 0", got)
	}
	if got := seriesCount(t, reg, "litevirt_dual_run_detected"); got != 0 {
		t.Fatalf("detected series = %d after step-down, want 0", got)
	}
}
