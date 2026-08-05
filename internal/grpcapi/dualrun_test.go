package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
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

func (r *recordingVirt) DumpXML(name string) (string, error) {
	// Minimal well-formed domain XML so the inventory collector can read a size.
	return `<domain type='kvm'><name>` + name + `</name><memory unit='MiB'>1024</memory><vcpu>1</vcpu></domain>`, nil
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

// condLifecycle reads a condition's durable lifecycle ("" when no row exists).
func condLifecycle(s *Server, kind, target string) string {
	code, subjectKind := conditionIdentity(kind)
	h, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, dualRunEvaluator, code, subjectKind, target)
	if err != nil || !ok {
		return ""
	}
	return h.Lifecycle
}

func confirmedCond(s *Server, kind, target string) bool {
	return condLifecycle(s, kind, target) == corrosion.ConditionConfirmed
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

	s.detectDualRunPass(ctx) // pass 1 — below threshold
	if confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("confirmed on pass 1 — debounce not applied")
	}
	if got := sets("ha.dualrun.vm:vmA"); got != 0 {
		t.Fatalf("paged %d times on pass 1, want 0", got)
	}

	s.detectDualRunPass(ctx) // pass 2 — confirm
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("not confirmed on pass 2")
	}
	if got := sets("ha.dualrun.vm:vmA"); got != 1 {
		t.Fatalf("paged %d times through pass 2, want 1", got)
	}

	s.detectDualRunPass(ctx) // pass 3 — still present, no re-page (set-transition only)
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
		s.detectDualRunPass(ctx)
		s.detectDualRunPass(ctx)
		if !confirmedCond(s, kindDualRunVM, "vmA") {
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if confirmedCond(s, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must stay exempt for a migrating VM (cutover lag)")
	}
	if confirmedCond(s, kindDualRunVM, "vmA") {
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
	s1.detectDualRunPass(ctx)
	s1.detectDualRunPass(ctx)
	if confirmedCond(s1, kindDualRunVIP, "10.0.0.9") {
		t.Fatal("single VIP holder should not page")
	}

	// Two holders -> alert.
	s2 := dualRunTestServer(t, 2)
	s2.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {kernelVIPs: []string{"10.0.0.9"}},
		"h2": {kernelVIPs: []string{"10.0.0.9"}},
	})
	s2.detectDualRunPass(ctx)
	s2.detectDualRunPass(ctx)
	if !confirmedCond(s2, kindDualRunVIP, "10.0.0.9") {
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
	sPartial.detectDualRunPass(ctx)
	sPartial.detectDualRunPass(ctx)
	if confirmedCond(sPartial, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must be suppressed when the DB owner was not probed (partial coverage)")
	}
	if !confirmedCond(sPartial, kindDualRunCoverage, "h3") {
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
	sFull.detectDualRunPass(ctx)
	sFull.detectDualRunPass(ctx)
	if !confirmedCond(sFull, kindOwnerMismatch, "vmA") {
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindLWWUnresolved, "h2") {
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
	s.detectDualRunPass(ctx)
	if confirmedCond(s, kindDualRunCoverage, "h2") {
		t.Fatal("coverage finding confirmed on pass 1 — debounce not applied")
	}
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunCoverage, "h2") {
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

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("precondition: should be confirmed")
	}

	// Heal: only one holder now. Resolution is STRICTER than confirmation — one
	// clean pass proves nothing (a probe can race a restart); the condition
	// resolves only after TWO consecutive complete clean scans.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {},
	})
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("one clean scan must NOT resolve a confirmed dual-run")
	}
	if got := clears("ha.dualrun.vm:vmA"); got != 0 {
		t.Fatalf("cleared event fired %d times after one clean scan, want 0", got)
	}
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionResolved {
		t.Fatalf("after two complete clean scans lifecycle = %q, want resolved", got)
	}
	if got := clears("ha.dualrun.vm:vmA"); got != 1 {
		t.Fatalf("cleared event fired %d times, want exactly 1", got)
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

	for i := 0; i < 3; i++ {
		s.detectDualRunPass(ctx) // real gather → localRuntimeSnapshot(self)
	}
	if rv.destroys != 0 || rv.undefines != 0 {
		t.Fatalf("detector performed destructive ops: destroys=%d undefines=%d", rv.destroys, rv.undefines)
	}
}

// TestGetRuntimeInventory_PeerOnly: the RPC rejects a non-peer caller and, for a
// peer, returns this host's local runtime inventory with running domains marked
// as disk-holders.
func TestGetRuntimeInventory_PeerOnly(t *testing.T) {
	s := testServer(t)
	s.virt = &recordingVirt{domains: map[string]string{"run": "running", "stop": "stopped"}}

	if _, err := s.GetRuntimeInventory(adminCtx(), &pb.GetRuntimeInventoryRequest{}); err == nil {
		t.Fatal("GetRuntimeInventory must reject a non-peer (admin) caller")
	}

	ctx := peerCtxFor(t, s, "peer-1")
	resp, err := s.GetRuntimeInventory(ctx, &pb.GetRuntimeInventoryRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeInventory(peer): %v", err)
	}
	var holders []string
	for _, w := range resp.GetWorkloads() {
		if w.GetDiskHolder() {
			holders = append(holders, w.GetName())
		}
	}
	if len(holders) != 1 || holders[0] != "run" {
		t.Fatalf("disk holders = %v, want [run]", holders)
	}
	// The stopped-but-defined domain is still LISTED — runtime state the DB
	// comparison needs — just not a holder.
	if len(resp.GetWorkloads()) != 2 {
		t.Fatalf("workloads = %d entries, want 2 (run + stop)", len(resp.GetWorkloads()))
	}
}

// TestLocalRuntimeSnapshot_OnlyRunningVMsAreDiskHolders: only DomainState=="running"
// (RUNNING|BLOCKED) counts as an active disk-holder; a stopped/paused domain does not.
func TestLocalRuntimeSnapshot_OnlyRunningVMsAreDiskHolders(t *testing.T) {
	s := testServer(t)
	s.virt = &recordingVirt{domains: map[string]string{"run": "running", "stop": "stopped"}}
	snap := snapshotFromInventory(s.collectRuntimeInventory(context.Background()))
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunCT, "ctA") {
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
	sMig.detectDualRunPass(ctx)
	sMig.detectDualRunPass(ctx)
	if !confirmedCond(sMig, kindDualRunCT, "ctB") {
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if confirmedCond(s, kindDualRunCoverage, "h2") {
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if confirmedCond(s, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must be deferred when the DB owner was not positively probed")
	}
}

// TestDualRun_DebounceReArmsOnFlap: a finding that disappears for a pass must reset its
// counter — reappearing does not immediately re-confirm.
func TestDualRun_DebounceReArmsOnFlap(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	ctx := context.Background()

	present := fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	absent := fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {},
	})

	s.gatherRuntimeOverride = present
	s.detectDualRunPass(ctx) // seen=1
	s.gatherRuntimeOverride = absent
	s.detectDualRunPass(ctx) // gone -> reset
	s.gatherRuntimeOverride = present
	s.detectDualRunPass(ctx) // seen=1 again (must NOT confirm)
	if confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("a flapping finding must not confirm on its first pass back (counter must reset)")
	}
	s.detectDualRunPass(ctx) // seen=2 -> confirm
	if !confirmedCond(s, kindDualRunVM, "vmA") {
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
	snap := snapshotFromInventory(s.collectRuntimeInventory(context.Background()))
	if !snap.partial {
		t.Fatal("ListDomains error must mark the snapshot partial")
	}

	// Per-item state error → partial, but the readable sibling is still reported.
	s2 := testServer(t)
	s2.virt = &recordingVirt{
		domains:    map[string]string{"ok": "running", "wedged": "running"},
		stateErrOn: map[string]bool{"wedged": true},
	}
	snap2 := snapshotFromInventory(s2.collectRuntimeInventory(context.Background()))
	if !snap2.partial {
		t.Fatal("a per-item DomainState error must mark the snapshot partial")
	}
	if len(snap2.diskHolderVMs) != 1 || snap2.diskHolderVMs[0] != "ok" {
		t.Fatalf("healthy sibling must still be reported despite a wedged domain: %v", snap2.diskHolderVMs)
	}

	// Clean host → not partial.
	s3 := testServer(t)
	s3.virt = &recordingVirt{domains: map[string]string{"ok": "running"}}
	if snapshotFromInventory(s3.collectRuntimeInventory(context.Background())).partial {
		t.Fatal("a clean host must not be marked partial")
	}
}

// TestGetRuntimeInventory_CarriesIncomplete: the completeness flag rides the RPC
// response — complete=false when a local probe errored, so a caller can never
// mistake a blind host for an empty one.
func TestGetRuntimeInventory_CarriesIncomplete(t *testing.T) {
	s := testServer(t)
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	resp, err := s.GetRuntimeInventory(peerCtxFor(t, s, "peer-1"), &pb.GetRuntimeInventoryRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeInventory: %v", err)
	}
	if resp.GetComplete() {
		t.Fatal("GetRuntimeInventory must report complete=false when a local probe errored")
	}
	if len(resp.GetErrors()) == 0 {
		t.Fatal("an incomplete inventory must say why")
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if confirmedCond(s, kindOwnerMismatch, "vmA") {
		t.Fatal("owner-mismatch must be deferred when the owner's snapshot is partial")
	}
	if !confirmedCond(s, kindDualRunCoverage, "h3") {
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
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
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

// fakeCT is a minimal ContainerRuntime for the LXC-capability-gate tests.
type fakeCT struct {
	ContainerRuntime
	names   []string
	listErr error
	states  map[string]string
	// limits maps name → {cpu, memMiB}; absent means 0/0 (fully unlimited).
	limits map[string][2]int
}

func (f *fakeCT) ListContainers(context.Context) ([]string, error) { return f.names, f.listErr }
func (f *fakeCT) StateContainer(_ context.Context, n string) (string, error) {
	return f.states[n], nil
}
func (f *fakeCT) ContainerLimits(_ context.Context, n string) (int, int, error) {
	l := f.limits[n]
	return l[0], l[1], nil
}

// TestLocalRuntimeSnapshot_NonLXCHost_NotPartial: on a host without lxc-* tooling the CT
// probe is skipped entirely — a "lxc-ls not found" error must NOT mark the snapshot partial
// (there are no local containers to miss), else every VM-only host would page a standing
// coverage alert.
func TestLocalRuntimeSnapshot_NonLXCHost_NotPartial(t *testing.T) {
	orig := lxcCapable
	lxcCapable = func() bool { return false }
	defer func() { lxcCapable = orig }()

	s := testServer(t)
	// The runtime is wired (as the daemon does) but would error — must be ignored.
	s.containerRuntime = &fakeCT{listErr: fmt.Errorf("exec: \"lxc-ls\": executable file not found in $PATH")}
	snap := snapshotFromInventory(s.collectRuntimeInventory(context.Background()))
	if snap.partial {
		t.Fatal("a non-LXC host must not be marked partial by a skipped CT probe")
	}
	if len(snap.runningCTs) != 0 {
		t.Fatalf("expected no CTs on a non-LXC host, got %v", snap.runningCTs)
	}
}

// TestLocalRuntimeSnapshot_LXCCapable_ProbeErrorPartial: on an LXC-capable host, a genuine
// container-list error IS a coverage gap → partial.
func TestLocalRuntimeSnapshot_LXCCapable_ProbeErrorPartial(t *testing.T) {
	orig := lxcCapable
	lxcCapable = func() bool { return true }
	defer func() { lxcCapable = orig }()

	s := testServer(t)
	s.containerRuntime = &fakeCT{listErr: fmt.Errorf("lxc-ls: permission denied")}
	if !snapshotFromInventory(s.collectRuntimeInventory(context.Background())).partial {
		t.Fatal("a container-list error on an LXC-capable host must mark the snapshot partial")
	}

	// And a healthy capable host reports its running containers, not partial.
	s2 := testServer(t)
	s2.containerRuntime = &fakeCT{names: []string{"ctA", "ctB"}, states: map[string]string{"ctA": "running", "ctB": "stopped"}}
	snap := snapshotFromInventory(s2.collectRuntimeInventory(context.Background()))
	if snap.partial {
		t.Fatal("a healthy LXC host must not be partial")
	}
	if len(snap.runningCTs) != 1 || snap.runningCTs[0] != "ctA" {
		t.Fatalf("running CTs = %v, want [ctA]", snap.runningCTs)
	}
}

// twoHolderGather is the canonical dual-run fixture: vmA an active disk-holder
// on both hosts, full coverage.
func twoHolderGather() func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string) {
	return fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
}

// readCond fetches the durable condition row for assertions.
func readCond(t *testing.T, s *Server, kind, target string) corrosion.HealthCondition {
	t.Helper()
	code, subjectKind := conditionIdentity(kind)
	h, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, dualRunEvaluator, code, subjectKind, target)
	if err != nil || !ok {
		t.Fatalf("condition %s/%s missing: ok=%v err=%v", kind, target, ok, err)
	}
	return h
}

// TestConditionLifecycle_ObservedWarningThenConfirmedCritical pins the severity
// progression: the first positive scan records an OBSERVED warning; the second
// consecutive one CONFIRMS at critical (for a corruption-class code).
func TestConditionLifecycle_ObservedWarningThenConfirmedCritical(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	s.gatherRuntimeOverride = twoHolderGather()
	ctx := context.Background()

	s.detectDualRunPass(ctx)
	h := readCond(t, s, kindDualRunVM, "vmA")
	if h.Lifecycle != corrosion.ConditionObserved || h.Severity != corrosion.SeverityWarning {
		t.Fatalf("after one scan: %s/%s, want observed/warning", h.Lifecycle, h.Severity)
	}
	if h.ObserveCount != 1 || h.FirstSeen == "" || h.ConfirmedAt != "" {
		t.Errorf("observed row bookkeeping wrong: %+v", h)
	}

	s.detectDualRunPass(ctx)
	h = readCond(t, s, kindDualRunVM, "vmA")
	if h.Lifecycle != corrosion.ConditionConfirmed || h.Severity != corrosion.SeverityCritical {
		t.Fatalf("after two scans: %s/%s, want confirmed/critical", h.Lifecycle, h.Severity)
	}
	if h.ConfirmedAt == "" || h.ObserveCount != 2 {
		t.Errorf("confirmed row bookkeeping wrong: %+v", h)
	}
	if len(h.Hosts) != 2 {
		t.Errorf("involved hosts = %v, want both holders", h.Hosts)
	}
}

// TestConditionLifecycle_SurvivesLeaderChange: a NEW leader (fresh process state,
// same replicated rows) continues the lifecycle exactly where the old one
// stopped — the confirmed state neither re-arms nor re-pages, and its counts
// keep advancing.
func TestConditionLifecycle_SurvivesLeaderChange(t *testing.T) {
	s1 := dualRunTestServer(t, 2)
	seedVM(t, s1, "vmA", "h1", "running")
	s1.gatherRuntimeOverride = twoHolderGather()
	ctx := context.Background()
	s1.detectDualRunPass(ctx)
	s1.detectDualRunPass(ctx)
	if !confirmedCond(s1, kindDualRunVM, "vmA") {
		t.Fatal("precondition: confirmed on the first leader")
	}

	// Leadership moves: h2 shares the SAME replicated state, no in-memory carry.
	s2 := &Server{hostName: "h2", db: s1.db, events: events.NewBus()}
	s2.gatherRuntimeOverride = twoHolderGather()
	sets, _, stop := captureDualRun(t, s2)
	defer stop()
	s2.detectDualRunPass(ctx)
	h := readCond(t, s2, kindDualRunVM, "vmA")
	if h.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("new leader sees lifecycle %q, want confirmed preserved", h.Lifecycle)
	}
	if h.ObserveCount != 3 {
		t.Errorf("observe count = %d, want 3 (continued, not re-armed)", h.ObserveCount)
	}
	if got := sets("ha.dualrun.vm:vmA"); got != 0 {
		t.Errorf("new leader re-paged a standing confirmed condition %d times, want 0", got)
	}
	if h.Reporter != "h2" {
		t.Errorf("reporter = %q, want the new leader h2", h.Reporter)
	}
}

// TestConditionLifecycle_IncompleteCoverageCannotResolve: with the dual-run gone
// but a peer unreachable, the scan proves nothing about absence — the condition
// must stay confirmed with its clean streak unadvanced, for as many passes as
// the blindness lasts.
func TestConditionLifecycle_IncompleteCoverageCannotResolve(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	s.gatherRuntimeOverride = twoHolderGather()
	ctx := context.Background()
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)

	// vmA no longer reported anywhere — but h2 is unreachable.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
	}, "h2")
	for i := 0; i < 3; i++ {
		s.detectDualRunPass(ctx)
	}
	h := readCond(t, s, kindDualRunVM, "vmA")
	if h.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("lifecycle = %q under incomplete coverage, want confirmed retained", h.Lifecycle)
	}
	if h.CleanCount != 0 {
		t.Errorf("clean streak advanced to %d under incomplete coverage, want 0 — partial scans prove nothing", h.CleanCount)
	}

	// Coverage returns: two complete clean scans resolve it.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {},
	})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionResolved {
		t.Fatalf("after coverage returned and two clean scans: %q, want resolved", got)
	}
}

// TestConditionLifecycle_GateInvalidCannotResolve: a leader without local quorum
// may RECORD positive evidence but may not PROVE absence — resolution waits for
// the decision gate.
func TestConditionLifecycle_GateInvalidCannotResolve(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	s.gatherRuntimeOverride = twoHolderGather()
	ctx := context.Background()
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)

	// Quorum lost; the dual-run also disappears from the (complete) gather.
	s.SetGate(fakeServerGate{execOK: false})
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {},
	})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionConfirmed {
		t.Fatalf("lifecycle = %q with an invalid gate, want confirmed retained", got)
	}

	// Quorum back: the same clean evidence now resolves.
	s.SetGate(fakeServerGate{execOK: true})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionResolved {
		t.Fatalf("lifecycle = %q after quorum returned, want resolved", got)
	}
}

// TestConditionLifecycle_EvaluatorStatusRecordsCoverage: every pass writes the
// evaluator's scan status, so consumers can tell "clean" from "blind".
func TestConditionLifecycle_EvaluatorStatusRecordsCoverage(t *testing.T) {
	s := dualRunTestServer(t, 2)
	ctx := context.Background()
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}}, "h2")
	s.detectDualRunPass(ctx)

	sts, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil || len(sts) != 1 {
		t.Fatalf("evaluator status rows = %d err=%v, want 1", len(sts), err)
	}
	if sts[0].Evaluator != dualRunEvaluator || sts[0].Coverage != corrosion.CoveragePartial {
		t.Fatalf("status = %+v, want dual_run/partial", sts[0])
	}

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}, "h2": {}})
	s.detectDualRunPass(ctx)
	sts, _ = corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if sts[0].Coverage != corrosion.CoverageComplete {
		t.Fatalf("coverage = %q after a full gather, want complete", sts[0].Coverage)
	}
}

// TestEpochMismatch_ValidEqualMarkerDoesNotFire is the false-positive
// regression the LAB caught: with owner_epoch_v1 latched, a VM running on its
// DB owner with a VALID marker EQUAL to the row's epoch must raise nothing.
// The detector's DB index is built from ListVMs, which did not select
// vm_owner_epoch — so every epoched VM compared marker N against 0 and paged.
func TestEpochMismatch_ValidEqualMarkerDoesNotFire(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.OwnerEpochV1: true}})
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 9 WHERE name = 'vmA'`); err != nil {
		t.Fatalf("stamp epoch: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 9, status: MarkerValid}}},
		"h2": {},
	})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if lc := condLifecycle(s, kindEpochMismatch, "vmA"); lc != "" {
		t.Fatalf("valid equal marker raised owner_epoch_mismatch (lifecycle %q) — the ListVMs epoch column regression", lc)
	}

	// Control: an UNEQUAL marker on the owner does fire and confirms.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"},
			vmMarkers: map[string]markerInfo{"vmA": {epoch: 4, status: MarkerValid}}},
		"h2": {},
	})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindEpochMismatch, "vmA") {
		t.Fatal("an unequal marker on the DB owner must confirm owner_epoch_mismatch")
	}
}
