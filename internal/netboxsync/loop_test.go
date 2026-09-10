package netboxsync

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// fpLoop is the cluster fingerprint every fixture here builds identities under.
const fpLoop = "abc123"

func TestApplyPhasesRunsClearsBeforeAssignments(t *testing.T) {
	// Address 41 moves from NIC A (interface 21) to NIC B (interface 22): A
	// emits clear 41, B emits assign 41. Flattened into one batch, the worker
	// pool can run the assign first and the clear then detaches what was just
	// correctly attached.
	//
	// This drives the PRODUCTION runner, applyPhases. A test that looped over
	// Phases() itself could not catch applyPhases flattening the list or
	// skipping a boundary, because the loop would supply the ordering it claims
	// to verify.
	//
	// No forced scheduling. A barrier that pins the UNSAFE order deadlocks under
	// correct phasing — assign cannot start until clear returns — and one that
	// pins the safe order would mask a collapse entirely. The deterministic
	// anti-collapse guard is Task 3's Phase(clear) < Phase(assign) inequality;
	// this test covers the different failure of orchestration bypassing phases.
	//
	// SEVERAL moves, not one. Under correct phasing the boundary is absolute, so
	// the count changes nothing; under a collapsed one it is the difference
	// between a coin flip and a near-certainty, because EVERY clear would have to
	// win its race against EVERY assign for the violation to go unseen.
	const moves = 5
	initial := map[int]int{}
	var actions []Action
	for i := range moves {
		initial[40+i] = 20 + i
		actions = append(actions, Action{
			Kind: "nic", Op: "assign", Key: "nic-to", NetBoxID: 30 + i, IPID: 40 + i,
		})
	}
	for i := range moves {
		actions = append(actions, Action{
			Kind: "nic", Op: "clear", Key: "nic-from", NetBoxID: 20 + i, IPID: 40 + i,
		})
	}
	nb := newRecordingNetBox(initial)
	r := newTestReconciler(t, nb)

	if err := r.applyPhases(context.Background(), actions, indexDesired(nil, fpLoop), fpLoop); err != nil {
		t.Fatal(err)
	}

	// Every clear must appear before every assign in the recorded call log.
	// Actions are deliberately supplied assign-first, so a runner that ignored
	// phases would preserve that order and fail here.
	firstAssign, lastClear := -1, -1
	for i, c := range nb.Calls() {
		switch c.Op {
		case "assign":
			if firstAssign < 0 {
				firstAssign = i
			}
		case "clear":
			lastClear = i
		}
	}
	if firstAssign < 0 || lastClear < 0 {
		t.Fatalf("want both a clear and an assign, got %+v", nb.Calls())
	}
	if lastClear > firstAssign {
		t.Fatalf("clears must run before assignments, got %+v", nb.Calls())
	}
	for i := range moves {
		if got := nb.AssignedInterfaceFor(40 + i); got != 30+i {
			t.Fatalf("address %d must end assigned to interface %d, got %d", 40+i, 30+i, got)
		}
	}
}

// TestApplyPhasesStopsWhenTheLeaseIsLost is the unit-level half of the
// per-batch re-validation: the runner must abandon the sweep at the batch
// boundary rather than finish it. The fleet scenario proves the same property
// end to end over a real lease.
func TestApplyPhasesStopsWhenTheLeaseIsLost(t *testing.T) {
	nb := newRecordingNetBox(nil)
	r := newTestReconciler(t, nb)
	r.holdsLease = func(context.Context) bool { return false }

	err := r.applyPhases(context.Background(), []Action{
		{Kind: "nic", Op: "clear", Key: "nic-a", NetBoxID: 21, IPID: 41},
	}, indexDesired(nil, fpLoop), fpLoop)
	if err == nil {
		t.Fatal("a lost lease must abandon the sweep, not complete it")
	}
	if len(nb.Calls()) != 0 {
		t.Fatalf("nothing may be written without the lease, got %+v", nb.Calls())
	}
}

// TestSyncRunsThroughApplyPhases pins that the PRODUCTION entry point goes
// through the phase runner, not around it.
//
// applyPhases is where both the per-batch lease re-validation and the phase
// boundaries live, so a Sync that called apply directly would be an ungated,
// unordered sweep — and every ordering test in this file would keep passing,
// because they call applyPhases by name. Driving Sync with the lease already
// lost is what tells the two apart: the phased runner refuses before the first
// batch and writes nothing.
func TestSyncRunsThroughApplyPhases(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := newTestReconciler(t, nb)
	r.holdsLease = func(context.Context) bool { return false }
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")

	err := r.Sync(context.Background())
	if err == nil {
		t.Fatal("a sweep with no lease must be refused, not completed")
	}
	if !strings.Contains(err.Error(), "lease") {
		t.Fatalf("the error must name the lost lease, got %v", err)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.created) != 0 || len(nb.createdInterfaces) != 0 {
		t.Fatalf("nothing may be written without the lease, created %v / %v",
			nb.created, nb.createdInterfaces)
	}
}

// TestSyncMirrorsWhatLitevirtHolds is the positive control for the above: with
// the lease held, the same fixture reaches NetBox. Without it, a Sync that
// silently produced an EMPTY desired set would satisfy every "nothing was
// written" assertion in this file.
func TestSyncMirrorsWhatLitevirtHolds(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := newTestReconciler(t, nb)
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.created) != 1 {
		t.Fatalf("want one VM mirrored, got %+v", nb.created)
	}
	if got := nb.created[0]; got.Name != "vm-1" || got.Status != "active" || got.VCPUs != 2 || got.MemoryMB != 1024 {
		t.Fatalf("mirrored VM = %+v, want name vm-1 / status active / 2 vCPU / 1024 MiB", got)
	}
	if len(nb.createdInterfaces) != 1 {
		t.Fatalf("want one interface mirrored, got %+v", nb.createdInterfaces)
	}
	if got := nb.createdInterfaces[0]; got.Name != "eth0" || got.MAC != "52:54:00:aa:bb:cc" {
		t.Fatalf("mirrored interface = %+v, want eth0 with the NIC's MAC", got)
	}
}

// TestCreateInterfaceFailsWhenMACIsNotEchoed pins the fail-closed check on the
// created object.
//
// DRF silently IGNORES unknown write fields. On a NetBox that has moved MACs to
// their own model, `mac_address` on a vminterface write is accepted, dropped,
// and echoed back empty — so every interface would be created MAC-less. The
// identity is MAC-derived, so nothing downstream can notice: the mirror would
// keep writing interfaces that never carry the value it keyed them on. Refusing
// the create is the only outcome that surfaces it.
func TestCreateInterfaceFailsWhenMACIsNotEchoed(t *testing.T) {
	const mac = "52:54:00:aa:bb:cc"
	nb := &stubVirt{
		byIdentity:      map[string][]int{},
		dropMACOnCreate: true,
	}
	r := newTestReconciler(t, nb)

	key := netbox.Identity(fpLoop, "uuid-1", mac)
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: mac}},
	}}, fpLoop)

	err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: key, ParentNetBoxID: 11}}, idx, fpLoop)
	if err == nil {
		t.Fatal("a NetBox that dropped mac_address must fail the create, not be trusted")
	}
	if !strings.Contains(err.Error(), "mac") {
		t.Fatalf("the error must name the MAC echo, got %v", err)
	}
	// Nothing may be recorded: a mapping written here would adopt the MAC-less
	// object forever.
	ref, rerr := getRef(r, kindNIC, key)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if ref != nil {
		t.Fatalf("a refused create must record no mapping, got %+v", ref)
	}
}

// TestCreateInterfaceAcceptsAnUpperCasedMACEcho is the negative control: NetBox
// echoes a MAC UPPER-cased, so a case-sensitive equality check would refuse
// every create against a real server.
func TestCreateInterfaceAcceptsAnUpperCasedMACEcho(t *testing.T) {
	const mac = "52:54:00:aa:bb:cc"
	nb := &stubVirt{byIdentity: map[string][]int{}, upperCaseMACEcho: true}
	r := newTestReconciler(t, nb)

	key := netbox.Identity(fpLoop, "uuid-1", mac)
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: mac}},
	}}, fpLoop)

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: key, ParentNetBoxID: 11}}, idx, fpLoop); err != nil {
		t.Fatalf("an upper-cased echo is what NetBox returns and must be accepted: %v", err)
	}
}

// seedClusterRow writes the `cluster` row every identity is derived from, and
// nothing else.
//
// Separate from seedMirrorableVM because a scenario about an EMPTY desired
// state still needs a derivable fingerprint: without the row the sweep fails at
// the fingerprint read and never reaches the diff it is about.
func seedClusterRow(t *testing.T, r *Reconciler) {
	t.Helper()
	if err := r.db.Execute(context.Background(),
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES ('default', 'unit', 'unit.local', 'ca-pem', ?, ?)
		 ON CONFLICT(id) DO UPDATE SET ca_cert = excluded.ca_cert`,
		r.db.NowWall(), r.db.NowWall()); err != nil {
		t.Fatalf("seed cluster row: %v", err)
	}
}

// seedMirroredObjectRef writes the `netbox_objects` mapping row the mirror's own
// createVM records when it puts a virtual_machine into NetBox.
//
// A FIXTURE THAT PRE-POPULATES NETBOX HAS TO WRITE THIS TOO, or it models a
// state no cluster reaches: an object under this cluster's identity exists only
// because this cluster's mirror created it, and that write and the mapping row
// are the same operation. Leaving it out understates what a caught-up node
// holds, and the vm/replace premise reads exactly this row for the one
// incarnation whose `vms` tombstone a same-name re-create purges.
//
// It is a REPLICATED row, so a node that has not hydrated does not hold it —
// which is why the partial-read fixtures deliberately do NOT call this, and the
// fully-hydrated ones do.
func seedMirroredObjectRef(t *testing.T, r *Reconciler, identity string, netboxID int) {
	t.Helper()
	if err := corrosion.PutObjectRef(context.Background(), r.db, corrosion.ObjectRef{
		LitevirtKind: kindVM, LitevirtKey: identity,
		NetBoxKind: netboxKindVM, NetBoxID: netboxID,
	}); err != nil {
		t.Fatalf("seed object ref %s: %v", identity, err)
	}
}

// seedMirrorableVM writes the rows one running VM with one NIC leaves behind,
// plus the `cluster` row every identity is derived from.
func seedMirrorableVM(t *testing.T, r *Reconciler, name, uuid, mac string) {
	t.Helper()
	ctx := context.Background()
	seedClusterRow(t, r)
	if err := corrosion.InsertVM(ctx, r.db, corrosion.VMRecord{
		Name:     name,
		HostName: "host-a",
		State:    "running",
		Spec:     `{"uuid":"` + uuid + `","cpu":2,"memory_mib":1024}`,
	}, []corrosion.InterfaceRecord{{
		VMName: name, NetworkName: "bound", Ordinal: 0, MAC: mac, IP: "10.0.5.100",
	}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
}

// --- the recording fake ------------------------------------------------------

// netboxCall is one recorded mutation, in the order the client issued it.
type netboxCall struct {
	Op      string // "assign" | "clear"
	IPID    int
	IfaceID int
}

// recordingNetBox records assignment mutations and their order.
//
// It does NOT reorder anything. Forced scheduling cannot work here: a barrier
// pinning the unsafe order deadlocks under correct phasing, because assign
// cannot begin until clear returns; one pinning the safe order would hide a
// collapse. Recording order and asserting on it is both sufficient and
// terminating.
type recordingNetBox struct {
	mu       sync.Mutex
	calls    []netboxCall
	assigned map[int]int // address id -> interface id
}

func newRecordingNetBox(initial map[int]int) *recordingNetBox {
	m := map[int]int{}
	for k, v := range initial {
		m[k] = v
	}
	return &recordingNetBox{assigned: m}
}

func (f *recordingNetBox) AssignIPToInterface(_ context.Context, ipID, ifaceID int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, netboxCall{Op: "assign", IPID: ipID, IfaceID: ifaceID})
	f.assigned[ipID] = ifaceID
	return nil
}

func (f *recordingNetBox) ClearIPAssignment(_ context.Context, ipID int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, netboxCall{Op: "clear", IPID: ipID})
	delete(f.assigned, ipID)
	return nil
}

func (f *recordingNetBox) Calls() []netboxCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netboxCall(nil), f.calls...)
}

// AssignedInterfaceFor returns the interface holding an address, or 0.
func (f *recordingNetBox) AssignedInterfaceFor(ipID int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assigned[ipID]
}

// The rest of netboxWriter. Every method is a no-op: this fake exists to record
// ORDER on the assignment pair, and an accidental call to any other method
// would be a different bug, caught by the tests that do assert on them.
func (f *recordingNetBox) FindVMByIdentity(context.Context, string) ([]netbox.VirtualMachine, error) {
	return nil, nil
}

func (f *recordingNetBox) CreateVM(_ context.Context, vm netbox.VirtualMachine) (netbox.VirtualMachine, error) {
	return vm, nil
}
func (f *recordingNetBox) UpdateVM(context.Context, int, netbox.VirtualMachine) error { return nil }
func (f *recordingNetBox) DeleteVM(context.Context, int) error                        { return nil }

func (f *recordingNetBox) FindInterfaceByIdentity(context.Context, string) ([]netbox.VMInterface, error) {
	return nil, nil
}

func (f *recordingNetBox) CreateInterface(_ context.Context, i netbox.VMInterface) (netbox.VMInterface, error) {
	return i, nil
}
func (f *recordingNetBox) UpdateInterface(context.Context, int, netbox.VMInterface) error { return nil }
func (f *recordingNetBox) DeleteInterface(context.Context, int) error                     { return nil }
func (f *recordingNetBox) FindDeviceByName(context.Context, string) (int, error)          { return 0, nil }
func (f *recordingNetBox) EnsureClusterType(context.Context, string) (int, error)         { return 1, nil }
func (f *recordingNetBox) EnsureCluster(context.Context, string, int) (int, error)        { return 2, nil }

func (f *recordingNetBox) ListVMsByCluster(context.Context, int) ([]netbox.VirtualMachine, error) {
	return nil, nil
}

func (f *recordingNetBox) ListInterfacesByCluster(context.Context, int) ([]netbox.VMInterface, error) {
	return nil, nil
}

func (f *recordingNetBox) ListOwnedIPsForInterfaces(context.Context, []int) ([]netbox.IPAddress, error) {
	return nil, nil
}

// --- the fast poll -----------------------------------------------------------
//
// The poll exists so a delete does not sit in NetBox for a whole sweep interval.
// It is deliberately the WEAKER of the two cadences: it accelerates the node
// that already holds the lease and it can only ever cause a sweep the slow tick
// would have run anyway, so every scenario below is about what it must NOT do —
// acquire, write, or sweep when there is nothing to sweep for.

// TestQueuedWorkSweepsBeforeTheSlowTick is the poll's whole reason to exist: a
// queued item must reach NetBox on the fast cadence, not the slow one.
//
// It also pins the ack, which is the poll's termination condition: an item the
// sweep covered but never tombstoned would make every later poll sweep again
// forever.
func TestQueuedWorkSweepsBeforeTheSlowTick(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{HoldsLease: leaseHeld})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")
	enqueueMirrorWork(t, r, "vm-1")

	firePoll(t, r)

	if got := nb.Sweeps(); got == 0 {
		t.Fatal("queued work must sweep on the poll tick, not wait out the sweep interval")
	}
	nb.mu.Lock()
	created := len(nb.created)
	nb.mu.Unlock()
	if created != 1 {
		t.Fatalf("the poll's sweep mirrored %d VMs, want 1 — it must run the FULL sweep", created)
	}
	if got := pendingMirrorWork(t, r); got != 0 {
		t.Fatalf("%d items still queued after a successful sweep — the ack never ran, so every "+
			"later poll would sweep again forever", got)
	}
}

// TestIdlePollDoesNotSweepOrWrite is the cost bound.
//
// Every configured node runs this loop on the fast cadence, so a poll that swept
// unconditionally would be a full NetBox reconciliation per node per minute, and
// one that acquired would be a replicated lease write per node per minute. On an
// idle cluster the poll must be one local SELECT and nothing else.
//
// The fixture holds a VM the sweep WOULD mirror, so "nothing was written" is a
// statement about the poll rather than about an empty cluster.
func TestIdlePollDoesNotSweepOrWrite(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{HoldsLease: leaseHeld})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")
	// The queue is deliberately EMPTY. pollingReconciler's AcquireLease fails
	// the test if it is called, which is the "no lease write" half.

	firePoll(t, r)

	if got := nb.Sweeps(); got != 0 {
		t.Fatalf("an empty queue ran %d sweeps, want 0 — the poll must peek before it sweeps", got)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.created) != 0 || len(nb.createdInterfaces) != 0 {
		t.Fatalf("an idle poll wrote to NetBox: %v / %v", nb.created, nb.createdInterfaces)
	}
}

// TestNonLeaderPollDoesNothing is the fail-closed direction on the fast path.
//
// Every node runs this loop and they all see the same queue. The lease READ is
// what stops the ones that do not lead, and it comes FIRST — before the peek —
// so a non-leader reaches the end of the tick having neither written to NetBox
// nor consumed the item the leader still needs to see.
func TestNonLeaderPollDoesNothing(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{HoldsLease: func(context.Context) bool { return false }})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")
	enqueueMirrorWork(t, r, "vm-1")

	firePoll(t, r)

	if got := nb.Sweeps(); got != 0 {
		t.Fatalf("a non-leader ran %d sweeps, want 0", got)
	}
	nb.mu.Lock()
	wrote := len(nb.created) + len(nb.createdInterfaces) + len(nb.updatedVMs) + len(nb.deleted)
	nb.mu.Unlock()
	if wrote != 0 {
		t.Fatalf("a non-leader made %d NetBox writes, want 0", wrote)
	}
	if got := pendingMirrorWork(t, r); got != 1 {
		t.Fatalf("queued items = %d, want 1 — a non-leader must not consume the leader's trigger", got)
	}
}

// TestFailedSweepKeepsTheQueueItem pins the ack ORDER.
//
// The item is the trigger, and a sweep that failed did not do the work it was
// triggered for. Acking first — which is what the drain used to do — throws the
// trigger away on exactly the passes that achieved nothing, so the next poll
// finds an empty queue and the change waits out the whole sweep interval.
func TestFailedSweepKeepsTheQueueItem(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{}}
	r := pollingReconciler(t, nb, Options{HoldsLease: leaseHeld})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")
	enqueueMirrorWork(t, r, "vm-1")

	// Fail the sweep where a real NetBox does — on the write, after the reads —
	// so the pass genuinely reaches the end and returns an error, rather than
	// being turned back at the door.
	fp, err := corrosion.ClusterFingerprint(context.Background(), r.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	nb.createErr = map[string]error{
		netbox.Identity(fp, "uuid-1", ""): errors.New("netbox refused the create"),
	}

	firePoll(t, r)

	if got := nb.Sweeps(); got == 0 {
		t.Fatal("the sweep never ran, so this proves nothing about a FAILED one")
	}
	nb.mu.Lock()
	created := len(nb.created)
	nb.mu.Unlock()
	if created != 0 {
		t.Fatalf("the create was supposed to fail, but %d VMs were mirrored", created)
	}
	if got := pendingMirrorWork(t, r); got != 1 {
		t.Fatalf("queued items = %d, want 1 — a failed sweep must leave its trigger for the next poll", got)
	}
}

// TestRunPollsOnItsOwnTicker is the wiring assertion.
//
// Every scenario above drives run() with a tick the test supplies, so all of
// them would still pass if Run itself started only the sweep ticker — the poll
// would exist and never fire. Here the SWEEP tick is an hour away, so only the
// production poll ticker can produce a pass.
func TestRunPollsOnItsOwnTicker(t *testing.T) {
	nb := &sweepSignal{stubVirt: &stubVirt{byIdentity: map[string][]int{}}, fired: make(chan struct{}, 1)}
	r := pollingReconciler(t, nb, Options{
		HoldsLease:   leaseHeld,
		Interval:     time.Hour,
		PollInterval: time.Millisecond,
	})
	seedMirrorableVM(t, r, "vm-1", "uuid-1", "52:54:00:aa:bb:cc")
	enqueueMirrorWork(t, r, "vm-1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()

	select {
	case <-nb.fired:
	case <-time.After(10 * time.Second):
		t.Fatal("no sweep within 10s of queued work — Run is not ticking the poll")
	}
	cancel()
	<-done
}

// TestNewClampsThePollToTheSweep pins the two cadence defaults.
//
// The clamp is not cosmetic: a poll slower than the sweep it anticipates can
// never be the thing that notices a change, so an operator who lengthened the
// poll past the sweep would silently get a mirror with no fast path at all.
func TestNewClampsThePollToTheSweep(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       Options
		interval time.Duration
		poll     time.Duration
	}{
		{"defaults", Options{}, defaultInterval, defaultPollInterval},
		{"explicit", Options{Interval: time.Hour, PollInterval: 5 * time.Second}, time.Hour, 5 * time.Second},
		{"a poll slower than the sweep is clamped",
			Options{Interval: time.Minute, PollInterval: time.Hour}, time.Minute, time.Minute},
		{"a sweep faster than the default poll clamps the default",
			Options{Interval: 5 * time.Second}, 5 * time.Second, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(tc.in)
			if r.interval != tc.interval || r.pollInterval != tc.poll {
				t.Fatalf("New(%+v) = interval %v / poll %v, want %v / %v",
					tc.in, r.interval, r.pollInterval, tc.interval, tc.poll)
			}
		})
	}
}

// --- poll fixtures -----------------------------------------------------------

// leaseHeld is the lease READ of a node that leads.
func leaseHeld(context.Context) bool { return true }

// pollingReconciler builds a reconciler through New — the PRODUCTION
// constructor, so both cadences and the clamp are the real ones.
//
// AcquireLease is wired to fail the test unless a scenario overrides it. The
// poll must never acquire: it accelerates a lease this node already holds, and
// an acquire on the fast cadence is exactly the replicated write per node per
// minute the design removes.
func pollingReconciler(t *testing.T, nb netboxWriter, o Options) *Reconciler {
	t.Helper()
	o.NetBox = nb
	o.DB = newMirrorDB(t)
	o.Metrics = &countingMetrics{}
	if o.AcquireLease == nil {
		o.AcquireLease = func(context.Context) bool {
			t.Errorf("the poll took the leader lease; only the sweep tick may acquire")
			return true
		}
	}
	if o.Latched == nil {
		// Latched by default: every scenario here is about something other than
		// the capability gate, and an unwired predicate is fail-closed, so
		// leaving it nil would make each of them pass vacuously. The gate's own
		// scenarios (latch_test.go) set it explicitly, and the nil default is
		// pinned there against a bare New.
		o.Latched = leaseHeld
	}
	return New(o)
}

// firePoll drives poll ticks through the PRODUCTION loop and returns once at
// least one has run to completion.
//
// Deterministic, with no sleep. The tick channel is unbuffered, so the first
// send returns only once the loop has taken the tick, and the second returns
// only once the loop is back in its select — which is the barrier proving the
// first tick finished. The second tick is a repeat of the first and every
// scenario here asserts a property that holds for one poll or two; cancelling
// instead of sending the barrier would cancel the context the first poll is
// still using and turn a failed assertion into a failed sweep.
//
// The sweep channel is nil, which blocks forever: only the poll can fire, so
// nothing here can reach the acquire by another route.
func firePoll(t *testing.T, r *Reconciler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	poll := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); r.run(ctx, nil, poll) }()
	poll <- time.Now()
	poll <- time.Now()
	cancel()
	<-done
}

// enqueueMirrorWork records the latency shortcut a VM lifecycle path leaves.
func enqueueMirrorWork(t *testing.T, r *Reconciler, key string) {
	t.Helper()
	if err := corrosion.EnqueueSync(context.Background(), r.db, QueueKind, key, "upsert"); err != nil {
		t.Fatalf("EnqueueSync: %v", err)
	}
}

// pendingMirrorWork counts this mirror's un-acked queue items.
func pendingMirrorWork(t *testing.T, r *Reconciler) int {
	t.Helper()
	items, err := corrosion.DrainSyncQueue(context.Background(), r.db, QueueKind, 100)
	if err != nil {
		t.Fatalf("DrainSyncQueue: %v", err)
	}
	return len(items)
}

// sweepSignal announces each sweep on a channel, so a scenario driving the real
// Run can WAIT for the poll to fire rather than sleep past its cadence.
type sweepSignal struct {
	*stubVirt
	fired chan struct{}
}

func (s *sweepSignal) EnsureCluster(ctx context.Context, name string, typeID int) (int, error) {
	select {
	case s.fired <- struct{}{}:
	default: // already announced; the waiter only needs the first
	}
	return s.stubVirt.EnsureCluster(ctx, name, typeID)
}
