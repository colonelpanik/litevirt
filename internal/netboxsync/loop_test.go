package netboxsync

import (
	"context"
	"strings"
	"sync"
	"testing"

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

// seedMirrorableVM writes the rows one running VM with one NIC leaves behind,
// plus the `cluster` row every identity is derived from.
func seedMirrorableVM(t *testing.T, r *Reconciler, name, uuid, mac string) {
	t.Helper()
	ctx := context.Background()
	if err := r.db.Execute(ctx,
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES ('default', 'unit', 'unit.local', 'ca-pem', ?, ?)
		 ON CONFLICT(id) DO UPDATE SET ca_cert = excluded.ca_cert`,
		r.db.NowWall(), r.db.NowWall()); err != nil {
		t.Fatalf("seed cluster row: %v", err)
	}
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
