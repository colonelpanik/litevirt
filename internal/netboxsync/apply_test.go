package netboxsync

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

func TestApplySearchesBeforeCreating(t *testing.T) {
	nb := &stubVirt{
		// The object EXISTS in NetBox but has no local mapping — the exact state
		// left by a timeout after creation but before the identity-map write.
		byIdentity: map[string][]int{vmIdent("uuid-1"): {11}},
	}
	r := newTestReconciler(t, nb)

	id := netbox.Identity(fp, "uuid-1", "")
	err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: id}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1"}}, fp),
		fp,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nb.createCalls != 0 {
		t.Fatal("must adopt the existing object, not create a duplicate")
	}
	if ref := mustGetRef(t, r, "vm", id); ref.NetBoxID != 11 {
		t.Fatalf("must record the adopted id, got %+v", ref)
	}
}

func TestApplyDeleteUsesTheActionsObjectID(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	id := netbox.Identity(fp, "uuid-gone", "")

	// A delete action carries its NetBoxID: an identity alone cannot be deleted,
	// and re-resolving it here would be a second round trip that could observe
	// different state than the diff did.
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "delete", Key: id, NetBoxID: 11}},
		indexDesired(nil, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.deleted) != 1 || nb.deleted[0] != 11 {
		t.Fatalf("want VM 11 deleted, got %v", nb.deleted)
	}
	if ref, _ := getRef(r, "vm", id); ref != nil {
		t.Fatal("the identity mapping must be tombstoned with the object")
	}
}

func TestApplyDeletesADetachedInterface(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	id := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:01")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "delete", Key: id, NetBoxID: 21}},
		indexDesired(nil, fp), fp,
	); err != nil {
		t.Fatal(err)
	}
	// Without DeleteInterface, a hotplug detach never converges in NetBox.
	if len(nb.deletedInterfaces) != 1 || nb.deletedInterfaces[0] != 21 {
		t.Fatalf("want interface 21 deleted, got %v", nb.deletedInterfaces)
	}
	if ref, _ := getRef(r, "nic", id); ref != nil {
		t.Fatal("the identity mapping must be tombstoned with the interface")
	}
}

func TestApplyDeduplicatesKeepingOldest(t *testing.T) {
	nb := &stubVirt{byIdentity: map[string][]int{vmIdent("uuid-1"): {13, 11, 12}}}
	r := newTestReconciler(t, nb)

	id := netbox.Identity(fp, "uuid-1", "")
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: id}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1"}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	// NetBox offers no idempotency key, so a transient duplicate is possible.
	// The sweep is authoritative: keep the oldest, delete the rest.
	if len(nb.deleted) != 2 {
		t.Fatalf("want 2 duplicates deleted, got %v", nb.deleted)
	}
	if ref := mustGetRef(t, r, "vm", id); ref.NetBoxID != 11 {
		t.Fatalf("must keep the OLDEST object, got %+v", ref)
	}
	// Every duplicate is counted, so an operator sees the condition rather than
	// only its silent repair.
	if got := dupesCounted(t, r); got != 2 {
		t.Fatalf("litevirt_netbox_duplicate_objects_total incremented %d times, want 2", got)
	}
}

func TestVMCreateDoesNotCreateNICs(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	id := netbox.Identity(fp, "uuid-1", "")

	// Phase 2 owns every interface and Diff already emits a nic/create for each
	// one. Creating them here too would double the work and split interface
	// ownership across two phases, so a bug in either path would be masked by
	// the other.
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: id}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc", IP: "10.0.5.100", NetBoxIPID: 41}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	if nb.createCalls != 1 {
		t.Fatalf("want the VM created once, got %d", nb.createCalls)
	}
	if len(nb.createdInterfaces) != 0 {
		t.Fatalf("vm/create must never create interfaces, got %+v", nb.createdInterfaces)
	}
	if len(nb.ipAssignments) != 0 {
		t.Fatalf("vm/create must never assign addresses, got %+v", nb.ipAssignments)
	}
}

func TestNICCreateAssignsItsAddress(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)

	// Driven by nic/create, NOT vm/create: phase 0 creates only the VM, and Diff
	// emits no separate assign for a NIC that does not exist yet. Without an
	// assignment here a new NIC stays unassigned until a later sweep.
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")
	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc", IP: "10.0.5.100", NetBoxIPID: 41}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.createdInterfaces) != 1 || nb.createdInterfaces[0].VMID != 11 {
		t.Fatalf("interface must be created under the parent VM, got %+v", nb.createdInterfaces)
	}
	if len(nb.ipAssignments) != 1 {
		t.Fatalf("want exactly one assignment, got %v", nb.ipAssignments)
	}
	if got := nb.ipAssignments[0]; got.IPID != 41 || got.IfaceID != nb.createdInterfaces[0].ID {
		t.Fatalf("assignment = %+v, want IP 41 on the new interface", got)
	}
}

func TestNICCreateAdoptsAnExistingInterfaceThenAssigns(t *testing.T) {
	// The interface already exists in NetBox — a create whose identity-map write
	// was lost. Adopting must not mint a second interface, and the address must
	// still land on the adopted one.
	nb := &stubVirt{
		interfacesByIdentity: map[string][]int{
			netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc"): {21},
		},
	}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc", NetBoxIPID: 41}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatal(err)
	}
	if len(nb.createdInterfaces) != 0 {
		t.Fatalf("an existing interface must be adopted, not duplicated: %+v", nb.createdInterfaces)
	}
	if len(nb.ipAssignments) != 1 || nb.ipAssignments[0].IfaceID != 21 || nb.ipAssignments[0].IPID != 41 {
		t.Fatalf("want address 41 assigned to the adopted interface 21, got %v", nb.ipAssignments)
	}
	if ref := mustGetRef(t, r, "nic", nicID); ref.NetBoxID != 21 {
		t.Fatalf("the adopted id must be recorded, got %+v", ref)
	}
}

func TestNICCreateUsesActualParentWhenMappingIsLost(t *testing.T) {
	// The VM exists in NetBox but its netbox_objects row is gone, so Diff emits
	// no VM action and phase 0 records nothing. Phase ordering alone cannot
	// establish the parent; ParentNetBoxID from actual state can.
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: 11}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
		}}, fp),
		fp,
	); err != nil {
		t.Fatalf("a missing parent mapping must not fail the NIC create: %v", err)
	}
	if nb.createCalls != 0 {
		t.Fatal("the existing VM must not be duplicated")
	}
	if len(nb.createdInterfaces) != 1 || nb.createdInterfaces[0].VMID != 11 {
		t.Fatalf("want the interface created under VM 11, got %+v", nb.createdInterfaces)
	}
}

// TestNICCreateFallsBackToTheRecordedParent pins the OTHER half of the parent
// resolution: a NIC whose VM was created earlier in this sweep carries no
// ParentNetBoxID, because Diff read an actual state in which the VM did not
// exist. The netbox_objects row phase 0 wrote is the only link.
func TestNICCreateFallsBackToTheRecordedParent(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	vmID := netbox.Identity(fp, "uuid-1", "")
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")
	idx := indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
	}}, fp)

	// Phase 0, then phase 2 — the ordering the production runner uses.
	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: vmID}}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID}}, idx, fp); err != nil {
		t.Fatal(err)
	}
	created := mustGetRef(t, r, "vm", vmID).NetBoxID
	if len(nb.createdInterfaces) != 1 || nb.createdInterfaces[0].VMID != created {
		t.Fatalf("want the interface under the VM created this sweep (%d), got %+v", created, nb.createdInterfaces)
	}
}

// TestNICCreateRefusesWithNoResolvableParent pins that an unparented interface
// is never minted. NetBox would reject it anyway, but a create issued with
// virtual_machine 0 turns a recoverable "the mapping is lost" into an API error
// that says nothing about why.
func TestNICCreateRefusesWithNoResolvableParent(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	err := r.apply(context.Background(),
		[]Action{{Kind: "nic", Op: "create", Key: nicID}},
		indexDesired([]DesiredVM{{
			Name: "vm-1", UUID: "uuid-1",
			NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
		}}, fp),
		fp,
	)
	if err == nil {
		t.Fatal("want an error when no parent can be resolved")
	}
	if len(nb.createdInterfaces) != 0 {
		t.Fatalf("no interface may be created without a parent, got %+v", nb.createdInterfaces)
	}
}

// TestVMUpdateAndNICUpdateTargetTheActionsObject pins that both updates PATCH
// the id the diff resolved, and that the VM body carries the mirrored fields.
func TestVMUpdateAndNICUpdateTargetTheActionsObject(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	vmID := netbox.Identity(fp, "uuid-1", "")
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(), []Action{
		{Kind: "vm", Op: "update", Key: vmID, NetBoxID: 11},
		{Kind: "nic", Op: "update", Key: nicID, NetBoxID: 21, ParentNetBoxID: 11},
	}, indexDesired([]DesiredVM{{
		Name: "vm-1", UUID: "uuid-1", Status: "active", VCPUs: 2, MemoryMB: 2048,
		DiskGB: 20, DeviceID: 9,
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:cc"}},
	}}, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.updatedVMs) != 1 || nb.updatedVMs[0].ID != 11 {
		t.Fatalf("want VM 11 patched, got %+v", nb.updatedVMs)
	}
	got := nb.updatedVMs[0].VM
	if got.Name != "vm-1" || got.VCPUs != 2 || got.MemoryMB != 2048 ||
		got.DiskGB != 20 || got.Status != "active" || got.DeviceID != 9 || got.Identity != vmID {
		t.Fatalf("the update must carry every mirrored field, got %+v", got)
	}
	if len(nb.updatedIfaces) != 1 || nb.updatedIfaces[0].ID != 21 ||
		nb.updatedIfaces[0].Iface.Name != "eth0" {
		t.Fatalf("want interface 21 patched with the desired name, got %+v", nb.updatedIfaces)
	}
}

// TestAssignAndClearUseTheAddressID pins the two one-address actions. Clear
// takes the ADDRESS id — an interface id cannot detach anything — and Diff only
// ever carries a litevirt-owned address here.
func TestAssignAndClearUseTheAddressID(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	nicID := netbox.Identity(fp, "uuid-1", "52:54:00:aa:bb:cc")

	if err := r.apply(context.Background(), []Action{
		{Kind: "nic", Op: "assign", Key: nicID, NetBoxID: 21, IPID: 41},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: "nic", Op: "clear", Key: nicID, NetBoxID: 21, IPID: 42},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.ipAssignments) != 1 || nb.ipAssignments[0] != (ipAssignment{IPID: 41, IfaceID: 21}) {
		t.Fatalf("want address 41 assigned to interface 21, got %+v", nb.ipAssignments)
	}
	if len(nb.cleared) != 1 || nb.cleared[0] != 42 {
		t.Fatalf("want address 42 cleared, got %v", nb.cleared)
	}
}

// TestVMCreateSurvivesAnUnresolvableHostLink pins that the DCIM link is
// best-effort in BOTH directions: a lookup failure and a host that is simply
// not modelled must both leave a working mirror rather than failing the sweep.
func TestVMCreateSurvivesAnUnresolvableHostLink(t *testing.T) {
	nb := &stubVirt{deviceErr: errors.New("netbox: HTTP 500")}
	r := newTestReconciler(t, nb)

	if err := r.apply(context.Background(),
		[]Action{{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "uuid-1", "")}},
		indexDesired([]DesiredVM{{Name: "vm-1", UUID: "uuid-1", Host: "host-a"}}, fp),
		fp,
	); err != nil {
		t.Fatalf("an unresolvable host link must not fail the mirror: %v", err)
	}
	if len(nb.created) != 1 || nb.created[0].DeviceID != 0 {
		t.Fatalf("want the VM created with no device link, got %+v", nb.created)
	}
}

// TestApplyAppliesEveryActionInABatch exercises the worker pool: a batch is
// applied concurrently, so every action must still land exactly once.
func TestApplyAppliesEveryActionInABatch(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)

	var desired []DesiredVM
	var actions []Action
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5", "u6"} {
		desired = append(desired, DesiredVM{Name: "vm-" + u, UUID: u})
		actions = append(actions, Action{Kind: "vm", Op: "create", Key: netbox.Identity(fp, u, "")})
	}
	if err := r.apply(context.Background(), actions, indexDesired(desired, fp), fp); err != nil {
		t.Fatal(err)
	}
	if nb.createCalls != len(actions) {
		t.Fatalf("want %d VMs created, got %d", len(actions), nb.createCalls)
	}
	for _, d := range desired {
		if ref := mustGetRef(t, r, "vm", netbox.Identity(fp, d.UUID, "")); ref.NetBoxID == 0 {
			t.Fatalf("no mapping recorded for %s", d.UUID)
		}
	}
}

// TestApplyReportsAFailedActionWithoutSkippingTheRest pins that one failure
// does not silently abandon a batch's other actions, which are independent.
func TestApplyReportsAFailedActionWithoutSkippingTheRest(t *testing.T) {
	nb := &stubVirt{createErr: map[string]error{netbox.Identity(fp, "u1", ""): errors.New("boom")}}
	r := newTestReconciler(t, nb)

	err := r.apply(context.Background(), []Action{
		{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "u1", "")},
		{Kind: "vm", Op: "create", Key: netbox.Identity(fp, "u2", "")},
	}, indexDesired([]DesiredVM{
		{Name: "vm-1", UUID: "u1"}, {Name: "vm-2", UUID: "u2"},
	}, fp), fp)
	if err == nil {
		t.Fatal("a failed action must be reported")
	}
	if ref, _ := getRef(r, "vm", netbox.Identity(fp, "u2", "")); ref == nil {
		t.Fatal("the other action in the batch must still have been applied")
	}
}

// --- helpers ---------------------------------------------------------------

// newTestReconciler builds a reconciler over a real in-memory corrosion DB, so
// every identity mapping goes through the production SQL rather than a map.
func newTestReconciler(t *testing.T, nb netboxWriter) *Reconciler {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Reconciler{nb: nb, db: db, clusterID: 5, metrics: &countingMetrics{}}
}

func getRef(r *Reconciler, kind, key string) (*corrosion.ObjectRef, error) {
	return corrosion.GetObjectRef(context.Background(), r.db, kind, key)
}

func mustGetRef(t *testing.T, r *Reconciler, kind, key string) corrosion.ObjectRef {
	t.Helper()
	ref, err := getRef(r, kind, key)
	if err != nil {
		t.Fatal(err)
	}
	if ref == nil {
		t.Fatalf("no %s mapping recorded for %s", kind, key)
	}
	return *ref
}

func dupesCounted(t *testing.T, r *Reconciler) int {
	t.Helper()
	m, ok := r.metrics.(*countingMetrics)
	if !ok {
		t.Fatalf("metrics sink is %T, want *countingMetrics", r.metrics)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dupes
}

// countingMetrics is the test sink. The production one is process-global
// Prometheus state, which cannot be asserted on per test.
type countingMetrics struct {
	mu    sync.Mutex
	dupes int
}

func (m *countingMetrics) IncDuplicateObject() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dupes++
}

type updatedVM struct {
	ID int
	VM netbox.VirtualMachine
}

type updatedIface struct {
	ID    int
	Iface netbox.VMInterface
}

type ipAssignment struct {
	IPID    int
	IfaceID int
}

// stubVirt is an in-memory NetBox. It is mutex-guarded because apply runs a
// worker pool.
type stubVirt struct {
	mu sync.Mutex

	// byIdentity and interfacesByIdentity are what a search finds — the state a
	// create whose identity-map write was lost leaves behind.
	byIdentity           map[string][]int
	interfacesByIdentity map[string][]int
	devices              map[string]int
	deviceErr            error
	createErr            map[string]error

	createCalls       int
	created           []netbox.VirtualMachine
	updatedVMs        []updatedVM
	deleted           []int
	createdInterfaces []netbox.VMInterface
	updatedIfaces     []updatedIface
	deletedInterfaces []int
	ipAssignments     []ipAssignment
	cleared           []int
	deviceLookups     []string

	nextID int
}

// nextObjectID mints ids well above the fixtures' hand-picked ones, so a test
// asserting on a created object's id cannot accidentally match a fixture.
func (s *stubVirt) nextObjectID() int {
	s.nextID++
	return 100 + s.nextID
}

func (s *stubVirt) FindVMByIdentity(_ context.Context, identity string) ([]netbox.VirtualMachine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netbox.VirtualMachine
	for _, id := range s.byIdentity[identity] {
		out = append(out, netbox.VirtualMachine{ID: id, Identity: identity})
	}
	return out, nil
}

func (s *stubVirt) CreateVM(_ context.Context, vm netbox.VirtualMachine) (netbox.VirtualMachine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.createErr[vm.Identity]; err != nil {
		return netbox.VirtualMachine{}, err
	}
	s.createCalls++
	vm.ID = s.nextObjectID()
	s.created = append(s.created, vm)
	return vm, nil
}

func (s *stubVirt) UpdateVM(_ context.Context, id int, vm netbox.VirtualMachine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updatedVMs = append(s.updatedVMs, updatedVM{ID: id, VM: vm})
	return nil
}

func (s *stubVirt) DeleteVM(_ context.Context, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, id)
	return nil
}

func (s *stubVirt) FindInterfaceByIdentity(_ context.Context, identity string) ([]netbox.VMInterface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netbox.VMInterface
	for _, id := range s.interfacesByIdentity[identity] {
		out = append(out, netbox.VMInterface{ID: id, Identity: identity})
	}
	return out, nil
}

func (s *stubVirt) CreateInterface(_ context.Context, i netbox.VMInterface) (netbox.VMInterface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i.ID = s.nextObjectID()
	s.createdInterfaces = append(s.createdInterfaces, i)
	return i, nil
}

func (s *stubVirt) UpdateInterface(_ context.Context, id int, i netbox.VMInterface) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updatedIfaces = append(s.updatedIfaces, updatedIface{ID: id, Iface: i})
	return nil
}

func (s *stubVirt) DeleteInterface(_ context.Context, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletedInterfaces = append(s.deletedInterfaces, id)
	return nil
}

func (s *stubVirt) AssignIPToInterface(_ context.Context, ipID, ifaceID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipAssignments = append(s.ipAssignments, ipAssignment{IPID: ipID, IfaceID: ifaceID})
	return nil
}

func (s *stubVirt) ClearIPAssignment(_ context.Context, ipID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleared = append(s.cleared, ipID)
	return nil
}

func (s *stubVirt) FindDeviceByName(_ context.Context, name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLookups = append(s.deviceLookups, name)
	if s.deviceErr != nil {
		return 0, s.deviceErr
	}
	return s.devices[name], nil
}

// The collection half of the interface. The applier never reads through it —
// Reconciler.actualState does — but it is one interface so a fake cannot
// satisfy the writes while a second, drifting path serves the reads.
func (s *stubVirt) ListVMsByCluster(context.Context, int) ([]netbox.VirtualMachine, error) {
	return nil, nil
}

func (s *stubVirt) ListInterfacesByCluster(context.Context, int) ([]netbox.VMInterface, error) {
	return nil, nil
}

func (s *stubVirt) ListOwnedIPsForInterfaces(context.Context, []int) ([]netbox.IPAddress, error) {
	return nil, nil
}
