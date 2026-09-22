package health

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// specUUID reads the uuid out of a stored spec.
func specUUID(t *testing.T, spec string) string {
	t.Helper()
	var m struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(spec), &m); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	return m.UUID
}

// TestMaybeBackfillUUID_AdoptsTheDomainUUIDPreservingSpec is the backfill for
// VMs created before litevirt recorded a uuid in the spec.
//
// The uuid is what makes an identity incarnation-unique, so a VM without one
// cannot be named in NetBox at all — and, worse, its absence is indistinguishable
// from the VM having been destroyed, which is why the inventory mirror withholds
// EVERY delete while any such VM exists. libvirt minted a uuid for the domain
// regardless, so the persistent XML on the owning host is the authority.
func TestMaybeBackfillUUID_AdoptsTheDomainUUIDPreservingSpec(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// A legacy spec: no uuid, plus fields that must survive the edit untouched.
	spec := `{"name":"vm1","machine":"pc-q35-9.0","cpu":4,"memory_mib":2048,"firmware":"uefi"}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: spec, State: "running", CPUActual: 4, MemActual: 2048},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fake := libvirtfake.New()
	if err := fake.DefineDomain(
		`<domain><name>vm1</name><uuid>5113ced7-9006-4086-b7dd-9d1840181e03</uuid>` +
			`<os><type machine="pc-q35-9.0">hvm</type></os></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	r.maybeBackfillUUID(ctx, corrosion.VMRecord{Name: "vm1", Spec: spec, CPUActual: 4, MemActual: 2048})

	got, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if u := specUUID(t, got.Spec); u != "5113ced7-9006-4086-b7dd-9d1840181e03" {
		t.Errorf("uuid = %q, want the domain's", u)
	}

	var m struct {
		Name      string `json:"name"`
		Machine   string `json:"machine"`
		CPU       int    `json:"cpu"`
		MemoryMiB int    `json:"memory_mib"`
		Firmware  string `json:"firmware"`
	}
	if err := json.Unmarshal([]byte(got.Spec), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Name != "vm1" || m.Machine != "pc-q35-9.0" || m.CPU != 4 || m.MemoryMiB != 2048 || m.Firmware != "uefi" {
		t.Errorf("backfill perturbed other spec fields: %+v", m)
	}
}

// TestMaybeBackfillUUID_NeverRewritesAnExistingUUID is the one thing this must
// never do. A VM's uuid is its identity across incarnations; rewriting it would
// silently orphan every NetBox object already stamped with the old value and
// make the mirror create a duplicate under the new one.
func TestMaybeBackfillUUID_NeverRewritesAnExistingUUID(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	const stored = "11111111-2222-3333-4444-555555555555"
	spec := `{"name":"vm1","uuid":"` + stored + `","cpu":2}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: spec, State: "running"},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// libvirt reports a DIFFERENT uuid — a redefined domain, a restore, an
	// import. The stored value still wins: it is the identity others already
	// hold.
	fake := libvirtfake.New()
	if err := fake.DefineDomain(
		`<domain><name>vm1</name><uuid>99999999-8888-7777-6666-555555555555</uuid></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	r.maybeBackfillUUID(ctx, corrosion.VMRecord{Name: "vm1", Spec: spec})

	got, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if u := specUUID(t, got.Spec); u != stored {
		t.Fatalf("uuid = %q, want the stored %q left alone — rewriting it orphans "+
			"every object already stamped with it", u, stored)
	}
}

// TestSweepBacksFillUUIDForAnErroredVM: an errored VM is still a defined domain
// with a readable uuid, and it is no less invisible to the mirror for being in
// error — its unreadable record blocks every mirror delete cluster-wide exactly
// as a running one's would.
//
// Driven through the SWEEP rather than by calling the backfill directly,
// because the defect this pins is a missing CALL SITE: the backfill itself was
// correct and its direct-call tests passed while an errored VM was never
// offered to it. A test that invoked maybeBackfillUUID by hand could not see
// that, which is the same vacuity the projection tests exist to avoid.
func TestSweepBacksFillUUIDForAnErroredVM(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	spec := `{"name":"vm-err","cpu":2}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-err", HostName: "node-a", Spec: spec, State: "error"},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fake := libvirtfake.New()
	// Defined and NOT running: the domain persists, so its XML — and its uuid —
	// are readable.
	if err := fake.DefineDomain(
		`<domain><name>vm-err</name><uuid>5113ced7-9006-4086-b7dd-9d1840181e03</uuid></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	r.ReconcileOnce(ctx)

	got, err := corrosion.GetVM(ctx, db, "vm-err")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if u := specUUID(t, got.Spec); u != "5113ced7-9006-4086-b7dd-9d1840181e03" {
		t.Fatalf("uuid = %q after a sweep, want the domain's — an errored VM "+
			"stays invisible to the mirror and blocks every delete", u)
	}
}

// TestMaybeBackfillUUID_WritesNothingWithoutAUsableUUID: a domain whose XML
// carries no usable uuid leaves the spec alone. An absent uuid is visible and
// skipped; a bogus one mints a confident, permanently wrong identity.
func TestMaybeBackfillUUID_WritesNothingWithoutAUsableUUID(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	spec := `{"name":"vm1","cpu":2}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: spec, State: "running"},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain><name>vm1</name><uuid>not-a-uuid</uuid></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	r.maybeBackfillUUID(ctx, corrosion.VMRecord{Name: "vm1", Spec: spec})

	got, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if u := specUUID(t, got.Spec); u != "" {
		t.Fatalf("uuid = %q, want none written from an unusable value", u)
	}
}
