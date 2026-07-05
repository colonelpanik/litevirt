package health

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestMaybePinMachineType_BackfillsAliasPreservingSpec proves the G7 backfill
// rewrites an unversioned machine alias to the concrete type libvirt resolved,
// while leaving every other spec field intact, and is a no-op once pinned.
func TestMaybePinMachineType_BackfillsAliasPreservingSpec(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Stored spec carries the alias plus other fields that must survive the edit.
	spec := `{"name":"vm1","machine":"q35","cpu":4,"memory_mib":2048,"firmware":"uefi"}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: spec, State: "running", CPUActual: 4, MemActual: 2048},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fake := libvirtfake.New()
	// libvirt bound the domain to a concrete versioned machine type.
	if err := fake.DefineDomain(`<domain><name>vm1</name><os><type arch="x86_64" machine="pc-q35-9.0">hvm</type></os></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)

	r.maybePinMachineType(ctx, corrosion.VMRecord{Name: "vm1", Spec: spec, CPUActual: 4, MemActual: 2048})

	got, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	var m struct {
		Name      string `json:"name"`
		Machine   string `json:"machine"`
		CPU       int    `json:"cpu"`
		MemoryMiB int    `json:"memory_mib"`
		Firmware  string `json:"firmware"`
	}
	if err := json.Unmarshal([]byte(got.Spec), &m); err != nil {
		t.Fatalf("unmarshal pinned spec: %v", err)
	}
	if m.Machine != "pc-q35-9.0" {
		t.Errorf("machine = %q, want pinned pc-q35-9.0", m.Machine)
	}
	// Every other field preserved.
	if m.Name != "vm1" || m.CPU != 4 || m.MemoryMiB != 2048 || m.Firmware != "uefi" {
		t.Errorf("backfill perturbed other spec fields: %+v", m)
	}

	// Idempotent: a second pass over the now-pinned spec must not rewrite (and
	// must not touch the DB even if libvirt reported something else).
	fake2 := libvirtfake.New()
	_ = fake2.DefineDomain(`<domain><name>vm1</name><os><type machine="pc-q35-8.2">hvm</type></os></domain>`)
	r2 := NewReconciler("node-a", t.TempDir(), db, fake2)
	r2.maybePinMachineType(ctx, corrosion.VMRecord{Name: "vm1", Spec: got.Spec, CPUActual: 4, MemActual: 2048})
	after, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil {
		t.Fatalf("GetVM after: %v", err)
	}
	var m2 struct {
		Machine string `json:"machine"`
	}
	_ = json.Unmarshal([]byte(after.Spec), &m2)
	if m2.Machine != "pc-q35-9.0" {
		t.Errorf("already-pinned spec was rewritten to %q; must be a no-op", m2.Machine)
	}
}

// TestMaybePinMachineType_CASNoClobber proves the backfill won't clobber a
// concurrent user spec edit: if the stored spec changed since the reconcile pass
// read it, the CAS write no-ops (the fresh edit survives).
func TestMaybePinMachineType_CASNoClobber(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	staleSpec := `{"name":"vm1","machine":"q35","cpu":2}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: staleSpec, State: "running", CPUActual: 2},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A concurrent user update lands AFTER the reconcile pass snapshotted staleSpec.
	freshSpec := `{"name":"vm1","machine":"q35","cpu":8}`
	if err := corrosion.UpdateVMSpec(ctx, db, "vm1", freshSpec, 8, 0); err != nil {
		t.Fatalf("concurrent UpdateVMSpec: %v", err)
	}

	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain><name>vm1</name><os><type machine="pc-q35-9.0">hvm</type></os></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	// Backfill runs off the STALE snapshot (cpu:2) — its CAS must not overwrite the
	// fresh cpu:8 edit.
	r.maybePinMachineType(ctx, corrosion.VMRecord{Name: "vm1", Spec: staleSpec, CPUActual: 2})

	got, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.Spec != freshSpec {
		t.Errorf("CAS clobbered a concurrent edit: spec = %s, want the fresh %s", got.Spec, freshSpec)
	}
}

// TestMaybePinMachineType_StoppedDomain covers the stopped-VM backfill: a stopped
// but still-defined VM gets its machine pinned from the persistent domain.
func TestMaybePinMachineType_StoppedDomain(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	spec := `{"name":"svm","machine":"q35"}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "svm", HostName: "node-a", Spec: spec, State: "stopped"},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	if err := fake.DefineDomain(`<domain><name>svm</name><os><type machine="pc-q35-8.2">hvm</type></os></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.maybePinMachineType(ctx, corrosion.VMRecord{Name: "svm", Spec: spec})

	got, err := corrosion.GetVM(ctx, db, "svm")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	var m struct {
		Machine string `json:"machine"`
	}
	_ = json.Unmarshal([]byte(got.Spec), &m)
	if m.Machine != "pc-q35-8.2" {
		t.Errorf("stopped VM machine = %q, want pinned pc-q35-8.2", m.Machine)
	}
}
