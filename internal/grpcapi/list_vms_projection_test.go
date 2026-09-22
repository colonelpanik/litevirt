package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListVMs ships a PROJECTION of the stored spec, not the whole thing — the list
// view must not carry every VM's cloud-init. What that projection contains is
// therefore load-bearing for any caller that reads a scalar off it, and getting
// it wrong is invisible to a test that hand-builds its own pb.VMSpec: such a
// test asserts against a value the RPC never produces.
//
// These pin the projection through the REAL RPC, which is the only place the
// difference shows up.

// TestListVMsProjectsTheUUID is the regression behind `lv doctor vm-uuids`.
// The projection originally carried labels alone, so a VM with a perfectly good
// uuid came back with Spec.Uuid == "" and was reported as missing one, while an
// unlabelled VM came back with a nil Spec and was skipped entirely — the report
// was exactly inverted.
func TestListVMsProjectsTheUUID(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "has-uuid", HostName: "host-1", State: "running",
		Spec: `{"name":"has-uuid","uuid":"5113ced7-9006-4086-b7dd-9d1840181e03","cpu":2}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// No labels at all — the shape that used to come back with a nil Spec.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "legacy", HostName: "host-1", State: "running",
		Spec: `{"name":"legacy","cpu":2}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	got := map[string]*pb.VM{}
	for _, vm := range resp.GetVms() {
		got[vm.GetName()] = vm
	}

	if u := got["has-uuid"].GetSpec().GetUuid(); u != "5113ced7-9006-4086-b7dd-9d1840181e03" {
		t.Errorf("has-uuid: Spec.Uuid = %q, want the stored uuid", u)
	}
	// A VM WITH a stored spec must carry a non-nil Spec even with no labels, or
	// "Spec == nil" cannot be read as "there is no stored spec".
	if got["legacy"].GetSpec() == nil {
		t.Fatal("legacy: Spec is nil for a VM that HAS a stored spec — a caller " +
			"cannot then tell an absent spec from an absent field")
	}
	if u := got["legacy"].GetSpec().GetUuid(); u != "" {
		t.Errorf("legacy: Spec.Uuid = %q, want empty", u)
	}
}

// TestListVMsProjectsTheMachineType is the same defect in the neighbouring
// report, `lv doctor machine-types`: an unversioned alias is what it looks for,
// and a projection that never carried `machine` made every labelled VM read as
// carrying the empty alias.
func TestListVMsProjectsTheMachineType(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "pinned", HostName: "host-1", State: "running",
		Spec: `{"name":"pinned","machine":"pc-q35-9.0","cpu":2}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.GetVms()) != 1 {
		t.Fatalf("got %d VMs, want 1", len(resp.GetVms()))
	}
	if m := resp.GetVms()[0].GetSpec().GetMachine(); m != "pc-q35-9.0" {
		t.Errorf("Spec.Machine = %q, want the stored pc-q35-9.0", m)
	}
}

// TestListVMsStillProjectsLabels is the control: widening the projection must
// not drop what it already carried. The UI's tag chips and the ansible
// inventory's litevirt_label_* vars both read these.
func TestListVMsStillProjectsLabels(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "tagged", HostName: "host-1", State: "running",
		Spec: `{"name":"tagged","labels":{"env":"prod","team":"core"},"cpu":2}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	labels := resp.GetVms()[0].GetSpec().GetLabels()
	if labels["env"] != "prod" || labels["team"] != "core" {
		t.Errorf("labels = %v, want env=prod team=core", labels)
	}
}

// TestListVMsDoesNotShipTheWholeSpec is the other control, and the reason the
// projection exists: the list must not carry cloud-init user-data for every VM
// in the cluster. A future field added to the projection has to justify itself
// against this.
func TestListVMsDoesNotShipTheWholeSpec(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "fat", HostName: "host-1", State: "running",
		Spec: `{"name":"fat","uuid":"5113ced7-9006-4086-b7dd-9d1840181e03",` +
			`"cloud_init":{"userdata":"#cloud-config\nssh_authorized_keys: [a-secret-key]"}}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if ci := resp.GetVms()[0].GetSpec().GetCloudInit(); ci != nil && ci.GetUserdata() != "" {
		t.Errorf("the list projection shipped cloud-init user-data: %q", ci.GetUserdata())
	}
}

// TestListVMsProjectsTheCPUMode is the regression behind `lv doctor cpu-mode`.
//
// The projection carried labels/uuid/machine but not cpu_mode, so every VM came
// back with Spec.CpuMode == "" and the report called ALL of them legacy —
// including ones just retrofitted to host-model, whose stored spec plainly said
// so. The report could never reach zero, which is the one thing it exists to
// show.
//
// Caught on a live cluster, not by the doctor unit test, because that test
// hand-builds pb.VM values with a full spec and so never exercises the
// projection. This asserts through the real RPC, where the gap is visible.
func TestListVMsProjectsTheCPUMode(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "retrofitted", HostName: "host-1", State: "running",
		Spec: `{"name":"retrofitted","cpu":2,"cpu_mode":"host-model"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "pinned", HostName: "host-1", State: "running",
		Spec: `{"name":"pinned","cpu":2,"cpu_mode":"custom","cpu_model":"x86-64-v3"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// The genuinely legacy shape the report is meant to surface.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "legacy-cpu", HostName: "host-1", State: "running",
		Spec: `{"name":"legacy-cpu","cpu":2}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	got := map[string]*pb.VM{}
	for _, vm := range resp.GetVms() {
		got[vm.GetName()] = vm
	}

	if m := got["retrofitted"].GetSpec().GetCpuMode(); m != "host-model" {
		t.Errorf("retrofitted: Spec.CpuMode = %q, want host-model — the report would "+
			"call an already-fixed VM legacy", m)
	}
	if m := got["pinned"].GetSpec().GetCpuMode(); m != "custom" {
		t.Errorf("pinned: Spec.CpuMode = %q, want custom", m)
	}
	// cpu_model rides along so a list-level caller can render a custom mode
	// without a per-VM InspectVM round trip.
	if m := got["pinned"].GetSpec().GetCpuModel(); m != "x86-64-v3" {
		t.Errorf("pinned: Spec.CpuModel = %q, want x86-64-v3", m)
	}
	// And the legacy VM must still read as empty, or the report reaches zero by
	// lying rather than by anything being fixed.
	if m := got["legacy-cpu"].GetSpec().GetCpuMode(); m != "" {
		t.Errorf("legacy-cpu: Spec.CpuMode = %q, want empty", m)
	}
	if got["legacy-cpu"].GetSpec() == nil {
		t.Fatal("legacy-cpu: Spec is nil for a VM that HAS a stored spec")
	}
}
