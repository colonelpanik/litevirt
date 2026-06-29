package tenancy

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/billing"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func newEngineTestClient(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestEngine_Admit_DefaultProjectUnbounded(t *testing.T) {
	c := newEngineTestClient(t)
	e := NewEngine(c, nil)
	// Wildly oversized request must pass for the default project.
	if err := e.Admit(context.Background(), Default, QuotaRequest{
		VCPU: 1_000_000, MemMiB: 1_000_000, DiskGiB: 1_000_000, NIC: 100,
	}); err != nil {
		t.Errorf("default project must accept unbounded requests, got %v", err)
	}
}

func TestEngine_Admit_RejectsMissingProject(t *testing.T) {
	c := newEngineTestClient(t)
	e := NewEngine(c, nil)
	err := e.Admit(context.Background(), "/ghost", QuotaRequest{VCPU: 1})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing project should be rejected with not-found, got %v", err)
	}
}

func TestEngine_Admit_EnforcesPublicIPCap(t *testing.T) {
	ctx := context.Background()
	c := newEngineTestClient(t)
	if err := corrosion.InsertProject(ctx, c, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	// Allow 1 public IP per VM.
	if err := corrosion.UpsertProjectQuota(ctx, c, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", PublicIPLimit: 1,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	e := NewEngine(c, nil)
	if err := e.Admit(ctx, "/acme", QuotaRequest{PublicIPs: 1}); err != nil {
		t.Errorf("1 public IP under limit 1 must pass: %v", err)
	}
	err := e.Admit(ctx, "/acme", QuotaRequest{PublicIPs: 2})
	if err == nil || !strings.Contains(err.Error(), "public_ips") {
		t.Errorf("over-public-IP request must reject: %v", err)
	}
}

func TestEngine_Admit_EnforcesBackupGiBCap(t *testing.T) {
	ctx := context.Background()
	c := newEngineTestClient(t)
	if err := corrosion.InsertProject(ctx, c, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, c, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", BackupGiBLimit: 100,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	e := NewEngine(c, nil)
	if err := e.Admit(ctx, "/acme", QuotaRequest{BackupGiB: 80}); err != nil {
		t.Errorf("80 GiB under 100 GiB limit must pass: %v", err)
	}
	err := e.Admit(ctx, "/acme", QuotaRequest{BackupGiB: 200})
	if err == nil || !strings.Contains(err.Error(), "backup_gib") {
		t.Errorf("over-backup-GiB request must reject: %v", err)
	}
}

func TestEngine_EmitsBillingEvents(t *testing.T) {
	c := newEngineTestClient(t)
	rec := &billing.RecordingEmitter{}
	e := NewEngine(c, rec)
	e.EmitVMCreated(context.Background(), "", "vm-1", QuotaRequest{VCPU: 2, MemMiB: 2048})
	e.EmitVMDeleted(context.Background(), "/acme", "vm-1")

	if len(rec.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(rec.Events))
	}
	if rec.Events[0].Kind != "vm.create" || rec.Events[0].Project != Default {
		t.Errorf("first event mismatch: %+v", rec.Events[0])
	}
	if rec.Events[1].Kind != "vm.delete" || rec.Events[1].Project != "/acme" {
		t.Errorf("second event mismatch: %+v", rec.Events[1])
	}
}

// TestAdmitAttach: a workload may use a GLOBAL (empty-project) resource or one its
// own project owns; cross-project use is denied. Both sides normalize, so a blank
// workload project is the default project — which still may not use a NAMED
// project's owned resource.
func TestAdmitAttach(t *testing.T) {
	cases := []struct {
		wl, owner string
		want      bool
	}{
		{"acme", "", true},       // global resource — any project
		{"", "", true},           // global, default workload
		{"acme", "acme", true},   // same project
		{Default, "", true},      // default workload, global
		{"", Default, true},      // blank workload normalizes to default == default-owned
		{"acme", "beta", false},  // cross-project
		{"", "acme", false},      // default workload may not use an acme-owned resource
		{"acme", Default, false}, // acme workload may not use a default-owned resource
	}
	for _, c := range cases {
		if got := AdmitAttach(c.wl, c.owner); got != c.want {
			t.Errorf("AdmitAttach(%q,%q) = %v, want %v", c.wl, c.owner, got, c.want)
		}
	}
}
