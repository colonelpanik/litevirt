package corrosion

import (
	"context"
	"strings"
	"testing"
)

func newProjectTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestProject_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme", Display: "Acme Co"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme/team-foo", ParentName: "/acme"}); err != nil {
		t.Fatalf("InsertProject child: %v", err)
	}
	got, err := GetProject(ctx, c, "/acme/team-foo")
	if err != nil || got == nil {
		t.Fatalf("GetProject: got=%v err=%v", got, err)
	}
	if got.ParentName != "/acme" {
		t.Errorf("parent = %q, want /acme", got.ParentName)
	}
	// _default always present.
	def, _ := GetProject(ctx, c, DefaultProject)
	if def == nil || def.Name != DefaultProject {
		t.Errorf("default project should always resolve")
	}
}

func TestProject_RejectsOrphanedChild(t *testing.T) {
	c := newProjectTestClient(t)
	err := InsertProject(context.Background(), c, ProjectRecord{Name: "/orphan", ParentName: "/does-not-exist"})
	if err == nil {
		t.Fatal("expected error when parent missing")
	}
}

// TestDeleteProject_RefusesWhenContainersExist guards the gap found in the
// v1.0.18 regression: DeleteProject refused non-empty projects for VMs but not
// containers, so a project owning only containers could be deleted, orphaning
// their project association (quota/RBAC). It must refuse for containers too.
func TestDeleteProject_RefusesWhenContainersExist(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "h1", Name: "ct-1", State: "running", Project: "/acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err == nil {
		t.Fatal("DeleteProject should refuse a project that still owns containers")
	}
	// Once the container is gone, deletion succeeds.
	if err := DeleteContainer(ctx, c, "h1", "ct-1"); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Errorf("DeleteProject should succeed once empty: %v", err)
	}
}

func TestProjectQuota_AdmissionPassesUnderLimit(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 8, MemMiBLimit: 8192, NICLimit: 4,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	// New VM asking for 4 vCPU / 4 GiB / 1 NIC: must pass.
	if err := CheckProjectQuota(ctx, c, "/acme", QuotaCheck{
		VCPU: 4, MemMiB: 4096, NIC: 1,
	}); err != nil {
		t.Errorf("admission should pass under quota: %v", err)
	}
}

func TestProjectQuota_AdmissionRejectsOverLimit(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 4,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	err := CheckProjectQuota(ctx, c, "/acme", QuotaCheck{VCPU: 8})
	if err == nil {
		t.Fatal("admission should reject when request exceeds quota")
	}
	if !strings.Contains(err.Error(), "vcpu") {
		t.Errorf("error should mention vcpu: %v", err)
	}
}

func TestProjectQuota_UnboundedWhenNoQuotaRow(t *testing.T) {
	c := newProjectTestClient(t)
	// No project, no quota row → unbounded.
	if err := CheckProjectQuota(context.Background(), c, "/acme",
		QuotaCheck{VCPU: 1_000_000}); err != nil {
		t.Errorf("admission should be unbounded without a quota row, got %v", err)
	}
}

func TestDeleteProject_RefusesNonEmpty(t *testing.T) {
	ctx := context.Background()
	c := newProjectTestClient(t)
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	// Seed a VM in the project.
	if err := InsertVM(ctx, c, VMRecord{
		Name: "vm-1", Spec: "{}", State: "running", Project: "/acme",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	err := DeleteProject(ctx, c, "/acme")
	if err == nil {
		t.Fatal("should refuse deletion of non-empty project")
	}
}

func TestSumProjectUsage_PublicIPs(t *testing.T) {
	c := newProjectTestClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "pub-vm", HostName: "h1", Spec: `{"cpu":2,"memory_mib":1024}`, State: "running", Project: "/acme"}
	ifaces := []InterfaceRecord{
		{VMName: "pub-vm", NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "10.0.0.5"},    // private (RFC1918)
		{VMName: "pub-vm", NetworkName: "wan", Ordinal: 1, MAC: "52:54:00:00:00:02", IP: "203.0.113.7"}, // public
	}
	if err := InsertVM(ctx, c, vm, ifaces, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	u, err := SumProjectUsage(ctx, c, "/acme")
	if err != nil {
		t.Fatalf("SumProjectUsage: %v", err)
	}
	if u.NICUsed != 2 {
		t.Errorf("NICUsed = %d, want 2", u.NICUsed)
	}
	if u.PublicIPsUsed != 1 {
		t.Errorf("PublicIPsUsed = %d, want 1 (only 203.0.113.7 is non-private)", u.PublicIPsUsed)
	}
}

func TestSumProjectUsage_BackupGiB(t *testing.T) {
	c := newProjectTestClient(t)
	ctx := context.Background()

	if err := InsertVM(ctx, c,
		VMRecord{Name: "bk-vm", HostName: "h1", Spec: "{}", State: "running", Project: "/acme"},
		nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Two disks backed up: 3 GiB + 5 GiB.
	if err := UpsertVMBackup(ctx, c, "bk-vm", "root", "/repo", 3*(1<<30)); err != nil {
		t.Fatalf("UpsertVMBackup root: %v", err)
	}
	if err := UpsertVMBackup(ctx, c, "bk-vm", "data", "/repo", 5*(1<<30)); err != nil {
		t.Fatalf("UpsertVMBackup data: %v", err)
	}
	// Re-push root, larger — upsert REPLACES (latest-per-disk), not accumulate.
	if err := UpsertVMBackup(ctx, c, "bk-vm", "root", "/repo", 4*(1<<30)); err != nil {
		t.Fatalf("UpsertVMBackup root v2: %v", err)
	}

	u, err := SumProjectUsage(ctx, c, "/acme")
	if err != nil {
		t.Fatalf("SumProjectUsage: %v", err)
	}
	if u.BackupGiBUsed != 9 { // 4 (root, replaced) + 5 (data)
		t.Errorf("BackupGiBUsed = %d, want 9", u.BackupGiBUsed)
	}
}
