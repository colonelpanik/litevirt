package compose

import (
	"testing"
)

func makeFile(name string, vms map[string]VMDef) *File {
	return &File{Name: name, VMs: vms}
}

func intPtr(n int) *int { return &n }

func TestBuild_CreateAll(t *testing.T) {
	f := makeFile("mystack", map[string]VMDef{
		"web": {Image: "ubuntu-22.04", CPU: 2, Memory: 1024},
		"db":  {Image: "postgres-15", CPU: 4, Memory: 4096},
	})

	plan, err := Build(f, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("expected 2 ops, got %d", len(plan.Ops))
	}
	for _, op := range plan.Ops {
		if op.Kind != OpCreate {
			t.Errorf("expected OpCreate, got %q for %s", op.Kind, op.VMName)
		}
	}
}

func TestBuild_NoChanges(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"api": {Image: "myapp:latest", CPU: 2, Memory: 512},
	})
	current := []CurrentVM{
		{Name: "api", Image: "myapp:latest", CPU: 2, MemMiB: 512, State: "running"},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if plan.HasChanges() {
		t.Errorf("expected no changes, got plan: %v", plan.Ops)
	}
}

func TestBuild_UpdateOnCPUChange(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"api": {Image: "myapp:latest", CPU: 4, Memory: 512},
	})
	current := []CurrentVM{
		{Name: "api", Image: "myapp:latest", CPU: 2, MemMiB: 512},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpUpdate {
		t.Errorf("expected OpUpdate, got %v", plan.Ops)
	}
}

func TestBuild_DeleteRemoved(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"web": {Image: "nginx", CPU: 1, Memory: 256},
	})
	current := []CurrentVM{
		{Name: "web", Image: "nginx", CPU: 1, MemMiB: 256},
		{Name: "cache", Image: "redis", CPU: 1, MemMiB: 256},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	var deletions []string
	for _, op := range plan.Ops {
		if op.Kind == OpDelete {
			deletions = append(deletions, op.VMName)
		}
	}
	if len(deletions) != 1 || deletions[0] != "cache" {
		t.Errorf("expected cache deletion, got deletions: %v", deletions)
	}
}

func TestBuild_Replicas(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"worker": {Image: "worker:v1", CPU: 2, Memory: 512, Replicas: intPtr(3)},
	})

	plan, err := Build(f, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}

	creates := 0
	for _, op := range plan.Ops {
		if op.Kind == OpCreate {
			creates++
		}
	}
	if creates != 3 {
		t.Errorf("expected 3 creates for 3 replicas, got %d", creates)
	}
}

func TestBuild_Summary(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"web": {Image: "nginx", CPU: 1, Memory: 256},
		"new": {Image: "app:latest", CPU: 2, Memory: 512},
	})
	current := []CurrentVM{
		{Name: "web", Image: "nginx", CPU: 1, MemMiB: 256},
		{Name: "old", Image: "old-app", CPU: 1, MemMiB: 256},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}

	s := plan.Summary()
	if s == "" {
		t.Error("Summary returned empty string")
	}
	// Should mention creates and deletes.
	if !containsCount(s, "create") {
		t.Errorf("summary missing 'create': %s", s)
	}
	if !containsCount(s, "delete") {
		t.Errorf("summary missing 'delete': %s", s)
	}
}

func TestBuild_WarningOnRestartAnyLocalDisk(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"db": {
			Image: "postgres",
			CPU:   2, Memory: 1024,
			Disks:   map[string]DiskDef{"data": {Size: "50G"}}, // local disk
			Migrate: &MigrateDef{OnHostFailure: "restart-any"},
		},
	})

	plan, err := Build(f, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	for _, op := range plan.Ops {
		if op.VMName == "db" && op.Kind == OpCreate {
			if op.Warning == "" {
				t.Error("expected warning for local disk + restart-any, got none")
			}
			return
		}
	}
	t.Error("expected create op for db")
}

func TestBuild_ImageChange(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"app": {Image: "myapp:v2", CPU: 2, Memory: 512},
	})
	current := []CurrentVM{
		{Name: "app", Image: "myapp:v1", CPU: 2, MemMiB: 512},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpUpdate {
		t.Errorf("expected OpUpdate for image change, got %v", plan.Ops)
	}
}

func containsCount(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && stringContains(s, substr)
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBuild_CloudInitChanged(t *testing.T) {
	oldHash := CloudInitHash("old userdata", "old netconfig")
	f := makeFile("stack", map[string]VMDef{
		"app": {
			Image: "myapp:v1", CPU: 2, Memory: 512,
			CloudInit: &CloudInitDef{
				UserData:      "new userdata",
				NetworkConfig: "new netconfig",
			},
		},
	})
	current := []CurrentVM{
		{Name: "app", Image: "myapp:v1", CPU: 2, MemMiB: 512, CloudInitHash: oldHash},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpUpdate {
		t.Fatalf("expected OpUpdate, got %v", plan.Ops)
	}
	if !stringContains(plan.Ops[0].Detail, "cloud-init changed") {
		t.Errorf("expected 'cloud-init changed' in Detail, got %q", plan.Ops[0].Detail)
	}
}

func TestBuild_CloudInitAdded(t *testing.T) {
	f := makeFile("stack", map[string]VMDef{
		"app": {
			Image: "myapp:v1", CPU: 2, Memory: 512,
			CloudInit: &CloudInitDef{
				UserData: "#cloud-config\npackages: [htop]",
			},
		},
	})
	current := []CurrentVM{
		{Name: "app", Image: "myapp:v1", CPU: 2, MemMiB: 512, CloudInitHash: ""},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpUpdate {
		t.Fatalf("expected OpUpdate, got %v", plan.Ops)
	}
	if !stringContains(plan.Ops[0].Detail, "cloud-init added") {
		t.Errorf("expected 'cloud-init added' in Detail, got %q", plan.Ops[0].Detail)
	}
}

func TestBuild_CloudInitRemoved(t *testing.T) {
	existingHash := CloudInitHash("some userdata", "some netconfig")
	f := makeFile("stack", map[string]VMDef{
		"app": {Image: "myapp:v1", CPU: 2, Memory: 512, CloudInit: nil},
	})
	current := []CurrentVM{
		{Name: "app", Image: "myapp:v1", CPU: 2, MemMiB: 512, CloudInitHash: existingHash},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpUpdate {
		t.Fatalf("expected OpUpdate, got %v", plan.Ops)
	}
	if !stringContains(plan.Ops[0].Detail, "cloud-init removed") {
		t.Errorf("expected 'cloud-init removed' in Detail, got %q", plan.Ops[0].Detail)
	}
}

func TestBuild_CloudInitUnchanged(t *testing.T) {
	userdata := "#cloud-config\npackages: [curl]"
	netconfig := "version: 2"
	hash := CloudInitHash(userdata, netconfig)

	f := makeFile("stack", map[string]VMDef{
		"app": {
			Image: "myapp:v1", CPU: 2, Memory: 512,
			CloudInit: &CloudInitDef{
				UserData:      userdata,
				NetworkConfig: netconfig,
			},
		},
	})
	current := []CurrentVM{
		{Name: "app", Image: "myapp:v1", CPU: 2, MemMiB: 512, CloudInitHash: hash},
	}

	plan, err := Build(f, current)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if plan.HasChanges() {
		t.Errorf("expected no changes when cloud-init is unchanged, got: %v", plan.Ops)
	}
}

func TestCloudInitHash(t *testing.T) {
	// Same inputs produce the same hash.
	h1 := CloudInitHash("userdata", "netconfig")
	h2 := CloudInitHash("userdata", "netconfig")
	if h1 != h2 {
		t.Errorf("expected consistent hash, got %q and %q", h1, h2)
	}

	// Different userdata produces a different hash.
	h3 := CloudInitHash("other userdata", "netconfig")
	if h1 == h3 {
		t.Errorf("expected different hash for different userdata, but both were %q", h1)
	}

	// Different networkconfig produces a different hash.
	h4 := CloudInitHash("userdata", "other netconfig")
	if h1 == h4 {
		t.Errorf("expected different hash for different networkconfig, but both were %q", h1)
	}

	// Empty inputs produce a non-empty hash.
	h5 := CloudInitHash("", "")
	if h5 == "" {
		t.Error("expected non-empty hash for empty inputs")
	}

	// Swapping userdata and networkconfig produces a different hash (inputs are order-sensitive).
	h6 := CloudInitHash("netconfig", "userdata")
	if h1 == h6 {
		t.Errorf("expected different hash when userdata and networkconfig are swapped, but both were %q", h1)
	}
}

// TestBuild_RetriesTransientStates verifies that VMs in transient or error
// states get OpUpdate (not OpNoChange) so a redeploy after a partial failure
// re-attempts the lifecycle action. Without this, a daemon killed mid-create
// leaves a permanent state=creating zombie that no future `compose up` would
// fix.
func TestBuild_RetriesTransientStates(t *testing.T) {
	f := makeFile("s", map[string]VMDef{
		"web": {Image: "img", CPU: 2, Memory: 1024},
	})
	transientStates := []string{"creating", "starting", "stopping", "rebuilding", "error", "failed"}
	for _, st := range transientStates {
		current := []CurrentVM{
			{Name: "web", Image: "img", CPU: 2, MemMiB: 1024, State: st},
		}
		plan, err := Build(f, current)
		if err != nil {
			t.Fatalf("Build [%s]: %v", st, err)
		}
		if len(plan.Ops) != 1 {
			t.Fatalf("[%s] expected 1 op, got %d", st, len(plan.Ops))
		}
		if plan.Ops[0].Kind != OpUpdate {
			t.Errorf("[%s] expected OpUpdate (retry), got %q", st, plan.Ops[0].Kind)
		}
	}
}

// TestBuild_RunningStateIsNoChangeWhenSpecMatches verifies that the new
// transient-state retry logic doesn't accidentally retry healthy VMs.
func TestBuild_RunningStateIsNoChangeWhenSpecMatches(t *testing.T) {
	f := makeFile("s", map[string]VMDef{
		"web": {Image: "img", CPU: 2, Memory: 1024},
	})
	current := []CurrentVM{
		{Name: "web", Image: "img", CPU: 2, MemMiB: 1024, State: "running"},
	}
	plan, _ := Build(f, current)
	if len(plan.Ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(plan.Ops))
	}
	if plan.Ops[0].Kind != OpNoChange {
		t.Errorf("running steady-state VM: got %q, want OpNoChange", plan.Ops[0].Kind)
	}
}

func TestIsTransientOrErrorState(t *testing.T) {
	cases := map[string]bool{
		"running":     false,
		"stopped":     false,
		"paused":      false,
		"fenced":      false,
		"migrating":   false, // intentionally not retried — interrupting a migration is worse
		"creating":    true,
		"starting":    true,
		"stopping":    true,
		"rebuilding":  true,
		"error":       true,
		"failed":      true,
	}
	for state, want := range cases {
		if got := isTransientOrErrorState(state); got != want {
			t.Errorf("isTransientOrErrorState(%q) = %v, want %v", state, got, want)
		}
	}
}
