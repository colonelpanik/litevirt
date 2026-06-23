package corrosion

import (
	"context"
	"testing"
)

func newCtTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Containers count toward their project's shared vCPU/Mem budget — a stopped
// container still counts (allocation, like VMs), and other projects don't leak in.
func TestSumProjectUsage_IncludesContainers(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	mk := func(name, project, state string, cpu, mem int) {
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "h1", Name: name, State: state, Project: project, CPULimit: cpu, MemMiB: mem,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "p1", "running", 2, 512)
	mk("b", "p1", "stopped", 1, 256) // stopped still counts
	mk("c", "p2", "running", 4, 4096) // other project — must not leak

	u, err := SumProjectUsage(ctx, c, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if u.VCPUUsed != 3 || u.MemMiBUsed != 768 {
		t.Errorf("p1 usage = %d vCPU / %d MiB, want 3 / 768 (a+b, stopped included, p2 excluded)", u.VCPUUsed, u.MemMiBUsed)
	}
}

// A container's project (v25) round-trips through Upsert/Get/List, and an empty
// project normalizes to "_default" (so old rows / unset callers land in the
// default tenancy bucket).
func TestContainerProject(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()

	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "a", State: "running", Project: "/acme/team"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "b", State: "running"}); err != nil { // empty → _default
		t.Fatal(err)
	}
	got, _ := GetContainer(ctx, c, "h1", "a")
	if got == nil || got.Project != "/acme/team" {
		t.Fatalf("a project = %+v, want /acme/team", got)
	}
	got, _ = GetContainer(ctx, c, "h1", "b")
	if got == nil || got.Project != "_default" {
		t.Fatalf("b project = %+v, want _default", got)
	}
	// List carries it too.
	all, _ := ListContainers(ctx, c, "h1")
	byName := map[string]string{}
	for _, ct := range all {
		byName[ct.Name] = ct.Project
	}
	if byName["a"] != "/acme/team" || byName["b"] != "_default" {
		t.Errorf("ListContainers projects = %+v", byName)
	}
}

// ListContainersByStack returns only containers tagged with the stack label.
func TestListContainersByStack(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	mk := func(name, stack string) {
		r := ContainerRecord{HostName: "h1", Name: name, State: "running"}
		if stack != "" {
			r.Labels = map[string]string{LabelStack: stack}
		}
		if err := UpsertContainer(ctx, c, r); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "s1")
	mk("b", "s2")
	mk("c", "") // no stack label → belongs to no stack

	got, err := ListContainersByStack(ctx, c, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("ListContainersByStack(s1) = %+v, want just [a]", got)
	}
	// A stack with no tagged containers is empty (and non-nil so callers can range).
	if got, _ := ListContainersByStack(ctx, c, "nope"); len(got) != 0 {
		t.Errorf("unknown stack returned %d containers", len(got))
	}
}

// SetHostLabel merges into hosts.labels and preserves other labels; re-setting
// the same value is a no-op.
func TestSetHostLabel(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	if err := InsertHost(ctx, c, HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", CertSerial: "x", State: "active",
	}); err != nil {
		t.Fatal(err)
	}

	if err := SetHostLabel(ctx, c, "h1", LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
	h, _ := GetHost(ctx, c, "h1")
	if h == nil || h.Labels[LabelLXCCapable] != "true" {
		t.Fatalf("LXC label not set: %+v", h)
	}

	// Merging a second label preserves the first.
	if err := SetHostLabel(ctx, c, "h1", "rack", "r1"); err != nil {
		t.Fatal(err)
	}
	h, _ = GetHost(ctx, c, "h1")
	if h.Labels[LabelLXCCapable] != "true" || h.Labels["rack"] != "r1" {
		t.Fatalf("merge lost a label: %+v", h.Labels)
	}

	// Re-setting the same value is a no-op (returns nil without churn).
	if err := SetHostLabel(ctx, c, "h1", LabelLXCCapable, "true"); err != nil {
		t.Fatalf("no-op set returned error: %v", err)
	}
}
