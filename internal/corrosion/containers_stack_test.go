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
	mk("b", "p1", "stopped", 1, 256)  // stopped still counts
	mk("c", "p2", "running", 4, 4096) // other project — must not leak

	u, err := SumProjectUsage(ctx, c, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if u.VCPUUsed != 3 || u.MemMiBUsed != 768 {
		t.Errorf("p1 usage = %d vCPU / %d MiB, want 3 / 768 (a+b, stopped included, p2 excluded)", u.VCPUUsed, u.MemMiBUsed)
	}
}

// Container backups (v26) draw down the SAME backup_gib budget as VMs: the
// per-(container,repo) index round-trips, sums into BackupGiBUsed for the
// container's project, and re-pushing the same (container,repo) overwrites
// rather than double-counts.
func TestUpsertContainerBackup_AndProjectFootprint(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()

	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "h1", Name: "ct1", State: "running", Project: "p1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "h1", Name: "other", State: "running", Project: "p2",
	}); err != nil {
		t.Fatal(err)
	}

	const giB = int64(1) << 30
	if err := UpsertContainerBackup(ctx, c, "ct1", "/repo", 3*giB); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainerBackup(ctx, c, "other", "/repo", 9*giB); err != nil {
		t.Fatal(err)
	}

	u, err := SumProjectUsage(ctx, c, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if u.BackupGiBUsed != 3 {
		t.Errorf("p1 BackupGiBUsed = %d, want 3 (ct1 only; p2's container excluded)", u.BackupGiBUsed)
	}

	// Re-push the same (container, repo) with a new size → overwrite, not add.
	if err := UpsertContainerBackup(ctx, c, "ct1", "/repo", 5*giB); err != nil {
		t.Fatal(err)
	}
	u, _ = SumProjectUsage(ctx, c, "p1")
	if u.BackupGiBUsed != 5 {
		t.Errorf("after re-push BackupGiBUsed = %d, want 5 (overwrite)", u.BackupGiBUsed)
	}
}

// Container snapshots (v27) round-trip through Insert/List/Get/Delete, scoped
// per (host, container), and tombstone on delete.
func TestContainerSnapshots_CRUD(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()

	mk := func(ct, name string, size int64) {
		if err := InsertContainerSnapshot(ctx, c, ContainerSnapshotRecord{
			CtName: ct, HostName: "h1", Name: name, State: "ok", SizeBytes: size,
			Type: "tar", Path: "/var/lib/litevirt/ct-snapshots/" + ct + "/" + name + ".tar",
		}); err != nil {
			t.Fatalf("InsertContainerSnapshot: %v", err)
		}
	}
	mk("web", "s1", 100)
	mk("web", "s2", 200)
	mk("db", "s1", 300) // different container — must not leak into web's list

	snaps, err := ListContainerSnapshots(ctx, c, "h1", "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("web has %d snapshots, want 2", len(snaps))
	}

	got, err := GetContainerSnapshot(ctx, c, "h1", "web", "s2")
	if err != nil || got == nil {
		t.Fatalf("GetContainerSnapshot: %v / nil=%v", err, got == nil)
	}
	if got.SizeBytes != 200 || got.Type != "tar" {
		t.Errorf("snapshot s2 = %+v, want size 200 type tar", got)
	}

	if err := DeleteContainerSnapshot(ctx, c, "h1", "web", "s1"); err != nil {
		t.Fatal(err)
	}
	if g, _ := GetContainerSnapshot(ctx, c, "h1", "web", "s1"); g != nil {
		t.Errorf("s1 should be tombstoned, got %+v", g)
	}
	snaps, _ = ListContainerSnapshots(ctx, c, "h1", "web")
	if len(snaps) != 1 || snaps[0].Name != "s2" {
		t.Errorf("after delete web has %+v, want just s2", snaps)
	}
}

// is_template + on_host_failure (v28) round-trip through Upsert/Get;
// SetContainerTemplate flips the flag.
func TestContainerTemplateAndPolicyColumns(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "h1", Name: "tmpl", State: "stopped", Project: "p1",
		IsTemplate: true, OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := GetContainer(ctx, c, "h1", "tmpl")
	if got == nil || !got.IsTemplate || got.OnHostFailure != "image-recreate" {
		t.Fatalf("round-trip = %+v, want is_template=true on_host_failure=image-recreate", got)
	}
	if err := SetContainerTemplate(ctx, c, "h1", "tmpl", false); err != nil {
		t.Fatal(err)
	}
	got, _ = GetContainer(ctx, c, "h1", "tmpl")
	if got.IsTemplate {
		t.Error("SetContainerTemplate(false) did not clear is_template")
	}
}

// RelocateContainer (B5 re-key) soft-deletes the source row and inserts a fresh
// pending/relocate-recreate row on the target, preserving spec fields.
func TestRelocateContainer(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "dead", Name: "web", State: "running", Image: "alpine:3.19",
		CPULimit: 2, MemMiB: 256, Project: "p1", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}
	if err := RelocateContainer(ctx, c, "dead", "web", "live"); err != nil {
		t.Fatalf("RelocateContainer: %v", err)
	}
	// Source row gone.
	if g, _ := GetContainer(ctx, c, "dead", "web"); g != nil {
		t.Errorf("source row still present: %+v", g)
	}
	// Target row present, pending+relocate, spec preserved.
	g, _ := GetContainer(ctx, c, "live", "web")
	if g == nil {
		t.Fatal("target row missing")
	}
	if g.State != "pending" || g.StateDetail != ContainerRelocateRecreateDetail {
		t.Errorf("target state/detail = %q/%q, want pending/%s", g.State, g.StateDetail, ContainerRelocateRecreateDetail)
	}
	if g.Image != "alpine:3.19" || g.CPULimit != 2 || g.MemMiB != 256 || g.Project != "p1" || g.OnHostFailure != "image-recreate" {
		t.Errorf("target spec not preserved: %+v", g)
	}
	// Exactly one live "web" cluster-wide.
	all, _ := ListContainers(ctx, c, "")
	n := 0
	for _, ct := range all {
		if ct.Name == "web" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("live web rows = %d, want 1", n)
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
