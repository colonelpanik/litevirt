package fleet

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Container cold-migration is the one container path that is structurally
// unreachable from a single-package test: MigrateContainer archives on the
// SOURCE, pushes the manifest into the TARGET's staging repo over peer mTLS,
// then drives the target's RestoreContainer — two daemons, real gRPC, real
// streaming. internal/grpcapi's own tests all stub that drive out through
// s.migrateRestoreOverride (see peer_restore_drive.go:69), so nothing in the
// tree exercises source→target for real. These scenarios do.
//
// Each asserts on the TARGET's on-disk rootfs, not just on cluster rows: a
// migration that moved no bytes must not be able to pass.

// ctMigrateCluster brings up a 2-node fleet sharing one CRDT view. Sharing is
// deliberate — these scenarios are about the migrate handoff over the wire, not
// about replication lag, and a converged cluster is the state a real migrate
// runs in (the AlreadyExists preflight reads the TARGET's row from the source's
// own DB, which only means anything once the two have converged).
func ctMigrateCluster(t *testing.T) *Cluster {
	t.Helper()
	return New(t, Options{Nodes: 2, SharedCRDT: true})
}

// createContainer drives the real CreateContainer RPC on n and fails the test
// if it does not land.
func createContainer(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	_, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName:  n.Name,
		Name:      name,
		Template:  "download",
		Distro:    "debian",
		Release:   "bookworm",
		Arch:      "amd64",
		Cpu:       1,
		MemoryMib: 256,
	})
	if err != nil {
		t.Fatalf("CreateContainer %s on %s: %v", name, n.Name, err)
	}
}

// runMigrate drives MigrateContainer from source→target and drains the
// progress stream, returning the terminal error (nil on success).
func runMigrate(t *testing.T, c *Cluster, source, target *Node, name, repo string) error {
	t.Helper()
	st, err := c.SelfClient(source).MigrateContainer(context.Background(), &pb.MigrateContainerRequest{
		Name:       name,
		SourceHost: source.Name,
		TargetHost: target.Name,
		RepoPath:   repo,
	})
	if err != nil {
		return err
	}
	for {
		_, rerr := st.Recv()
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// stagingRepo returns a fresh, INITIALISED absolute staging-repo path.
// Absolute paths are admin-only, which the harness's mTLS SelfClient satisfies.
//
// Initialising matters: an unopenable repo makes MigrateContainer fail at its
// very first step, which silently turns every rollback scenario below into a
// vacuous pass (the source is "still intact" only because nothing ever touched
// it). Each of those scenarios asserts a call count that pins the work actually
// happened.
func stagingRepo(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(root); err != nil {
		t.Fatalf("init staging repo: %v", err)
	}
	return root
}

// TestContainerMigrate_MovesRootfsAndOwnership is the happy path: after a
// migrate the container's BYTES are on the target, its row is owned by the
// target, and the source keeps neither.
func TestContainerMigrate_MovesRootfsAndOwnership(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-move"

	createContainer(t, c, src, name)
	// A payload only the source has. If the target ends up serving this, the
	// rootfs genuinely crossed the wire rather than being re-created locally.
	const payload = "rootfs-bytes-from-node-0"
	src.CT.Seed(name, payload)

	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if got := dst.CT.Payload(name); got != payload {
		t.Fatalf("target rootfs payload = %q, want %q — the container's bytes did not cross the wire", got, payload)
	}
	if src.CT.Exists(name) {
		t.Error("source still holds the container runtime after a landed migrate")
	}

	// Ownership re-keyed: target row live, source row gone.
	if rec, err := corrosion.GetContainer(ctx, dst.DB, dst.Name, name); err != nil || rec == nil {
		t.Fatalf("target row after migrate: rec=%v err=%v — target must own the container", rec, err)
	}
	if rec, err := corrosion.GetContainer(ctx, src.DB, src.Name, name); err != nil {
		t.Fatalf("read source row: %v", err)
	} else if rec != nil {
		t.Error("source row still live after a landed migrate — the container is owned twice")
	}
}

// TestContainerMigrate_RefusesWhenTargetOwnsTheName must refuse BEFORE
// touching the source: a name collision that stopped the source container
// first would be an outage caused by a check that could have run earlier.
func TestContainerMigrate_RefusesWhenTargetOwnsTheName(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-collide"

	createContainer(t, c, src, name)
	createContainer(t, c, dst, name) // same name, already on the target

	err := runMigrate(t, c, src, dst, name, stagingRepo(t))
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("migrate onto an occupied name: got %v, want AlreadyExists", err)
	}
	if calls := src.CT.StopCalls(); len(calls) != 0 {
		t.Errorf("source container was stopped %d times before the collision check; want 0 — a refused migrate must not bounce the source", len(calls))
	}
	if calls := src.CT.ExportCalls(); len(calls) != 0 {
		t.Errorf("source was archived %d times despite a refused migrate; want 0", len(calls))
	}
}

// TestContainerMigrate_RefusesFromNonOwner: migrate runs on the owning daemon.
// Driven anywhere else it must name the owner rather than act.
func TestContainerMigrate_RefusesFromNonOwner(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-wrong-host"

	createContainer(t, c, src, name)

	// Drive it against the TARGET daemon, which does not own the container.
	st, err := c.SelfClient(dst).MigrateContainer(context.Background(), &pb.MigrateContainerRequest{
		Name: name, SourceHost: src.Name, TargetHost: dst.Name, RepoPath: stagingRepo(t),
	})
	if err == nil {
		_, err = st.Recv()
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("migrate driven at a non-owner: got %v, want FailedPrecondition", err)
	}
	if !src.CT.Exists(name) {
		t.Error("container disappeared from its owner after a refused migrate")
	}
}

// TestContainerMigrate_RollsBackARunningSourceOnArchiveFailure: an archive
// failure happens BEFORE the target could have written anything, so the source
// must come back exactly as it was — running, and still owning its row.
func TestContainerMigrate_RollsBackARunningSourceOnArchiveFailure(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-rollback"

	createContainer(t, c, src, name)
	if _, err := c.SelfClient(src).StartContainer(ctx, &pb.StartContainerRequest{
		HostName: src.Name, Name: name,
	}); err != nil {
		t.Fatalf("start container: %v", err)
	}

	src.CT.FailExport(errors.New("simulated archive failure"))
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err == nil {
		t.Fatal("migrate succeeded despite an archive failure")
	}

	// Pin that the migrate got far enough to matter — otherwise "the source is
	// intact" is true only because nothing ever touched it.
	if got := len(src.CT.StopCalls()); got != 1 {
		t.Fatalf("source stopped %d times, want 1 — the migrate never reached the cold-transfer stop, so this scenario proves nothing", got)
	}
	if got := len(src.CT.StartCalls()); got < 2 {
		t.Fatalf("source started %d times, want ≥2 (initial + rollback restart)", got)
	}

	// The source must be running again and still tracked.
	if got := src.CT.State(name); got != "running" {
		t.Errorf("source runtime state after rollback = %q, want %q", got, "running")
	}
	rec, err := corrosion.GetContainer(ctx, src.DB, src.Name, name)
	if err != nil || rec == nil {
		t.Fatalf("source row after rollback: rec=%v err=%v — a rolled-back migrate must leave it tracked", rec, err)
	}
	if rec.State != "running" {
		t.Errorf("source row state = %q, want running", rec.State)
	}
	// The migration's operator-stop marker is a transfer-window artefact. Left
	// behind, the reconciler would hold the container down forever.
	if rec.StateDetail == "operator-stop" {
		t.Error("rollback left the migration's operator-stop marker on the source row — the reconciler will never restart it")
	}
	// Nothing may have landed on the target.
	if dst.CT.Exists(name) {
		t.Error("target holds a container copy after a rolled-back migrate")
	}
}

// TestContainerMigrate_ParksARunningSourceWhenTheTargetOutcomeIsIndeterminate
// pins the deliberately conservative branch, which is easy to get wrong in
// exactly the direction that causes a split brain.
//
// A target-side import failure comes back as codes.Internal, and
// classifyRestoreError treats every code outside the definite pre-row set as
// RestoreUnknown (backup_container.go:487) — a transport break could have
// dropped the row-recorded frame AFTER the target wrote its row. So the source
// must NOT be restarted: the target might be live on the same container and its
// IPAM leases. Instead it is parked (stopped + operator-stop, the reconciler's
// guaranteed-stick marker) and the ambiguity surfaced to an operator.
//
// The container is never lost — the source keeps both its runtime and its row.
func TestContainerMigrate_ParksARunningSourceWhenTheTargetOutcomeIsIndeterminate(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "ct-target-fails"

	createContainer(t, c, src, name)
	if _, err := c.SelfClient(src).StartContainer(ctx, &pb.StartContainerRequest{
		HostName: src.Name, Name: name,
	}); err != nil {
		t.Fatalf("start container: %v", err)
	}
	dst.CT.FailImport(errors.New("simulated target import failure"))

	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err == nil {
		t.Fatal("migrate succeeded despite the target failing to import")
	}

	// The failure must have happened on the FAR side, after a real archive and
	// a real cross-node push — not early on the source.
	if got := len(src.CT.ExportCalls()); got != 1 {
		t.Fatalf("source archived %d times, want 1 — the migrate never reached the transfer, so the target's failure was never exercised", got)
	}
	if got := len(dst.CT.ImportCalls()); got != 1 {
		t.Fatalf("target attempted %d imports, want 1 — the manifest never crossed the wire", got)
	}

	// The core invariant: a source whose target outcome is unknown stays DOWN.
	if got := len(src.CT.StartCalls()); got != 1 {
		t.Errorf("source was started %d times, want 1 (the initial start only) — restarting a source whose target may hold it is a split brain", got)
	}
	if got := src.CT.State(name); got != "stopped" {
		t.Errorf("source runtime state = %q, want stopped", got)
	}

	// …but it is never lost: runtime and row both survive, marked for an operator.
	if !src.CT.Exists(name) {
		t.Error("source runtime was removed on an indeterminate outcome — the container may now exist nowhere")
	}
	rec, err := corrosion.GetContainer(ctx, src.DB, src.Name, name)
	if err != nil || rec == nil {
		t.Fatalf("source row: rec=%v err=%v — an indeterminate migrate must leave the source tracked", rec, err)
	}
	if rec.State != "stopped" || rec.StateDetail != "operator-stop" {
		t.Errorf("source row = (%q,%q), want (stopped,operator-stop) — without the sticky marker the reconciler restarts a container the target may hold",
			rec.State, rec.StateDetail)
	}
	if trec, terr := corrosion.GetContainer(ctx, dst.DB, dst.Name, name); terr != nil {
		t.Fatalf("read target row: %v", terr)
	} else if trec != nil {
		t.Error("target wrote a container row despite failing to import it")
	}
}
