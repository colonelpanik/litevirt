package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// A migrating container's IPAM leases are handed to the target BEFORE the
// restore, because the target keeps the imported IPs rather than re-reserving
// them — so it must already own every managed address before it can start.
// MigrateContainer verifies that handoff in BOTH directions and hands the
// leases BACK on rollback (migrate_container.go:150-255).
//
// Every one of those checks reads and writes cluster-wide IPAM state while two
// daemons act on the same container, which is why this belongs in the fleet
// tier. The scenarios below assert on ip_allocations ownership directly.
//
// Each takes ~3s, and that is not a hang: creating a container on a managed
// network runs the real network.SafeProvision, which sleeps one 3s interval
// verifying host connectivity settled after provisioning
// (network/safeguard.go:184). Real behaviour, so it is left alone.

const (
	ctNetName   = "ctnet"
	ctNetSubnet = "10.77.0.0/24"
)

// seedContainerNetwork registers a managed bridge network with a subnet, so a
// NIC naming it gets a real IPAM lease. Bridge networks degrade gracefully when
// the host device can't be provisioned (container_network.go:132), which is
// what lets this run rootless.
func seedContainerNetwork(t *testing.T, c *Cluster) {
	t.Helper()
	rec := corrosion.NetworkRecord{
		Name:   ctNetName,
		Type:   "bridge",
		Config: `{"type":"bridge","interface":"br-ctnet","subnet":"` + ctNetSubnet + `"}`,
	}
	for _, n := range c.Nodes {
		if err := corrosion.UpsertNetwork(context.Background(), n.DB, rec); err != nil {
			t.Fatalf("seed network on %s: %v", n.Name, err)
		}
	}
}

// createContainerOnNetwork creates a container with one MANAGED NIC and returns
// the IP that was allocated to it. It fails the test if no address was leased —
// without that guard every lease-ownership assertion below would hold
// vacuously over an empty NIC set.
func createContainerOnNetwork(t *testing.T, c *Cluster, n *Node, name string) string {
	t.Helper()
	if _, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: n.Name, Name: name, Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: 256,
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: ctNetName}},
	}); err != nil {
		t.Fatalf("CreateContainer %s on %s: %v", name, n.Name, err)
	}
	ifaces := containerIfaces(t, n, name)
	if len(ifaces) == 0 {
		t.Fatalf("container %s has no managed NICs — the lease assertions would be vacuous", name)
	}
	if ifaces[0].IP == "" {
		t.Fatalf("container %s NIC got no IPAM address — the lease assertions would be vacuous", name)
	}
	return ifaces[0].IP
}

// containerIfaces rebuilds the container's managed NIC set from its create-spec
// — the same source MigrateContainer verifies ownership against.
func containerIfaces(t *testing.T, n *Node, name string) []corrosion.ContainerInterfaceRecord {
	t.Helper()
	rec, err := corrosion.GetContainer(context.Background(), n.DB, n.Name, name)
	if err != nil || rec == nil {
		t.Fatalf("read container %s on %s: rec=%v err=%v", name, n.Name, rec, err)
	}
	return corrosion.BuildContainerInterfacesFromSpec(n.Name, name, corrosion.DecodeCreateSpec(rec.CreateSpec))
}

// leaseOwner returns the host currently holding the live IPAM lease for ip, or
// "" if no live lease exists.
func leaseOwner(t *testing.T, n *Node, ip string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT owner_host FROM ip_allocations
		  WHERE owner_kind = 'ct' AND ip = ? AND deleted_at IS NULL`, ip)
	if err != nil {
		t.Fatalf("query lease for %s: %v", ip, err)
	}
	if len(rows) == 0 || len(rows[0].Values) == 0 {
		return ""
	}
	owner, _ := rows[0].Values[0].(string)
	return owner
}

// TestContainerMigrate_HandsIPAMLeasesToTheTarget: after a landed migrate the
// target owns every managed address. A lease left behind on the source is how
// two hosts end up believing they own the same IP.
func TestContainerMigrate_HandsIPAMLeasesToTheTarget(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	seedContainerNetwork(t, c)
	const name = "ct-ipam-move"

	ip := createContainerOnNetwork(t, c, src, name)
	if got := leaseOwner(t, src, ip); got != src.Name {
		t.Fatalf("before migrate, lease for %s is owned by %q, want %q", ip, got, src.Name)
	}

	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if got := leaseOwner(t, dst, ip); got != dst.Name {
		t.Fatalf("after migrate, lease for %s is owned by %q, want the target %q", ip, got, dst.Name)
	}
	// And the invariant the migrate itself checks: the target owns EVERY managed
	// NIC address named by the spec it rebuilt from.
	ifaces := containerIfaces(t, dst, name)
	ownsAll, err := network.ContainerLeasesOwnedBy(context.Background(), dst.DB, dst.Name, name, ifaces)
	if err != nil {
		t.Fatalf("verify target lease ownership: %v", err)
	}
	if !ownsAll {
		t.Error("target does not own every managed NIC address after a landed migrate")
	}
}

// TestContainerMigrate_HandsIPAMLeasesBackOnRollback exercises the hand-BACK:
// the leases move to the target before the restore is attempted, so a rollback
// must move them back before restarting the source. Restarting a source that no
// longer owns its address is exactly the conflict the handoff exists to prevent
// — and the rollback refuses to restart at all unless it can prove ownership
// (migrate_container.go:150-175).
//
// Reaching a genuine rollback AFTER the handoff needs a target failure that
// classifies as definitively pre-row. A target-side import error is codes.
// Internal and therefore indeterminate (it parks instead — see
// TestContainerMigrate_ParksARunningSourceWhenTheTargetOutcomeIsIndeterminate).
// AlreadyExists is conclusive, so this races a container onto the target during
// the archive window: past the source's preflight, before the restore.
func TestContainerMigrate_HandsIPAMLeasesBackOnRollback(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	seedContainerNetwork(t, c)
	ctx := context.Background()
	const name = "ct-ipam-rollback"

	ip := createContainerOnNetwork(t, c, src, name)
	if _, err := c.SelfClient(src).StartContainer(ctx, &pb.StartContainerRequest{
		HostName: src.Name, Name: name,
	}); err != nil {
		t.Fatalf("start container: %v", err)
	}

	// Mid-archive, give the target a container of the same name. The source's
	// preflight has already passed, so the collision now surfaces from the
	// target's restore as AlreadyExists → RestoreFailedBeforeRow → rollback.
	src.CT.OnExport(func() {
		if err := corrosion.UpsertContainer(ctx, dst.DB, corrosion.ContainerRecord{
			HostName: dst.Name, Name: name, State: "stopped",
		}); err != nil {
			t.Errorf("seed the colliding target row: %v", err)
		}
	})

	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err == nil {
		t.Fatal("migrate succeeded onto a name the target had taken")
	}
	if got := len(src.CT.ExportCalls()); got != 1 {
		t.Fatalf("source archived %d times, want 1 — the migrate never reached the handoff, so there was nothing to undo", got)
	}

	// The lease must be back with the source…
	if got := leaseOwner(t, src, ip); got != src.Name {
		t.Fatalf("after rollback, lease for %s is owned by %q, want it handed back to %q", ip, got, src.Name)
	}
	ifaces := containerIfaces(t, src, name)
	ownsAll, err := network.ContainerLeasesOwnedBy(ctx, src.DB, src.Name, name, ifaces)
	if err != nil {
		t.Fatalf("verify source lease ownership: %v", err)
	}
	if !ownsAll {
		t.Error("source does not own every managed NIC address after rollback")
	}

	// …and only then may it run again.
	if got := src.CT.State(name); got != "running" {
		t.Errorf("source runtime state after rollback = %q, want running", got)
	}
	rec, gerr := corrosion.GetContainer(ctx, src.DB, src.Name, name)
	if gerr != nil || rec == nil {
		t.Fatalf("source row after rollback: rec=%v err=%v", rec, gerr)
	}
	if rec.State != "running" || rec.StateDetail == "operator-stop" {
		t.Errorf("source row = (%q,%q), want it restored to running without the migration's operator-stop marker",
			rec.State, rec.StateDetail)
	}
}

// TestContainerMigrate_RefusesWhenTheSourceDoesNotOwnItsAddress: the migrate's
// PREcondition. A managed NIC whose address no source lease backs must not be
// migrated — handing the target an address it cannot own would manufacture a
// conflict on the far side rather than move one.
func TestContainerMigrate_RefusesWhenTheSourceDoesNotOwnItsAddress(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	seedContainerNetwork(t, c)
	ctx := context.Background()
	const name = "ct-ipam-stolen"

	ip := createContainerOnNetwork(t, c, src, name)

	// Simulate the drift this guards: the lease is gone (released out of band,
	// or lost to a stale spec) while the container's spec still names the IP.
	if err := src.DB.Execute(ctx,
		`UPDATE ip_allocations SET deleted_at = ?
		  WHERE owner_kind = 'ct' AND ip = ? AND deleted_at IS NULL`,
		src.DB.NowTS(), ip); err != nil {
		t.Fatalf("release the source lease: %v", err)
	}

	err := runMigrate(t, c, src, dst, name, stagingRepo(t))
	if err == nil {
		t.Fatal("migrate succeeded while the source did not own its NIC address")
	}

	// Refused, and rolled back — the container stays whole on the source.
	if !src.CT.Exists(name) {
		t.Error("source lost the container runtime after a refused migrate")
	}
	if rec, gerr := corrosion.GetContainer(ctx, src.DB, src.Name, name); gerr != nil || rec == nil {
		t.Fatalf("source row after a refused migrate: rec=%v err=%v", rec, gerr)
	}
	if dst.CT.Exists(name) {
		t.Error("target holds a copy of a container whose migrate was refused")
	}
	if got := leaseOwner(t, dst, ip); got == dst.Name {
		t.Error("the target was handed the address anyway — the precondition did not prevent the handoff")
	}
}
