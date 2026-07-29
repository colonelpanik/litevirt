// Fleet scenarios for MIGRATION admission.
//
// Migration ran no capacity admission at all. Every other way of putting a
// workload onto a host — create, clone, restore-then-start, resize-up — was
// admitted; a move was not. So `lv vm migrate` (and the health checker's
// automatic re-home, which drives the same handler) could pack a target host
// past the point where `lv run` would have refused a VM of that exact size, with
// nothing logged because nothing checked.
//
// Migration is inherently multi-node and that is where the bug hides: MigrateVM
// executes on the SOURCE (a call entering any other node is forwarded there), and
// the host that must be admitted against is a THIRD party — the target. These
// scenarios therefore enter on a roomy node, run on a roomy source, and target a
// host that cannot hold the workload, so an admission that consulted the entry
// node's or the source's capacity would pass and prove nothing.

package fleet

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedRunningVM stages a running, diskless VM owned by node n. Diskless keeps the
// scenario about admission: a migrate with local disks takes the --with-storage
// path, which needs real qcow2 files and tells us nothing more about capacity.
func seedRunningVM(t *testing.T, c *Cluster, n *Node, name, project string, cpu, memMiB int) {
	t.Helper()
	specJSON, err := json.Marshal(&pb.VMSpec{Name: name, Project: project, Cpu: int32(cpu), MemoryMib: int32(memMiB)})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := corrosion.InsertVM(context.Background(), c.Nodes[0].DB, corrosion.VMRecord{
		Name: name, HostName: n.Name, State: "running", Spec: string(specJSON),
		Project: project, CPUActual: cpu, MemActual: memMiB,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	// The domain must exist on the owning node's libvirt fake: migration drives
	// MigrateToTarget against it, and the post-cutover path reads its state.
	n.Virt.SetState(name, "running")
}

// migrateAt asks node at to migrate vm to targetHost and drains the progress
// stream, returning the terminal error (nil on success).
func migrateAt(t *testing.T, c *Cluster, at *Node, vmName, targetHost string) error {
	t.Helper()
	st, err := c.SelfClient(at).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: vmName, TargetHost: targetHost, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
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

// TestFleet_MigrateVM_IsAdmittedAgainstTheTargetHostsCapacity pins the host half.
//
// The sizing is chosen so only the RIGHT host can refuse: entry and source are
// large, the target cannot hold the VM. An admission that ran against the entry
// node, against the source (where the VM already fits — it is running there), or
// not at all, admits this.
func TestFleet_MigrateVM_IsAdmittedAgainstTheTargetHostsCapacity(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	entry, src, dst := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	setHostCapacity(t, c, entry.Name, 64, 65536, nil)
	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	// dst: ~1 GiB allocatable after the default reserve — cannot hold a 4 GiB VM.
	setHostCapacity(t, c, dst.Name, 8, 2048, nil)

	seedRunningVM(t, c, src, "mover", "", 2, 4096)

	err := migrateAt(t, c, entry, "mover", dst.Name)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("migrate onto a host with ~1 GiB free: got %v, want ResourceExhausted — a migration lands a "+
			"full-sized running VM and must be admitted against the host that will run it", err)
	}
	// A refused migration must not have moved or disturbed the VM.
	rec, gerr := corrosion.GetVM(ctx, src.DB, "mover")
	if gerr != nil || rec == nil {
		t.Fatalf("GetVM mover: rec=%v err=%v", rec, gerr)
	}
	if rec.HostName != src.Name {
		t.Errorf("refused migration still moved the VM to %q, want it left on %q", rec.HostName, src.Name)
	}
	if rec.State != "running" {
		t.Errorf("refused migration left the VM in state %q, want running", rec.State)
	}

	// Control: the same migration once the target can hold it. Without this the
	// refusal above passes for any reason at all, including a broken migrate path.
	setHostCapacity(t, c, dst.Name, 64, 65536, nil)
	if err := migrateAt(t, c, entry, "mover", dst.Name); err != nil {
		t.Fatalf("migrate onto a host with tens of GiB free: %v", err)
	}
	rec, gerr = corrosion.GetVM(ctx, dst.DB, "mover")
	if gerr != nil || rec == nil {
		t.Fatalf("GetVM after migrate: rec=%v err=%v", rec, gerr)
	}
	if rec.HostName != dst.Name {
		t.Errorf("VM is owned by %q after a successful migration, want %q", rec.HostName, dst.Name)
	}
}

// TestFleet_MigrateVM_DoesNotChargeTheProjectQuotaTwice is the other half of
// getting admission right, and the reason it is HOST-only.
//
// A migration MOVES an allocation the project's quota already counts — it does
// not grow it. Charging quota again would refuse the migration of any workload
// occupying more than half its project's ceiling, which is the same double-count
// TestFleet_TenancyQuota_StopStartStaysWithinQuota pins for stop/start. A VM at
// 3000 of a 4096 MiB ceiling is migratable; a quota-charging admission computes
// 3000 + 3000 > 4096 and refuses it.
func TestFleet_MigrateVM_DoesNotChargeTheProjectQuotaTwice(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	entry, src, dst := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// Every host is huge, so nothing but the quota could refuse this.
	for _, n := range []*Node{entry, src, dst} {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	if err := corrosion.InsertProject(ctx, c.Nodes[0].DB, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, c.Nodes[0].DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 4, MemMiBLimit: 4096,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	seedRunningVM(t, c, src, "big-half", "/acme", 2, 3000)

	if err := migrateAt(t, c, entry, "big-half", dst.Name); err != nil {
		t.Fatalf("migrating a VM occupying 3000 of its project's 4096 MiB ceiling: %v — "+
			"a move does not grow the project's allocation, so migration must not charge quota again", err)
	}
}

// TestFleet_MigrateVM_ReleasesItsReservation pins the other half of holding a
// lease: a migration that SUCCEEDS must not keep consuming the headroom it
// reserved while deciding. A leaked lease permanently withholds capacity from a
// workload that now exists on the target and is being counted normally — so the
// next migration onto that host is refused for memory nothing is using.
func TestFleet_MigrateVM_ReleasesItsReservation(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	entry, src, dst := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	for _, n := range []*Node{entry, src, dst} {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	seedRunningVM(t, c, src, "rel-vm", "", 2, 4096)

	if err := migrateAt(t, c, entry, "rel-vm", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cpu, mem, err := corrosion.HostReserved(ctx, dst.DB, dst.Name)
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a successful migration the target still holds %d vCPU/%d MiB in reservations, want 0/0 — "+
			"the migration's admission lease outlived the move and is now withholding capacity nothing is using", cpu, mem)
	}
}

// TestFleet_MigrateContainer_IsAdmittedAgainstTheTargetHostsCapacity: a cold
// container migrate lands the container's whole memory cap on the target, and
// admitted nothing.
//
// The refusal must come BEFORE the cold-transfer stop. A capacity check that ran
// only on the far side (inside the target's RestoreContainer) would stop and
// archive a running container first and roll it back afterwards — a real outage
// for a decision that was knowable up front — so the stop count is asserted, not
// just the error code.
func TestFleet_MigrateContainer_IsAdmittedAgainstTheTargetHostsCapacity(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-toobig"

	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	setHostCapacity(t, c, dst.Name, 8, 2048, nil) // ~1 GiB allocatable

	if _, err := c.SelfClient(src).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: src.Name, Name: name, Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: 2048,
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}

	err := runMigrate(t, c, src, dst, name, stagingRepo(t))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("cold-migrating a 2048 MiB container onto a host with ~1 GiB free: got %v, want ResourceExhausted", err)
	}
	if calls := src.CT.StopCalls(); len(calls) != 0 {
		t.Errorf("source container was stopped %d times before the capacity refusal; want 0 — "+
			"a migrate that cannot fit its target must not bounce a running container first", len(calls))
	}
	if calls := src.CT.ExportCalls(); len(calls) != 0 {
		t.Errorf("source was archived %d times despite a refused migrate; want 0", len(calls))
	}

	// Control: identical migrate, target sized to hold it. Proves the refusal is
	// capacity and not the migrate path failing for its own reasons — and that one
	// move reserves exactly ONCE (a source lease plus an unconditional target-side
	// lease would need 2× the container's memory free and refuse this).
	setHostCapacity(t, c, dst.Name, 8, 4096, nil) // 3072 allocatable: fits one 2048, not two
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("cold-migrating a 2048 MiB container onto a host with 3072 MiB allocatable: %v", err)
	}
	cpu, mem, rerr := corrosion.HostReserved(context.Background(), dst.DB, dst.Name)
	if rerr != nil {
		t.Fatalf("HostReserved: %v", rerr)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a landed container migrate the target still holds %d vCPU/%d MiB in reservations, want 0/0", cpu, mem)
	}
}
