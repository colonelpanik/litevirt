// Fleet scenarios for CLONE admission.
//
// CloneVM ran no capacity or quota admission at all. Every other way of bringing a
// VM into existence — create, restore, resize-up — was admitted; clone was not, so
// it was a full-sized VM that materialised wherever it liked. Cloning a template in
// a loop overfilled a host, and cloned a project straight past its quota, while the
// create path refused correctly the whole time. Nothing logged, because nothing
// checked.
//
// The multi-node shape is the part a single-package test cannot reach, and it is
// exactly where the bug hid: a clone is created on the SOURCE's host (its disks live
// there), so a clone entering any other node is forwarded. Admission therefore has
// to happen on the node that ends up executing, against THAT host's capacity — not
// the entry node's, which typically has room. These scenarios enter on a roomy node
// deliberately, so an admission that consulted the wrong host would pass.

package fleet

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// seedCloneSource stages a clonable template owned by host n: a real qcow2 disk in
// that node's own image store plus the VM/disk rows describing it.
//
// The disk is real because the clone engine is real — it creates a qcow2 overlay
// (linked) or converts (full), and neither works against a path that isn't a qcow2
// file. Staging it under n's data dir is what makes "the clone is built on the
// source's host" true rather than incidental.
func seedCloneSource(t *testing.T, c *Cluster, n *Node, name, project string, cpu, memMiB int) {
	t.Helper()
	ctx := context.Background()

	store := image.NewStore(filepath.Join(c.tmpRoot, n.Name, "data"))
	if err := store.Init(); err != nil {
		t.Fatalf("init image store on %s: %v", n.Name, err)
	}
	diskPath := store.DiskPath(name, "root")
	if err := mkdirAll(filepath.Dir(diskPath)); err != nil {
		t.Fatalf("mkdir disk dir: %v", err)
	}
	if err := qcow2.Create(diskPath, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}

	specJSON, err := json.Marshal(&pb.VMSpec{Name: name, Project: project, Cpu: int32(cpu), MemoryMib: int32(memMiB)})
	if err != nil {
		t.Fatalf("marshal source spec: %v", err)
	}
	// One write reaches every node: these scenarios run with Options.SharedCRDT, so
	// the cluster reads a single replica. That is deliberate — what is under test is
	// which HOST a clone is admitted against, and a convergence-dependent setup would
	// make a capacity failure and a replication failure indistinguishable.
	{
		db := c.Nodes[0].DB
		if err := corrosion.InsertVM(ctx, db,
			corrosion.VMRecord{
				Name: name, HostName: n.Name, State: "stopped", IsTemplate: true,
				Spec: string(specJSON), Project: project,
				CPUActual: cpu, MemActual: memMiB,
			},
			nil,
			[]corrosion.DiskRecord{{
				VMName: name, DiskName: "root", HostName: n.Name, Path: diskPath,
				SizeBytes: 64 * 1024 * 1024, StorageType: "local",
			}},
		); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
}

// cloneAt asks node at to clone source into target.
func cloneAt(t *testing.T, c *Cluster, at *Node, source, target string) (*pb.VM, error) {
	t.Helper()
	return c.SelfClient(at).CloneVM(context.Background(), &pb.CloneVMRequest{
		Source: source, Target: target,
	})
}

// TestFleet_Clone_IsAdmittedAgainstTheSourceHostsCapacity pins the host half.
//
// The sizing is chosen so only the RIGHT host can refuse: the entry node is large
// and idle, the source's host cannot hold the clone. An admission that ran on the
// entry node — or did not run at all — admits this.
func TestFleet_Clone_IsAdmittedAgainstTheSourceHostsCapacity(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, src := c.Nodes[0], c.Nodes[1]

	// entry: room to spare, and never the host that executes the clone.
	setHostCapacity(t, c, entry.Name, 64, 65536, nil)
	// src: ~1 GiB allocatable after the default reserve — cannot hold a 4 GiB clone.
	setHostCapacity(t, c, src.Name, 8, 2048, nil)

	seedCloneSource(t, c, src, "tpl", "", 2, 4096)

	_, err := cloneAt(t, c, entry, "tpl", "toobig")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("clone onto a host with ~1 GiB free: got %v, want ResourceExhausted — a clone is a "+
			"full-sized VM and must be admitted against the host that will actually run it", err)
	}
	if vm, gerr := corrosion.GetVM(context.Background(), src.DB, "toobig"); gerr == nil && vm != nil {
		t.Errorf("refused clone still left a VM row behind (state %q)", vm.State)
	}

	// Control: the same clone, once the source's host can hold it. Without this the
	// test above passes for any reason at all, including a broken clone engine.
	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	vm, err := cloneAt(t, c, entry, "tpl", "fits")
	if err != nil {
		t.Fatalf("clone onto a host with tens of GiB free: %v", err)
	}
	if vm.HostName != src.Name {
		t.Errorf("clone landed on %q, want %q (the source's host)", vm.HostName, src.Name)
	}
}

// TestFleet_Clone_ChargesTheProjectsQuota pins the tenancy half: a clone grows the
// project's allocation exactly like a create, so a project at its ceiling cannot be
// cloned into.
//
// Both hosts are deliberately huge here, so nothing but the quota can refuse — a
// green result from a host-capacity check standing in for a quota check would be a
// different property than the one claimed.
func TestFleet_Clone_ChargesTheProjectsQuota(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, src := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, entry.Name, 64, 65536, nil)
	setHostCapacity(t, c, src.Name, 64, 65536, nil)

	// /acme may hold 3 GiB. Its template already accounts for 2 GiB, so a 2 GiB
	// clone would put it at 4 GiB — over, but only by counting the clone.
	{
		db := c.Nodes[0].DB
		if err := corrosion.InsertProject(ctx, db, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
			t.Fatalf("InsertProject: %v", err)
		}
		if err := corrosion.UpsertProjectQuota(ctx, db, corrosion.ProjectQuotaRecord{
			ProjectName: "/acme", MemMiBLimit: 3072,
		}); err != nil {
			t.Fatalf("UpsertProjectQuota: %v", err)
		}
	}
	seedCloneSource(t, c, src, "acme-tpl", "/acme", 1, 2048)

	_, err := cloneAt(t, c, entry, "acme-tpl", "acme-over")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("clone into a project 2 GiB into its 3 GiB ceiling: got %v, want ResourceExhausted — "+
			"a clone consumes quota like any other VM", err)
	}

	// Control: raise the ceiling and the identical clone is admitted, so the refusal
	// above is the quota and not the clone engine failing for its own reasons.
	{
		db := c.Nodes[0].DB
		if err := corrosion.UpsertProjectQuota(ctx, db, corrosion.ProjectQuotaRecord{
			ProjectName: "/acme", MemMiBLimit: 8192,
		}); err != nil {
			t.Fatalf("raise quota: %v", err)
		}
	}
	if _, err := cloneAt(t, c, entry, "acme-tpl", "acme-fits"); err != nil {
		t.Fatalf("clone within an 8 GiB ceiling: %v", err)
	}
	rec, err := corrosion.GetVM(ctx, src.DB, "acme-fits")
	if err != nil || rec == nil {
		t.Fatalf("GetVM acme-fits: rec=%v err=%v", rec, err)
	}
	if rec.Project != "/acme" {
		t.Errorf("clone project = %q, want /acme (it inherits the source's, which is what its quota is charged to)", rec.Project)
	}
}

// TestFleet_Clone_ReleasesItsReservation pins the other half of holding a lease: a
// clone that SUCCEEDS must not keep consuming the headroom it reserved while
// deciding. A leaked lease is worse than no lease — it permanently withholds
// capacity from a workload that already exists and is being counted normally.
func TestFleet_Clone_ReleasesItsReservation(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, src := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, entry.Name, 64, 65536, nil)
	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	seedCloneSource(t, c, src, "rel-tpl", "", 2, 4096)

	if _, err := cloneAt(t, c, entry, "rel-tpl", "rel-1"); err != nil {
		t.Fatalf("clone: %v", err)
	}
	cpu, mem, err := corrosion.HostReserved(ctx, src.DB, src.Name)
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a successful clone the source host still holds %d vCPU/%d MiB in reservations, want 0/0 — "+
			"the clone's admission lease outlived the clone and is now withholding capacity nothing is using", cpu, mem)
	}
}
