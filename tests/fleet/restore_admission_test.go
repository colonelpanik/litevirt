// Fleet scenarios for RESTORE admission.
//
// A restore materialises a full-sized workload out of a manifest — a VM
// live-restore boots it, a container restore lays its rootfs down and starts it —
// and neither admitted anything. Backup data is the one input an operator can
// replay repeatedly, so "restore is unadmitted" is the cheapest way there was to
// overfill a host or walk a project past its quota, with `lv run` refusing the
// exact same shape correctly the whole time.
//
// These run in the fleet harness rather than in-package because the property is
// about the CLUSTER's view of capacity and quota — host rows, project rows, and
// the reservation ledger, over real gRPC — and because a restore's target host is
// chosen per-daemon: each scenario drives the daemon that will hold the workload
// while a roomy peer sits alongside, so an admission reading "some host" rather
// than "this host" cannot pass.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// relocateTokenHeader mirrors grpcapi's unexported relocateTokenMDKey: the
// metadata key a failover coordinator carries its attempt token in. Restating it
// here is deliberate — the header is a wire contract between two daemons, and a
// test that imported the constant could not notice it changing under a rename.
const relocateTokenHeader = "x-litevirt-relocate-token"

// ── VM live restore ─────────────────────────────────────────────────────

// seedVMBackup writes a one-disk VM backup carrying the spec a restore will
// rebuild the VM from. The embedded spec is the whole fixture: autoDefineRestoredVM
// sizes the restored domain from it, so it is also exactly what admission must
// charge.
func seedVMBackup(t *testing.T, name, project string, cpu, memMiB int) (repoDir, ts string) {
	t.Helper()
	repoDir = filepath.Join(t.TempDir(), "vmrepo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("init backup repo: %v", err)
	}
	specJSON, err := json.Marshal(&pb.VMSpec{
		Name: name, Project: project, Cpu: int32(cpu), MemoryMib: int32(memMiB),
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	ts = "2026-07-01T00:00:00Z"
	if _, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(make([]byte, 1<<20)),
		pbsstore.PushOptions{VMName: name, DiskName: "root", Timestamp: ts, VMSpecJSON: string(specJSON)}); err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	return repoDir, ts
}

// restoreLiveAt drives an auto-starting live restore on node n and drains the
// stream. Blockpull is on so the handler localises the disk and RETURNS instead
// of holding the NBD source open until the operator disconnects — the same path,
// minus a cancel that would race the VM-row write.
func restoreLiveAt(t *testing.T, c *Cluster, n *Node, repoDir, vmName, ts, newName string) error {
	t.Helper()
	st, err := c.SelfClient(n).RestoreLive(context.Background(), &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: vmName, DiskName: "root", Timestamp: ts,
		TargetPath: newName + ".qcow2", NewName: newName,
		AutoStart: true, Blockpull: true,
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

// TestFleet_RestoreLive_IsAdmittedAgainstTheRestoringHostsCapacity: the restored
// VM runs HERE, so it must fit here. A roomy peer is deliberately present — an
// admission that consulted the cluster at large, or the first host it found,
// would admit this.
func TestFleet_RestoreLive_IsAdmittedAgainstTheRestoringHostsCapacity(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	tight, roomy := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, roomy.Name, 64, 65536, nil)
	setHostCapacity(t, c, tight.Name, 8, 2048, nil) // ~1 GiB allocatable
	repo, ts := seedVMBackup(t, "backed-up", "", 2, 4096)

	err := restoreLiveAt(t, c, tight, repo, "backed-up", ts, "restored")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("live-restoring a 4 GiB VM onto a host with ~1 GiB free: got %v, want ResourceExhausted — "+
			"a restore boots a full-sized VM and consumes exactly what a create of that spec would", err)
	}
	if rec, gerr := corrosion.GetVM(ctx, tight.DB, "restored"); gerr == nil && rec != nil {
		t.Errorf("refused restore still left a VM row behind (state %q)", rec.State)
	}
	if tight.Virt.DomainExists("restored") {
		t.Error("refused restore still defined a domain — admission must run before DefineDomain")
	}

	// Control: the same restore once this host can hold it.
	setHostCapacity(t, c, tight.Name, 64, 65536, nil)
	if err := restoreLiveAt(t, c, tight, repo, "backed-up", ts, "restored-ok"); err != nil {
		t.Fatalf("live-restore onto a host with tens of GiB free: %v", err)
	}
	rec, gerr := corrosion.GetVM(ctx, tight.DB, "restored-ok")
	if gerr != nil || rec == nil {
		t.Fatalf("GetVM restored-ok: rec=%v err=%v", rec, gerr)
	}
	if rec.HostName != tight.Name {
		t.Errorf("restored VM is owned by %q, want %q", rec.HostName, tight.Name)
	}
	// The lease must not outlive the restore: the VM's own row now accounts for it.
	cpu, mem, rerr := corrosion.HostReserved(ctx, tight.DB, tight.Name)
	if rerr != nil {
		t.Fatalf("HostReserved: %v", rerr)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a successful live-restore the host still holds %d vCPU/%d MiB in reservations, want 0/0 — "+
			"the restore's admission lease outlived it and is withholding capacity nothing is using", cpu, mem)
	}
}

// TestFleet_RestoreLive_ChargesTheProjectsQuota pins the tenancy half. Unlike a
// migration or a start — which MOVE or RESUME an allocation the project already
// carries — a restore creates a NEW one: the row it writes is a VM the project
// did not have a moment ago, even when it restores alongside the original. So it
// charges quota, exactly like a create.
//
// Both hosts are huge here so nothing but the quota can refuse.
func TestFleet_RestoreLive_ChargesTheProjectsQuota(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	n, peer := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, n.Name, 64, 65536, nil)
	setHostCapacity(t, c, peer.Name, 64, 65536, nil)
	if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, n.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", MemMiBLimit: 3072,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	// The original is still live and accounts for 2 GiB of the 3 GiB ceiling, so a
	// 2 GiB restore alongside it is over — but only by counting the restore.
	specJSON, err := json.Marshal(&pb.VMSpec{Name: "orig", Project: "/acme", Cpu: 1, MemoryMib: 2048})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
		Name: "orig", HostName: n.Name, State: "running", Spec: string(specJSON),
		Project: "/acme", CPUActual: 1, MemActual: 2048,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM orig: %v", err)
	}
	repo, ts := seedVMBackup(t, "orig", "/acme", 1, 2048)

	err = restoreLiveAt(t, c, n, repo, "orig", ts, "orig-copy")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("restoring a 2 GiB VM into a project already 2 GiB into its 3 GiB ceiling: got %v, want ResourceExhausted — "+
			"a restore is a new allocation and consumes quota like any other VM", err)
	}

	// Control: raise the ceiling and the identical restore lands, so the refusal
	// above is the quota and not the restore path failing for its own reasons.
	if err := corrosion.UpsertProjectQuota(ctx, n.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", MemMiBLimit: 8192,
	}); err != nil {
		t.Fatalf("raise quota: %v", err)
	}
	if err := restoreLiveAt(t, c, n, repo, "orig", ts, "orig-copy2"); err != nil {
		t.Fatalf("restore within an 8 GiB ceiling: %v", err)
	}
	rec, gerr := corrosion.GetVM(ctx, n.DB, "orig-copy2")
	if gerr != nil || rec == nil {
		t.Fatalf("GetVM orig-copy2: rec=%v err=%v", rec, gerr)
	}
	if rec.Project != "/acme" {
		t.Errorf("restored VM project = %q, want /acme — the project charged must be the project written", rec.Project)
	}
}

// ── container restore ───────────────────────────────────────────────────

// backupContainer archives n's container into a fresh repo and returns the repo
// path + manifest timestamp a restore can be driven from.
func backupContainer(t *testing.T, c *Cluster, n *Node, name string) (repo, ts string) {
	t.Helper()
	repo = stagingRepo(t)
	st, err := c.SelfClient(n).BackupContainer(context.Background(), &pb.BackupContainerRequest{
		Name: name, HostName: n.Name, RepoPath: repo,
	})
	if err != nil {
		t.Fatalf("BackupContainer %s: %v", name, err)
	}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("BackupContainer stream: %v", rerr)
		}
		if p.ManifestTs != "" {
			ts = p.ManifestTs
		}
	}
	if ts == "" {
		t.Fatal("backup produced no manifest timestamp")
	}
	return repo, ts
}

// restoreContainerAt drives RestoreContainer on node n and drains the stream.
func restoreContainerAt(t *testing.T, c *Cluster, n *Node, repo, name, ts string) error {
	t.Helper()
	st, err := c.SelfClient(n).RestoreContainer(context.Background(), &pb.RestoreContainerRequest{
		RepoPath: repo, Name: name, Timestamp: ts, HostName: n.Name, Start: true,
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

// createSizedContainer creates a container of an explicit size on n.
func createSizedContainer(t *testing.T, c *Cluster, n *Node, name, project string, cpu, memMiB int32) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: n.Name, Name: name, Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Project: project, Cpu: cpu, MemoryMib: memMiB,
	}); err != nil {
		t.Fatalf("CreateContainer %s on %s: %v", name, n.Name, err)
	}
}

// TestFleet_RestoreContainer_IsAdmittedAgainstTheRestoringHostsCapacity: a
// restored container holds its whole memory cap on the host that restores it,
// and the ordinary CreateContainer path admits exactly that. The refusal must
// land before the import, so a host that cannot hold the container never writes
// its rootfs.
func TestFleet_RestoreContainer_IsAdmittedAgainstTheRestoringHostsCapacity(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	createSizedContainer(t, c, src, "ct-backed", "", 1, 2048)
	repo, ts := backupContainer(t, c, src, "ct-backed")

	setHostCapacity(t, c, dst.Name, 8, 2048, nil) // ~1 GiB allocatable
	err := restoreContainerAt(t, c, dst, repo, "ct-backed", ts)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("restoring a 2048 MiB container onto a host with ~1 GiB free: got %v, want ResourceExhausted", err)
	}
	if got := len(dst.CT.ImportCalls()); got != 0 {
		t.Errorf("target imported the rootfs %d times despite refusing the restore; want 0 — "+
			"admission must run before any I/O", got)
	}
	if rec, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct-backed"); rec != nil {
		t.Errorf("refused restore still wrote a container row on the target: %+v", rec)
	}

	// Control: the same restore once the host can hold it.
	setHostCapacity(t, c, dst.Name, 64, 65536, nil)
	if err := restoreContainerAt(t, c, dst, repo, "ct-backed", ts); err != nil {
		t.Fatalf("restore onto a host with tens of GiB free: %v", err)
	}
	if rec, gerr := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct-backed"); gerr != nil || rec == nil {
		t.Fatalf("target row after restore: rec=%v err=%v", rec, gerr)
	}
	cpu, mem, rerr := corrosion.HostReserved(ctx, dst.DB, dst.Name)
	if rerr != nil {
		t.Fatalf("HostReserved: %v", rerr)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after a successful container restore the host still holds %d vCPU/%d MiB in reservations, want 0/0", cpu, mem)
	}
}

// TestFleet_RestoreContainer_ChargesTheProjectsQuota: an operator restore is a
// NEW allocation — the source container is still live and still counted — so it
// draws on the project's budget exactly like CreateContainer does.
func TestFleet_RestoreContainer_ChargesTheProjectsQuota(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	setHostCapacity(t, c, dst.Name, 64, 65536, nil)
	if err := corrosion.InsertProject(ctx, src.DB, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, src.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", MemMiBLimit: 3072,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	createSizedContainer(t, c, src, "ct-acme", "/acme", 0, 2048)
	repo, ts := backupContainer(t, c, src, "ct-acme")

	err := restoreContainerAt(t, c, dst, repo, "ct-acme", ts)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("restoring a 2048 MiB container into a project 2048 MiB into its 3072 MiB ceiling: got %v, want ResourceExhausted", err)
	}

	if err := corrosion.UpsertProjectQuota(ctx, src.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", MemMiBLimit: 8192,
	}); err != nil {
		t.Fatalf("raise quota: %v", err)
	}
	if err := restoreContainerAt(t, c, dst, repo, "ct-acme", ts); err != nil {
		t.Fatalf("restore within an 8192 MiB ceiling: %v", err)
	}
	rec, gerr := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct-acme")
	if gerr != nil || rec == nil {
		t.Fatalf("restored row: rec=%v err=%v", rec, gerr)
	}
	if rec.Project != "/acme" {
		t.Errorf("restored container project = %q, want /acme", rec.Project)
	}
}

// TestFleet_RestoreContainer_CPUOnlyRestoreIsStillAdmitted: a CPU-limited,
// memory-UNLIMITED container must draw on the project's vCPU budget when
// restored. The old gate keyed the whole admission on memory being non-zero and
// passed 0 for CPU, so this exact shape was materialised past every check the
// handler has — no host check, no quota check, no host-safety check — and then
// its cpu_limit was persisted and counted by SumProjectUsage anyway. Restore
// must use the same host-memory / project-CPU+memory split as CreateContainer.
func TestFleet_RestoreContainer_CPUOnlyRestoreIsStillAdmitted(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	setHostCapacity(t, c, dst.Name, 64, 65536, nil)
	if err := corrosion.InsertProject(ctx, src.DB, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	// The live source (3 vCPU) already occupies 3 of the 4 vCPU ceiling, so
	// restoring a second instance (another 3) must refuse.
	if err := corrosion.UpsertProjectQuota(ctx, src.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 4,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	createSizedContainer(t, c, src, "ct-cpu", "/acme", 3, 0)
	repo, ts := backupContainer(t, c, src, "ct-cpu")

	err := restoreContainerAt(t, c, dst, repo, "ct-cpu", ts)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("restoring a 3 vCPU (memory-unlimited) container into a project 3 vCPU into its 4 vCPU ceiling: "+
			"got %v, want ResourceExhausted — memory==0 must not skip the CPU quota charge", err)
	}
	if got := len(dst.CT.ImportCalls()); got != 0 {
		t.Errorf("target imported the rootfs %d times despite refusing; want 0", got)
	}

	// Control: within a raised ceiling the same restore lands, with its CPU limit.
	if err := corrosion.UpsertProjectQuota(ctx, src.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 8,
	}); err != nil {
		t.Fatalf("raise quota: %v", err)
	}
	if err := restoreContainerAt(t, c, dst, repo, "ct-cpu", ts); err != nil {
		t.Fatalf("restore within an 8 vCPU ceiling: %v", err)
	}
	rec, gerr := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct-cpu")
	if gerr != nil || rec == nil {
		t.Fatalf("restored row: rec=%v err=%v", rec, gerr)
	}
	if rec.CPULimit != 3 || rec.MemMiB != 0 {
		t.Errorf("restored limits cpu=%d mem=%d, want 3/0", rec.CPULimit, rec.MemMiB)
	}
}

// TestFleet_RestoreContainer_FailoverRelocationIsNotBlockedByQuota is the
// regression the quota charge above must NOT cause.
//
// Host-loss relocation drives the same RestoreContainer handler, but it is not a
// new allocation: the container already existed and its project is already
// charged for it — the source row simply outlives the host that held it. A quota
// charge there would refuse to re-home any container occupying over half its
// project's ceiling, turning a tenancy limit into an availability limit at the
// exact moment availability is what the operator needs. Relocation is admitted
// against HOST capacity only.
func TestFleet_RestoreContainer_FailoverRelocationIsNotBlockedByQuota(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	setHostCapacity(t, c, dst.Name, 64, 65536, nil)
	if err := corrosion.InsertProject(ctx, src.DB, corrosion.ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	// 3000 of a 4096 MiB ceiling: fits, but over half — so a second charge for the
	// same container computes 3000 + 3000 > 4096 and refuses.
	if err := corrosion.UpsertProjectQuota(ctx, src.DB, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", MemMiBLimit: 4096,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	createSizedContainer(t, c, src, "ct-fail", "/acme", 0, 3000)
	repo, ts := backupContainer(t, c, src, "ct-fail")

	// Drive the relocation the way the failover coordinator does: from the
	// coordinator daemon, over peer mTLS, carrying the attempt token it will use
	// as provenance for the restored row (driveRemoteRestore's shape before
	// split-brain enforcement is latched, where no proof accompanies it).
	relocCtx := metadata.AppendToOutgoingContext(ctx, relocateTokenHeader, "attempt-1")
	st, err := c.PeerClient(src, dst).RestoreContainer(relocCtx, &pb.RestoreContainerRequest{
		RepoPath: repo, Name: "ct-fail", Timestamp: ts, HostName: dst.Name, Start: true,
	})
	if err == nil {
		for {
			_, rerr := st.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				err = rerr
				break
			}
		}
	}
	if err != nil {
		t.Fatalf("failover relocation of a container occupying 3000 of its project's 4096 MiB ceiling: %v — "+
			"relocation moves an allocation the project already carries; quota must not block it", err)
	}
	if rec, gerr := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct-fail"); gerr != nil || rec == nil {
		t.Fatalf("relocated row on the target: rec=%v err=%v", rec, gerr)
	}
}
