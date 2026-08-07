package grpcapi

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ImportVM admission. An import lands a full VM record — and with --start, a
// running domain — yet historically carried only the legacy read-only quota
// estimate (admitImport): no host capacity, no residency safety, no serialized
// reservation, no commit fence. These tests pin the same admission contract
// every other residency path carries.

// fakeImportStream drives the bidirectional ImportVM RPC from a test: the
// frames are received in order, then EOF; progress frames are recorded.
type fakeImportStream struct {
	grpc.ServerStream
	ctx    context.Context
	frames []*pb.ImportVMRequest
	i      int
	sent   []*pb.ImportVMProgress
}

func (f *fakeImportStream) Context() context.Context { return f.ctx }
func (f *fakeImportStream) Recv() (*pb.ImportVMRequest, error) {
	if f.i >= len(f.frames) {
		return nil, io.EOF
	}
	r := f.frames[f.i]
	f.i++
	return r, nil
}
func (f *fakeImportStream) Send(p *pb.ImportVMProgress) error {
	f.sent = append(f.sent, p)
	return nil
}

// stubQemuImg puts a fake qemu-img first on PATH: a shim that copies the
// source to the destination. The import's convert step requires qemu-img on
// PATH and CI runners do not install it (the first CI run of these tests
// failed exactly there); the stub makes the tests deterministic on every
// runner while still driving the real handler end to end. The copied raw
// bytes do not parse as qcow2, which only skips the best-effort size probe.
func stubQemuImg(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	shim := "#!/bin/sh\n" +
		"# stub qemu-img: 'info' answers the external-ref inspection with a\n" +
		"# backing-file-free raw image; 'convert' copies SRC (second-to-last\n" +
		"# arg) to DST (last arg).\n" +
		"if [ \"$1\" = info ]; then echo '{\"format\":\"raw\",\"virtual-size\":1048576}'; exit 0; fi\n" +
		"prev=\"\"; last=\"\"\n" +
		"for a; do prev=\"$last\"; last=\"$a\"; done\n" +
		"cp \"$prev\" \"$last\"\n"
	if err := writeFileHelper(dir+"/qemu-img", []byte(shim)); err != nil {
		t.Fatalf("write qemu-img stub: %v", err)
	}
	if err := chmodHelper(dir+"/qemu-img", 0o755); err != nil {
		t.Fatalf("chmod stub: %v", err)
	}
	t.Setenv("PATH", dir+":"+envPath())
}

// importSmallVM runs a full ImportVM of a one-disk Proxmox conf whose disk is
// mapped to a tiny local raw file, and returns the terminal error.
// extraConf lines are appended to the generated .conf (e.g. a net0 interface).
func importSmallVM(t *testing.T, s *Server, name, project string, memMiB int, start bool, extraConf ...string) error {
	t.Helper()
	stubQemuImg(t)
	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatalf("write staged disk: %v", err)
	}
	conf := fmt.Sprintf("name: %s\ncores: 1\nmemory: %d\nscsi0: local-lvm:%s-disk-0,size=1G\n", name, memMiB, name)
	for _, line := range extraConf {
		conf += line + "\n"
	}
	st := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{
		Name: name, SourceFormat: "proxmox", Project: project, Start: start,
		Chunk: []byte(conf), DiskMap: map[string]string{"scsi0": raw},
	}}}
	return s.ImportVM(st)
}

// TestImportVM_Start_RefusedWhenHostLacksCapacity: --start lands a running VM
// — the same consumption a create-and-start would have — and must be admitted
// against the host's headroom, not only the project's quota.
func TestImportVM_Start_RefusedWhenHostLacksCapacity(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s) // allocatable 1536 MiB
	s.virt = libvirtfake.New()

	err := importSmallVM(t, s, "imp-big", "", 2048, true)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("importing a 2048 MiB VM with --start onto a host with 1536 MiB allocatable: got %v, "+
			"want ResourceExhausted", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-big"); rec != nil {
		t.Fatalf("refused import still persisted a row: %+v", rec)
	}
	if s.virt.DomainExists("imp-big") {
		t.Fatal("refused import left a defined domain")
	}
}

// TestImportVM_Start_RefusedWhenInventoryIncomplete: --start is new residency;
// a host that cannot enumerate its own runtime refuses it. A STOPPED import of
// the same VM is not residency and still lands.
func TestImportVM_Start_RefusedWhenInventoryIncomplete(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	fake := libvirtfake.New()
	fake.FailListDomains = func() error { return fmt.Errorf("libvirtd unreachable") }
	s.virt = fake
	s.invalidateInventoryCache()

	err := importSmallVM(t, s, "imp-blind", "", 512, true)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("import with --start on a blind host: got %v, want FailedPrecondition", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-blind"); rec != nil {
		t.Fatalf("refused import still persisted a row: %+v", rec)
	}

	// A STOPPED import consumes no host runtime: it is a durable record, not
	// residency, and must not be blocked by the runtime probe.
	if err := importSmallVM(t, s, "imp-stopped", "", 512, false); err != nil {
		t.Fatalf("stopped import on a blind host: %v — a stopped row is not residency", err)
	}
	rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-stopped")
	if rec == nil || rec.State != "stopped" {
		t.Fatalf("stopped import row = %+v, want state stopped", rec)
	}
}

// TestImportVM_QuotaReserved_NotJustChecked: the import's cpu/mem quota charge
// goes through SERIALIZED admission — a competing reservation that sorts
// earlier consumes the quota headroom, so the import must stand down even
// though committed usage alone would fit. The legacy read-only estimate cannot
// see in-flight reservations at all.
func TestImportVM_QuotaReserved_NotJustChecked(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	ctx := context.Background()
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "acme", VCPULimit: 4, MemMiBLimit: 1024,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	// An earlier in-flight claimant holds 512 of the 1024 MiB.
	plantReservation(t, s, "00000000-earlier", "test-host", "acme", 1, 512)

	err := importSmallVM(t, s, "imp-q", "acme", 1024, false)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("import of 1024 MiB with 512 already reserved of a 1024 quota: got %v, "+
			"want ResourceExhausted — the estimate must be a reservation, not a glance", err)
	}
}

// plantQuotaReservation plants a nonterminal PROJECT-quota reservation holding
// an arbitrary QuotaAmount — the in-flight claimant a racing admission must
// yield to. Unlike plantReservation it charges no host capacity, so a test can
// isolate a single quota dimension.
func plantQuotaReservation(t *testing.T, s *Server, id, project string, amt corrosion.QuotaAmount) {
	t.Helper()
	rv := corrosion.ReservationVector{
		Project: project, ProjectCPU: amt.VCPU, ProjectMemMiB: amt.MemMiB,
		ProjectDiskGiB: amt.DiskGiB, ProjectNIC: amt.NIC,
	}
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode reservation: %v", err)
	}
	if err := corrosion.InsertOperation(context.Background(), s.db, corrosion.OperationRecord{
		ID: id, Method: "CreateVM", Project: project, ResourceKind: "capacity",
		OperationKind: string(corrosion.OpResourceUpdateRunning), ReservationJSON: enc,
	}); err != nil {
		t.Fatalf("plant reservation %s: %v", id, err)
	}
}

// quotaProject seeds a project with the given limits (0 = unbounded), so a test
// can bind exactly one quota dimension.
func quotaProject(t *testing.T, s *Server, name string, q corrosion.ProjectQuotaRecord) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: name}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	q.ProjectName = name
	if err := corrosion.UpsertProjectQuota(ctx, s.db, q); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
}

// TestImportVM_DiskQuotaReserved_NotJustChecked: the DISK dimension goes through
// the same serialized reservation as cpu/mem. It used to be covered only by the
// read-only pre-convert estimate, which cannot see an in-flight claim — so two
// concurrent imports each saw the full remaining disk budget, each fit, and both
// committed over the project's limit.
func TestImportVM_DiskQuotaReserved_NotJustChecked(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	// Disk is the only bounded dimension, so nothing else can explain a refusal.
	quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{DiskGiBLimit: 2})

	// An earlier in-flight claimant holds 2 of the 2 GiB. Committed usage is
	// still zero, so the unserialized estimate sees the whole budget free.
	plantQuotaReservation(t, s, "00000000-earlier", "acme", corrosion.QuotaAmount{DiskGiB: 2})

	err := importSmallVM(t, s, "imp-disk", "acme", 512, false)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("import of a 1 GiB disk with 2 of a 2 GiB disk quota already reserved: got %v, "+
			"want ResourceExhausted — disk must participate in the reservation, not a glance", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-disk"); rec != nil {
		t.Fatalf("refused import still persisted a row: %+v", rec)
	}
}

// TestImportVM_NICQuotaReserved_NotJustChecked is the disk test's sibling for
// the other dimension the reservation used to omit.
func TestImportVM_NICQuotaReserved_NotJustChecked(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{NICLimit: 1})
	plantQuotaReservation(t, s, "00000000-earlier", "acme", corrosion.QuotaAmount{NIC: 1})

	err := importSmallVM(t, s, "imp-nic", "acme", 512, false,
		"net0: virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0")
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("import of a 1-NIC VM with the whole 1-NIC quota already reserved: got %v, "+
			"want ResourceExhausted — NICs must participate in the reservation", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-nic"); rec != nil {
		t.Fatalf("refused import still persisted a row: %+v", rec)
	}
}

// TestImportVM_DiskQuotaAdmitsWhenItFits guards the other direction: the new
// dimensions must not refuse an import that genuinely fits.
func TestImportVM_DiskQuotaAdmitsWhenItFits(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	s.virt = libvirtfake.New()
	quotaProject(t, s, "acme", corrosion.ProjectQuotaRecord{DiskGiBLimit: 2, NICLimit: 2})

	if err := importSmallVM(t, s, "imp-fits", "acme", 512, false,
		"net0: virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0"); err != nil {
		t.Fatalf("import of a 1 GiB / 1 NIC VM into a 2 GiB / 2 NIC quota: %v", err)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-fits"); rec == nil {
		t.Fatal("import that fits its quota did not persist a row")
	}
}

func writeFileHelper(path string, data []byte) error  { return os.WriteFile(path, data, 0o644) }
func chmodHelper(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
func envPath() string                                 { return os.Getenv("PATH") }
