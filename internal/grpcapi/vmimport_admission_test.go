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

// importSmallVM runs a full ImportVM of a one-disk Proxmox conf whose disk is
// mapped to a tiny local raw file, and returns the terminal error.
func importSmallVM(t *testing.T, s *Server, name, project string, memMiB int, start bool) error {
	t.Helper()
	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatalf("write staged disk: %v", err)
	}
	conf := fmt.Sprintf("name: %s\ncores: 1\nmemory: %d\nscsi0: local-lvm:%s-disk-0,size=1G\n", name, memMiB, name)
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

func writeFileHelper(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }
