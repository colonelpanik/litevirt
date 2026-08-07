package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Promotion admission. PromoteReplica defines and starts a full-sized VM — the
// same consumption a create would have — and admitted nothing: not host
// capacity, not host safety, and (renamed) not project quota. These tests pin
// the doPromoteLocal admission gate the way the create/start/migrate paths are
// pinned.

const promoteReplicaFile = "vm1-root-20260101000000.raw"

// seedPromotableVM stages the durable record + replica file doPromoteLocal
// needs: vm1 owned by ownerHost, a root-disk record, and a matching replica in
// a local pool on s. Returns the pool dir for artifact assertions.
func seedPromotableVM(t *testing.T, s *Server, ownerHost, ownerState, project string, cpu, memMiB int) string {
	t.Helper()
	ctx := context.Background()
	if s.virt == nil {
		s.virt = libvirtfake.New()
	}
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})

	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: int32(cpu), MemoryMib: int32(memMiB)})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{
			Name: "vm1", HostName: ownerHost, State: "running", Spec: string(specJSON),
			Project: project, CPUActual: cpu, MemActual: memMiB,
		},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: ownerHost,
			Path: "/gone", SizeBytes: 1 << 20, StorageType: "local",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if ownerHost != s.hostName {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: ownerHost, Address: "10.0.0.66", State: ownerState,
		}); err != nil {
			t.Fatalf("InsertHost(%s): %v", ownerHost, err)
		}
	}
	if err := os.WriteFile(filepath.Join(poolDir, promoteReplicaFile), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatalf("write replica: %v", err)
	}
	return poolDir
}

// promoteVM drives the full PromoteReplica handler and returns its terminal error.
func promoteVM(s *Server, req *pb.PromoteReplicaRequest) error {
	req.TargetPool = "replica-pool"
	req.NoLocalize = true
	return s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
}

// assertNoPromotedArtifacts fails if the refused promotion left a live disk,
// a defined domain, or a promote marker behind.
func assertNoPromotedArtifacts(t *testing.T, s *Server, poolDir, domain string) {
	t.Helper()
	if s.virt.DomainExists(domain) {
		t.Errorf("refused promotion left domain %q defined", domain)
	}
	entries, _ := os.ReadDir(poolDir)
	for _, e := range entries {
		if e.Name() != promoteReplicaFile {
			t.Errorf("refused promotion left artifact %q in the pool", e.Name())
		}
	}
	if s.promoteMarkerPresent(domain) {
		t.Errorf("refused promotion left a promote marker for %q", domain)
	}
}

// TestPromoteReplica_SameName_RefusedWhenHostLacksCapacity: a fresh same-name
// promotion is a full-sized VM appearing on this host and must pass host
// admission BEFORE any disk or domain mutation.
func TestPromoteReplica_SameName_RefusedWhenHostLacksCapacity(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s) // allocatable 1536 MiB
	poolDir := seedPromotableVM(t, s, "dead-host", "failed", "", 2, 2048)

	err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("promoting a 2048 MiB VM onto a host with 1536 MiB allocatable: got %v, want ResourceExhausted", err)
	}
	assertNoPromotedArtifacts(t, s, poolDir, "vm1")
	rec, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
	if rec == nil || rec.HostName != "dead-host" {
		t.Fatalf("refused promotion disturbed the durable record: %+v", rec)
	}
}

// TestPromoteReplica_SameName_RefusedWhenInventoryIncomplete: the promoting
// host cannot enumerate its own runtime — new residency is refused exactly as
// a create would be, before anything is mutated.
func TestPromoteReplica_SameName_RefusedWhenInventoryIncomplete(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	fake := libvirtfake.New()
	fake.FailListDomains = func() error { return fmt.Errorf("libvirtd unreachable") }
	s.virt = fake
	s.invalidateInventoryCache()
	poolDir := seedPromotableVM(t, s, "dead-host", "failed", "", 1, 512)

	err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("promoting onto a host with incomplete inventory: got %v, want FailedPrecondition", err)
	}
	assertNoPromotedArtifacts(t, s, poolDir, "vm1")
}

// TestPromoteReplica_Renamed_RefusedWhenQuotaExhausted: a renamed promotion is
// a NEW allocation the project does not yet carry, so it must reserve project
// quota — the host has room, only the quota can refuse this.
func TestPromoteReplica_Renamed_RefusedWhenQuotaExhausted(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	poolDir := seedPromotableVM(t, s, "dead-host", "failed", "acme", 2, 2048)
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	// vm1 (2 vCPU / 2048 MiB) already consumes the project's usage; a second
	// allocation of the same size exceeds both limits.
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "acme", VCPULimit: 3, MemMiBLimit: 3000,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}

	err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1", NewName: "vm1-dr"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("renamed promotion past the project quota: got %v, want ResourceExhausted — "+
			"a renamed promotion inserts a second allocation and must be admitted against quota", err)
	}
	assertNoPromotedArtifacts(t, s, poolDir, "vm1-dr")
	if rec, _ := corrosion.GetVM(ctx, s.db, "vm1-dr"); rec != nil {
		t.Fatalf("refused renamed promotion still persisted a row: %+v", rec)
	}
}

// TestPromoteReplica_SameName_DoesNotDoubleChargeQuota: a takeover promotion
// re-homes an allocation the project already counts. Charging quota again
// would refuse the disaster-recovery of any VM over half its project's ceiling
// — availability lost to an accounting artifact.
func TestPromoteReplica_SameName_DoesNotDoubleChargeQuota(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	seedPromotableVM(t, s, "dead-host", "failed", "acme", 2, 2048)
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "acme", VCPULimit: 3, MemMiBLimit: 3000,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}

	if err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"}); err != nil {
		t.Fatalf("same-name promotion of a VM using 2048 of its project's 3000 MiB ceiling: %v — "+
			"a re-home must not charge the project twice", err)
	}
	rec, _ := corrosion.GetVM(ctx, s.db, "vm1")
	if rec == nil || rec.HostName != s.hostName {
		t.Fatalf("promotion did not re-home vm1: %+v", rec)
	}
}

// TestPromoteReplica_Renamed_FenceRefusalUnwindsTheStartedDomain: the renamed
// insert is fenced on the quota authority, checked immediately before the
// durable write — by which time the domain is already RUNNING. A refusal that
// late must unwind everything this attempt created (domain, live disk, promote
// marker), leave the original durable VM untouched, and persist nothing.
func TestPromoteReplica_Renamed_FenceRefusalUnwindsTheStartedDomain(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	fake := libvirtfake.New()
	s.virt = fake
	s.enfProjectAuthority = true
	s.gate = fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.ProjectAuthorityV1: true}}
	authorityHost(t, s, "acme") // this host holds acme's authority at epoch 1
	poolDir := seedPromotableVM(t, s, "dead-host", "failed", "acme", 1, 512)

	// Move the authority between admission and the insert. StartDomain is the
	// last runtime step before persistence, so its hook is exactly the window
	// the fence exists for: the grant was made under epoch 1, and by commit
	// time a takeover has minted epoch 2 on another node.
	fake.FailStartDomain = func(string) error {
		if _, applied, err := corrosion.TakeoverProjectAuthority(ctx, s.db, "acme", "usurper", "planned", "", 1); err != nil || !applied {
			t.Fatalf("takeover mid-promote: applied=%v err=%v", applied, err)
		}
		return nil // the domain still starts; only the fence may stop the commit
	}

	err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1", NewName: "vm1-dr"})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("renamed promotion across an authority handoff: got %v, want Aborted", err)
	}
	assertNoPromotedArtifacts(t, s, poolDir, "vm1-dr")
	if rec, _ := corrosion.GetVM(ctx, s.db, "vm1-dr"); rec != nil {
		t.Fatalf("fence-refused promotion still persisted a row: %+v", rec)
	}
	orig, _ := corrosion.GetVM(ctx, s.db, "vm1")
	if orig == nil || orig.HostName != "dead-host" {
		t.Fatalf("fence-refused promotion disturbed the original record: %+v", orig)
	}
}

// TestPromoteReplica_MarkedRunningRetry_AdoptedWithoutDoubleReserve: a crash-
// recovery retry that finds a running domain positively identified as our own
// prior promotion (host-local marker + running) adopts it WITHOUT reserving its
// capacity a second time — the runtime consumption already exists. The host is
// sized so the VM fits exactly once: any second reservation is arithmetically
// impossible, so the retry only succeeds by taking the adoption path.
func TestPromoteReplica_MarkedRunningRetry_AdoptedWithoutDoubleReserve(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := context.Background()
	admissionHost(t, s) // allocatable 1536 MiB
	fake := libvirtfake.New()
	s.virt = fake
	seedPromotableVM(t, s, "dead-host", "failed", "", 1, 1536)

	// The prior attempt started the domain and wrote the marker, then crashed
	// before persisting the row.
	fake.SetState("vm1", "running")
	if err := s.writePromoteMarker("vm1", "prior-proof"); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	s.invalidateInventoryCache()

	if err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"}); err != nil {
		t.Fatalf("retry adopting our own marked running promotion: %v — "+
			"adoption must not reserve capacity the running domain already consumes", err)
	}
	if st, _ := fake.DomainState("vm1"); st != "running" {
		t.Fatalf("adopted domain state = %q, want running (never destroy+rebuild our own promotion)", st)
	}
	rec, _ := corrosion.GetVM(ctx, s.db, "vm1")
	if rec == nil || rec.HostName != s.hostName {
		t.Fatalf("adoption did not persist the re-homed row: %+v", rec)
	}
	cpu, mem, rerr := corrosion.HostReserved(ctx, s.db, "test-host")
	if rerr != nil || cpu != 0 || mem != 0 {
		t.Fatalf("after adoption HostReserved = %d/%d (err=%v), want 0/0", cpu, mem, rerr)
	}
	if s.promoteMarkerPresent("vm1") {
		t.Fatal("marker must be removed once the re-homed row persists")
	}
}
