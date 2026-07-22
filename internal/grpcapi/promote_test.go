package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// promoteDomainAlreadyStarted must adopt (never destroy) a RUNNING domain from a prior
// promotion — recognized same-proof (start_attempted) OR cross-proof (marker), since a
// fresh proof each failover cycle carries empty step_state. This is the H4 data-loss guard.
func TestPromoteDomainAlreadyStarted(t *testing.T) {
	cases := []struct {
		name                                                       string
		startedStep, startAttempted, marker, exists, running, want bool
	}{
		{"started + running → adopt", true, false, false, true, true, true},
		{"started but domain ABSENT → do NOT adopt (rebuild)", true, false, false, false, false, false},
		{"started but domain stopped → do NOT adopt (restart/rebuild)", true, false, false, true, false, false},
		{"same-proof: start_attempted + running", false, true, false, true, true, true},
		{"cross-proof: marker + running (fresh proof, no steps)", false, false, true, true, true, true},
		{"marker but NOT running → not adopted (safe to (re)start)", false, false, true, true, false, false},
		{"running but neither step nor marker → NOT ours, don't adopt", false, false, false, true, true, false},
		{"marker but domain absent", false, false, true, false, false, false},
		{"nothing", false, false, false, false, false, false},
	}
	for _, c := range cases {
		if got := promoteDomainAlreadyStarted(c.startedStep, c.startAttempted, c.marker, c.exists, c.running); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// promoteDiskBuilt honors disk_built only when the live disk actually exists (H5: a
// forward-only checkpoint + an error path that removed the disk would otherwise skip the
// rebuild and loop).
func TestPromoteDiskBuilt(t *testing.T) {
	if !promoteDiskBuilt(true, true) {
		t.Error("disk_built + livePath exists → built")
	}
	if promoteDiskBuilt(true, false) {
		t.Error("disk_built but livePath MISSING → must rebuild (not built)")
	}
	if promoteDiskBuilt(false, true) {
		t.Error("no checkpoint → not built")
	}
}

// The host-local promote marker round-trips and is keyed per target name.
func TestPromoteMarker_RoundTrip(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	if s.promoteMarkerPresent("vm1") {
		t.Fatal("no marker initially")
	}
	if err := s.writePromoteMarker("vm1", "proof-1"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !s.promoteMarkerPresent("vm1") {
		t.Fatal("marker must be present after write")
	}
	if s.promoteMarkerPresent("vm2") {
		t.Fatal("marker is per-name")
	}
}

// An INDETERMINATE stat error (not ENOENT) must fail CLOSED — assume the marker may be present
// so a retry adopts a possibly-ours running domain rather than destroy+rebuild it.
func TestPromoteMarkerPresent_FailsClosedOnStatError(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	// A name longer than PATH_MAX makes os.Stat fail with ENAMETOOLONG — a deterministic
	// non-ENOENT stat error (Go treats ENOENT/ENOTDIR as IsNotExist, so those wouldn't
	// exercise the fail-closed branch).
	if !s.promoteMarkerPresent(strings.Repeat("a", 5000)) {
		t.Fatal("an indeterminate stat error must fail closed (marker assumed present)")
	}
	if got := s.promoteMarkerPath("vm1"); filepath.Base(got) != "vm1" {
		t.Fatalf("marker path = %q, want basename vm1", got)
	}
	s.removePromoteMarker("vm1")
	if s.promoteMarkerPresent("vm1") {
		t.Fatal("marker must be gone after remove")
	}
}

// TestPromoteReplica_RenamedPopulatesHardwareTables drives the ONE full
// PromoteReplica path that actually persists a fresh vms row (the --new-name
// takeover-alongside branch of doPromoteLocal): it must populate vm_nics for
// the rebuilt network attachment (mirroring CreateVM/task 7.1), carry ZERO
// vm_pci_intent rows (a disk replica has no hostdev record to recover — G1's
// firmware refusal covers the analogous vTPM case), and leave
// hardware_adoption_state at its schema default 'pending' since a promotion
// does not self-certify adoption.
func TestPromoteReplica_RenamedPopulatesHardwareTables(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()

	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})

	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// A replica file matching the (vm, disk) naming pattern doPromoteLocal
	// scans the pool dir for (isReplicaOf): "<vm>-<disk>-<timestamp>.raw".
	replicaPath := filepath.Join(poolDir, "vm1-root-20260101000000.raw")
	if err := os.WriteFile(replicaPath, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write replica: %v", err)
	}

	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}

	ifaces, err := corrosion.GetVMInterfaces(ctx, s.db, "vm1-promoted")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].NetworkName != "lo" {
		t.Fatalf("vm_interfaces = %+v, want 1 row on lo", ifaces)
	}

	nics, err := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "vm1-promoted")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	if len(nics) != 1 || nics[0].NetworkName != "lo" || nics[0].Model != "e1000" || nics[0].MAC != ifaces[0].MAC {
		t.Fatalf("vm_nics = %+v, want 1 e1000 row on lo matching vm_interfaces MAC %q", nics, ifaces[0].MAC)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "vm1-promoted")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 0 {
		t.Fatalf("vm_pci_intent = %+v, want 0 rows (promote never carries PCI passthrough)", intents)
	}

	state, _, err := corrosion.GetHardwareAdoptionState(ctx, s.db, "vm1-promoted")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "pending" {
		t.Errorf("hardware_adoption_state = %q, want pending (promote does not self-certify adoption)", state)
	}
}
