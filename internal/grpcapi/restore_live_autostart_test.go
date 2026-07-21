package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// seedLiveRepo creates a repo with one root-disk manifest of `data`,
// optionally embedding `specJSON` (the metadata path). Returns repo dir
// + manifest timestamp.
func seedLiveRepo(t *testing.T, data []byte, specJSON string) (string, string) {
	t.Helper()
	repoDir := t.TempDir()
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	ts := "2026-05-11T00:00:00Z"
	if _, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(data),
		pbsstore.PushOptions{VMName: "vm1", DiskName: "root", Timestamp: ts, VMSpecJSON: specJSON}); err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	return repoDir, ts
}

// runRestoreLiveUntil starts RestoreLive in a goroutine and waits until a
// frame of `phase` appears (or the RPC returns). Returns the stream and a
// cancel func; the caller cancels to unwind the keep-open path.
func runRestoreLiveUntil(t *testing.T, s *Server, req *pb.RestoreLiveRequest, phase pb.RestoreLiveProgress_Phase) (*restoreLiveStream, context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(adminCtx())
	stream := &restoreLiveStream{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.RestoreLive(req, stream) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stream.mu.Lock()
		var seen bool
		for _, p := range stream.out {
			if p.Phase == phase {
				seen = true
			}
		}
		stream.mu.Unlock()
		if seen {
			return stream, cancel, done
		}
		select {
		case err := <-done:
			// RPC returned before the phase (e.g. error or blockpull-complete).
			done <- err
			return stream, cancel, done
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never reached phase %v; frames=%d", phase, len(stream.out))
	return nil, cancel, done
}

func sawPhase(stream *restoreLiveStream, phase pb.RestoreLiveProgress_Phase) bool {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	for _, p := range stream.out {
		if p.Phase == phase {
			return true
		}
	}
	return false
}

func testSpecJSON(t *testing.T, name string) string {
	t.Helper()
	b, err := json.Marshal(&pb.VMSpec{
		Name: name, Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi",
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	return string(b)
}

func TestResolveRestoreSpec_Precedence(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: testSpecJSON(t, "existing")},
		nil, nil,
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	spec, err := s.resolveRestoreSpec(ctx,
		&pb.RestoreLiveRequest{
			VmName:       "vm1",
			FromExisting: true,
			Spec:         &pb.VMSpec{Name: "explicit", Cpu: 8, MemoryMib: 8192},
		},
		&pbsstore.Manifest{VMSpecJSON: testSpecJSON(t, "manifest")},
	)
	if err != nil {
		t.Fatalf("explicit spec: %v", err)
	}
	if spec.Name != "explicit" || spec.Cpu != 8 {
		t.Errorf("explicit spec precedence = %+v", spec)
	}

	spec, err = s.resolveRestoreSpec(ctx,
		&pb.RestoreLiveRequest{VmName: "vm1", FromExisting: true},
		&pbsstore.Manifest{VMSpecJSON: testSpecJSON(t, "manifest")},
	)
	if err != nil {
		t.Fatalf("manifest spec: %v", err)
	}
	if spec.Name != "manifest" {
		t.Errorf("manifest should beat existing spec, got %+v", spec)
	}

	spec, err = s.resolveRestoreSpec(ctx,
		&pb.RestoreLiveRequest{VmName: "vm1", FromExisting: true},
		&pbsstore.Manifest{},
	)
	if err != nil {
		t.Fatalf("existing spec: %v", err)
	}
	if spec.Name != "existing" {
		t.Errorf("existing fallback spec = %+v", spec)
	}

	_, err = s.resolveRestoreSpec(ctx,
		&pb.RestoreLiveRequest{VmName: "vm1", FromExisting: true},
		&pbsstore.Manifest{VMSpecJSON: `{"name":`},
	)
	if status.Code(err) != codes.Internal {
		t.Fatalf("bad manifest should fail instead of falling back to existing spec, got %v", err)
	}

	_, err = s.resolveRestoreSpec(ctx,
		&pb.RestoreLiveRequest{VmName: "vm1"},
		&pbsstore.Manifest{},
	)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing metadata without from_existing: got %v", err)
	}
}

func TestRestoreLive_AutoStart_FromManifestMetadata(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake

	data := make([]byte, pbsstore.ChunkSize) // one chunk
	repoDir, ts := seedLiveRepo(t, data, testSpecJSON(t, "vm1"))
	target := filepath.Join(t.TempDir(), "live.qcow2")

	stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer cancel()

	if !sawPhase(stream, pb.RestoreLiveProgress_DEFINING) {
		t.Error("missing DEFINING frame")
	}
	// Domain was defined + started in libvirt.
	events := fake.EventLog()
	var defined, started bool
	for _, e := range events {
		if e.Op == "define" && e.Domain == "vm1" {
			defined = true
		}
		if e.Op == "start" && e.Domain == "vm1" {
			started = true
		}
	}
	if !defined || !started {
		t.Errorf("expected define+start in libvirt; events=%+v", events)
	}
	// Domain XML points at the overlay.
	xml, _ := fake.DumpXML("vm1")
	if !contains2(xml, target) {
		t.Errorf("domain XML does not reference overlay %q", target)
	}
	// Corrosion has a running VM with the overlay-backed root disk.
	rec, err := corrosion.GetVM(context.Background(), s.db, "vm1")
	if err != nil || rec == nil {
		t.Fatalf("GetVM: %v / %v", rec, err)
	}
	if rec.State != "running" {
		t.Errorf("vm state = %q, want running", rec.State)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if len(disks) != 1 || disks[0].Path != target {
		t.Errorf("disk record = %+v, want path %q", disks, target)
	}

	cancel()
	<-done
}

// TestRestoreLive_AutoStart_PopulatesHardwareTables verifies autoDefineRestoredVM
// populates the v42 vm_nics table for its network attachment (mirroring
// CreateVM/task 7.1) and a vm_pci_intent row for a spec that carries Devices
// (the source VM had PCI passthrough) — even though the restored domain XML
// never attaches a matching <hostdev> (a disk replica/NBD overlay carries no
// physical device to recover), leaving that gap for the Phase-6 backfill audit
// to confirm/reconcile. hardware_adoption_state stays 'pending': a live-restore
// does not self-certify adoption.
func TestRestoreLive_AutoStart_PopulatesHardwareTables(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake

	spec := &pb.VMSpec{
		Name: "vm1", Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi",
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
		Devices: []*pb.DeviceSpec{{Address: "41:00.0"}}, // non-canonical BDF, see the DeviceID assertion below
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, string(specJSON))
	target := filepath.Join(t.TempDir(), "live.qcow2")

	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer cancel()

	ctx := context.Background()
	ifaces, err := corrosion.GetVMInterfaces(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].NetworkName != "lo" {
		t.Fatalf("vm_interfaces = %+v, want 1 row on lo", ifaces)
	}

	nics, err := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "vm1")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	if len(nics) != 1 || nics[0].NetworkName != "lo" || nics[0].Model != "e1000" || nics[0].MAC != ifaces[0].MAC {
		t.Fatalf("vm_nics = %+v, want 1 e1000 row on lo matching vm_interfaces MAC %q", nics, ifaces[0].MAC)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("vm_pci_intent = %+v, want 1 row", intents)
	}
	wantID := corrosion.DeterministicPCIIntentID("vm1",
		corrosion.CanonicalPCISelector(&pb.DeviceSpec{Address: "0000:41:00.0"}), 0)
	if intents[0].DeviceID != wantID {
		t.Errorf("vm_pci_intent[0].DeviceID = %q, want %q (derived from the canonical BDF)", intents[0].DeviceID, wantID)
	}

	state, _, err := corrosion.GetHardwareAdoptionState(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "pending" {
		t.Errorf("hardware_adoption_state = %q, want pending (live-restore does not self-certify adoption)", state)
	}

	cancel()
	<-done
}

func TestRestoreLive_AutoStart_OperatorSuppliedSpec(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake

	// Manifest WITHOUT embedded metadata.
	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, "")
	target := filepath.Join(t.TempDir(), "live.qcow2")

	stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true, NewName: "vm1-restored",
		Spec: &pb.VMSpec{Name: "ignored", Cpu: 4, MemoryMib: 4096, Machine: "q35", Firmware: "uefi"},
	}, pb.RestoreLiveProgress_STARTED)
	defer cancel()
	_ = stream

	rec, err := corrosion.GetVM(context.Background(), s.db, "vm1-restored")
	if err != nil || rec == nil {
		t.Fatalf("expected vm1-restored, got %v / %v", rec, err)
	}
	if fake.DomainExists("ignored") {
		t.Error("spec.Name should have been overridden by --name")
	}
	cancel()
	<-done
}

func TestRestoreLive_AutoStart_NoMetadataNoSpec_Fails(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.virt = libvirtfake.New()

	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, "") // no metadata
	target := filepath.Join(t.TempDir(), "live.qcow2")

	stream := &restoreLiveStream{ctx: adminCtx()}
	err := s.RestoreLive(&pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, stream)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
}

func TestRestoreLive_AutoStart_NameCollision(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.virt = libvirtfake.New()

	// An existing VM named vm1.
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, testSpecJSON(t, "vm1"))
	target := filepath.Join(t.TempDir(), "live.qcow2")

	stream := &restoreLiveStream{ctx: adminCtx()}
	err := s.RestoreLive(&pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, stream)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("want AlreadyExists, got %v", err)
	}
}

func TestRestoreLive_AutoStart_StartFails_RollsBack(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	fake.FailStartDomain = func(string) error { return context.DeadlineExceeded }
	s.virt = fake

	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, testSpecJSON(t, "vm1"))
	target := filepath.Join(t.TempDir(), "live.qcow2")

	stream := &restoreLiveStream{ctx: adminCtx()}
	err := s.RestoreLive(&pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, stream)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal on start failure, got %v", err)
	}
	// Domain was undefined on rollback; no corrosion record written.
	var undefined bool
	for _, e := range fake.EventLog() {
		if e.Op == "undefine" && e.Domain == "vm1" {
			undefined = true
		}
	}
	if !undefined {
		t.Error("expected domain to be undefined after start failure")
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); rec != nil {
		t.Error("no vms record should be written when start fails")
	}
}

func TestRestoreLive_AutoStart_Blockpull_SelfTerminates(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	// Default BlockJobStatus returns Found=false ⇒ "done" immediately.
	s.virt = fake

	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, testSpecJSON(t, "vm1"))
	target := filepath.Join(t.TempDir(), "live.qcow2")

	stream := &restoreLiveStream{ctx: adminCtx()}
	// With blockpull the handler returns on its own — no cancel needed.
	done := make(chan error, 1)
	go func() {
		done <- s.RestoreLive(&pb.RestoreLiveRequest{
			RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
			TargetPath: target, AutoStart: true, Blockpull: true,
		}, stream)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RestoreLive: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blockpull restore did not self-terminate")
	}
	if !sawPhase(stream, pb.RestoreLiveProgress_LOCALIZED) {
		t.Error("expected LOCALIZED frame")
	}
	var pulled bool
	for _, e := range fake.EventLog() {
		if e.Op == "blockpull" {
			pulled = true
		}
	}
	if !pulled {
		t.Error("expected a blockpull call")
	}
}

func TestBackupSnapshot_CapturesVMSpec(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()

	tmp := t.TempDir()
	diskPath := filepath.Join(tmp, "disk.raw")
	if err := writeFileBytes(t, diskPath, make([]byte, pbsstore.ChunkSize)); err != nil {
		t.Fatal(err)
	}
	specJSON := testSpecJSON(t, "vm1")
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: specJSON},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "host-a",
			Path: diskPath, SizeBytes: pbsstore.ChunkSize, StorageType: "local", TargetDev: "vda",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	repoDir := filepath.Join(tmp, "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("Init: %v", err)
	}

	stream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "vm1", DiskName: "root", RepoPath: repoDir, Timestamp: "2026-05-11T10:00:00Z",
	}, stream); err != nil {
		t.Fatalf("BackupSnapshot: %v", err)
	}
	repo, _ := pbsstore.Open(repoDir)
	m, err := repo.GetManifest("vm1", "2026-05-11T10:00:00Z", "root")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if m.VMSpecJSON != specJSON {
		t.Errorf("manifest VMSpecJSON = %q, want %q", m.VMSpecJSON, specJSON)
	}
}

func writeFileBytes(t *testing.T, path string, b []byte) error {
	t.Helper()
	return os.WriteFile(path, b, 0640)
}
