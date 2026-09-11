package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A cutover cannot be one commit. The replacement transition is a database write;
// freeing what the replaced VM owned is filesystem and storage-driver work that
// has to follow it — and the transition DISPLACES the rows describing what to
// free. So the journal carries a manifest across that gap, and these are the
// three boundaries a process can die at.

var errCrash = errors.New("simulated process exit")

// crashAt makes the handler abandon the cutover at one boundary, which is what a
// process dying there leaves behind.
func crashAt(s *Server, stage string) {
	s.SetCutoverCrashHook(func(got string) error {
		if got == stage {
			return errCrash
		}
		return nil
	})
}

// restartFixture is cutoverFixture plus a cloud-init ISO for the replaced VM, so
// the cleanup has a whole-file artifact to free as well as a volume.
func restartFixture(t *testing.T) (s *Server, originalDisk, replacementDisk, iso string) {
	t.Helper()
	s, _, originalDisk, replacementDisk = cutoverFixture(t)
	iso = lv.CloudInitISOPath(s.dataDir, "app")
	if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, iso)
	return s, originalDisk, replacementDisk, iso
}

// pendingCleanups is the journal's answer to "what did an interrupted attempt
// leave that a restart has to finish".
func pendingCleanups(t *testing.T, s *Server) []corrosion.VMReplaceCleanup {
	t.Helper()
	pending, err := corrosion.ListVMReplaceCleanups(context.Background(), s.db, s.hostName)
	if err != nil {
		t.Fatalf("ListVMReplaceCleanups: %v", err)
	}
	return pending
}

// BOUNDARY 1 — the process dies BEFORE the transition commits.
//
// The manifest is journaled by then, but a planned operation authorizes nothing:
// the replaced VM still owns everything the manifest lists, so a restart that
// acted on it would destroy a live VM's disks. Resume must do nothing at all.
func TestCutoverRestart_BeforeCommitDestroysNothing(t *testing.T) {
	s, original, replacement, iso := restartFixture(t)
	ctx := adminCtx()

	crashAt(s, "before-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon at the before-commit boundary")
	}

	// Nothing is authorized, so a restart finds no work.
	if pending := pendingCleanups(t, s); len(pending) != 0 {
		t.Fatalf("a PLANNED operation authorized cleanup: %+v", pending)
	}
	s.SetCutoverCrashHook(nil)
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume after an uncommitted attempt: %v", err)
	}
	for _, p := range []string{original, replacement, iso} {
		if !exists(p) {
			t.Errorf("an uncommitted attempt destroyed %s", p)
		}
	}
	// The transition never landed, so the replacement is still under its own name.
	if vm, err := corrosion.GetVM(ctx, s.db, "app-next"); err != nil || vm == nil {
		t.Fatalf("replacement after an uncommitted attempt: %+v err=%v", vm, err)
	}

	// And the cutover is still retryable, from the same journaled manifest.
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("retry after an uncommitted attempt: %v", err)
	}
	if exists(original) {
		t.Error("the retry left the replaced VM's volume behind")
	}
	if exists(iso) {
		t.Error("the retry left the replaced VM's cloud-init ISO behind")
	}
	if !exists(replacement) {
		t.Error("the retry destroyed the replacement's disk")
	}
}

// BOUNDARY 2 — the process dies IMMEDIATELY AFTER the transition commits.
//
// The name now belongs to the replacement and the rows that said what the
// replaced VM owned are gone. Only the journal knows, and a restart must finish
// the destruction from it — without re-running the transition, and without
// reading the reused name.
func TestCutoverRestart_AfterCommitFinishesCleanup(t *testing.T) {
	s, original, replacement, iso := restartFixture(t)
	ctx := adminCtx()

	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon at the after-commit boundary")
	}

	// The transition IS committed…
	vm, err := corrosion.GetVM(ctx, s.db, "app")
	if err != nil || vm == nil {
		t.Fatalf("the transition did not commit: %+v err=%v", vm, err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].Path != replacement {
		t.Fatalf("the name holds %+v, want the replacement's disk", disks)
	}
	// …and the destruction has NOT run.
	if !exists(original) || !exists(iso) {
		t.Fatal("the after-commit boundary already destroyed the replaced VM's resources")
	}
	pending := pendingCleanups(t, s)
	if len(pending) != 1 {
		t.Fatalf("committed cleanups awaiting a restart = %d, want 1", len(pending))
	}
	if pending[0].Manifest.ReplacedVM != "app" || len(pending[0].Manifest.Disks) != 1 {
		t.Fatalf("journaled manifest = %+v, want the replaced VM's own records", pending[0].Manifest)
	}

	// The restart finishes it.
	s.SetCutoverCrashHook(nil)
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if exists(original) {
		t.Error("resume left the replaced VM's volume behind")
	}
	if exists(iso) {
		t.Error("resume left the replaced VM's cloud-init ISO behind")
	}
	if !exists(replacement) {
		t.Error("resume destroyed the REPLACEMENT's disk")
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("cleanup is not recorded as done: %+v", left)
	}
	// Idempotent: a second restart must be a no-op, not a second destruction pass.
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if !exists(replacement) {
		t.Error("a repeated resume destroyed the replacement's disk")
	}
	// And the replacement is still the live VM at the name.
	if vm, err := corrosion.GetVM(ctx, s.db, "app"); err != nil || vm == nil {
		t.Fatalf("the VM at the contested name after resume: %+v err=%v", vm, err)
	}
}

// BOUNDARY 3 — the process dies MIDWAY THROUGH the cleanup.
//
// Some resources are already freed and some are not, and the completion step was
// never written — which is the only reason a restart still knows there is work.
// Finishing has to be idempotent over the part that already ran.
func TestCutoverRestart_MidCleanupFinishesTheRest(t *testing.T) {
	s, original, replacement, iso := restartFixture(t)
	ctx := adminCtx()

	crashAt(s, "mid-cleanup")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon at the mid-cleanup boundary")
	}

	// The volumes went first, so that half is done and the rest is not.
	if exists(original) {
		t.Fatal("the mid-cleanup boundary fired before the volumes were freed")
	}
	if !exists(iso) {
		t.Fatal("the mid-cleanup boundary fired after everything was freed")
	}
	if pending := pendingCleanups(t, s); len(pending) != 1 {
		t.Fatalf("an unfinished cleanup is not awaiting a restart: %+v", pending)
	}

	s.SetCutoverCrashHook(nil)
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if exists(iso) {
		t.Error("resume did not finish the part that was left")
	}
	if !exists(replacement) {
		t.Error("resume destroyed the replacement's disk")
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("cleanup is still not recorded as done: %+v", left)
	}
}

// A volume the REPLACEMENT also references must survive the cleanup. The manifest
// names the replaced VM's records, but a backing file can be shared, and the
// cleanup is driven from a name that no longer owns anything — so the
// shared-reference check has to be made against the right owner or it frees a
// disk the replacement is still using.
func TestCutoverCleanupKeepsAVolumeTheReplacementShares(t *testing.T) {
	s, original, _, _ := restartFixture(t)
	ctx := adminCtx()

	// The replacement references the replaced VM's volume too — a shared backing
	// file, which is the normal way a -next VM is built.
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "app-next", DiskName: "shared", HostName: s.hostName,
		Path: original, StorageType: "local",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	if !exists(original) {
		t.Fatal("the cleanup freed a volume the replacement still references")
	}
	// And it is still recorded against the replacement, now at the contested name.
	disks, err := corrosion.GetVMDisks(ctx, s.db, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	var found bool
	for _, d := range disks {
		if d.Path == original {
			found = true
		}
	}
	if !found {
		t.Fatalf("the shared volume is no longer recorded at the contested name: %+v", disks)
	}
}

// A committed cutover is not finished when its cleanup is. The replacement's
// libvirt domain and its name-keyed firmware still answer to the temporary name,
// and moving them is the other half of the operation — so a restart has to
// resume that too, or a crash straight after the DB commit becomes a "completed"
// journal with no domain at the name at all. An ordinary retry cannot rescue it:
// the replacement's row is tombstoned, so the handler reports NotFound.
func TestCutoverRestart_AfterCommitFinishesTheRuntimeHandoff(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()

	// A UEFI replacement, so the firmware half is real: the reconciler explicitly
	// cannot heal one of these.
	nvram := lv.NvramPath(s.dataDir, "app-next")
	if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, nvram)
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?`,
		`{"name":"app-next","firmware":"uefi","secure_boot":true,"uuid":"next-uuid"}`,
		s.db.NowTS(), "app-next"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(
		`<domain><name>app-next</name><uuid>next-uuid</uuid><os><nvram>` + nvram + `</nvram></os></domain>`); err != nil {
		t.Fatal(err)
	}

	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon after the commit")
	}
	// A direct retry cannot recover it — the replacement is tombstoned.
	s.SetCutoverCrashHook(nil)
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("a retry claimed to redo a committed cutover")
	}

	// The restart must finish BOTH phases.
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := s.virt.DumpXML("app"); err != nil {
		t.Errorf("resume left no domain at the contested name: %v", err)
	}
	if _, err := s.virt.DumpXML("app-next"); err == nil {
		t.Error("resume left the replacement's domain under its temporary name")
	}
	if !exists(lv.NvramPath(s.dataDir, "app")) {
		t.Error("resume left the replacement's firmware at its temporary path")
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("the operation is not finished: %+v", left)
	}
}

// The runtime handoff moves the REPLACEMENT's firmware onto the contested name.
// A cleanup pass that ran again after that would wipe it, so the phase has to be
// recorded and never repeated.
func TestCutoverRestart_ResumeDoesNotWipeTheReplacementsFirmware(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()

	nvram := lv.NvramPath(s.dataDir, "app-next")
	if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, nvram)
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?`,
		`{"name":"app-next","firmware":"uefi","uuid":"next-uuid"}`, s.db.NowTS(), "app-next"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(
		`<domain><name>app-next</name><uuid>next-uuid</uuid><os><nvram>` + nvram + `</nvram></os></domain>`); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	moved := lv.NvramPath(s.dataDir, "app")
	if !exists(moved) {
		t.Fatal("the cutover did not move the replacement's firmware onto the name")
	}
	// Resuming again must not re-run the name-keyed wipe.
	for i := 0; i < 2; i++ {
		if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
			t.Fatalf("resume %d: %v", i, err)
		}
	}
	if !exists(moved) {
		t.Error("a repeated resume wiped the REPLACEMENT's firmware from the contested name")
	}
}

// The temporary name is free after the transition, and free means reusable. A
// cleanup that exempted it from the shared-reference check would exempt whatever
// VM holds it when a delayed cleanup finally runs — including one created after
// the crash that legitimately references the captured volume.
func TestCutoverCleanupHonorsAReusedTemporaryName(t *testing.T) {
	s, original, _, _ := restartFixture(t)
	ctx := adminCtx()

	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon after the commit")
	}

	// The name is free now; something else takes it and references the volume the
	// pending cleanup is holding.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "app-next", HostName: s.hostName, Spec: `{"name":"app-next"}`, State: "stopped"},
		nil, []corrosion.DiskRecord{{
			VMName: "app-next", DiskName: "root", HostName: s.hostName,
			Path: original, StorageType: "local",
		}}); err != nil {
		t.Fatalf("re-create the temporary name: %v", err)
	}

	s.SetCutoverCrashHook(nil)
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !exists(original) {
		t.Fatal("the cleanup deleted a volume a live VM references, because it exempted the reused name")
	}
}

// BOUNDARY 4 — the process dies after the destruction is recorded but before the
// runtime handoff starts.
//
// This is the boundary the two phases exist to separate. The cleanup must NOT run
// again (the handoff is about to put the replacement's firmware where the wipe
// would look), and the handoff must still happen.
func TestCutoverRestart_BeforeRuntimeFinishesTheHandoff(t *testing.T) {
	s, original, replacement, iso := restartFixture(t)
	ctx := adminCtx()

	crashAt(s, "before-runtime")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon before the runtime handoff")
	}
	// The destruction ran and is recorded; the handoff has not.
	if exists(original) || exists(iso) {
		t.Fatal("the destruction phase did not complete before this boundary")
	}
	pending := pendingCleanups(t, s)
	if len(pending) != 1 || !pending[0].CleanupDone || pending[0].RuntimeDone {
		t.Fatalf("journal state = %+v, want the destruction done and the handoff owed", pending)
	}
	if _, err := s.virt.DumpXML("app"); err == nil {
		t.Fatal("the handoff already ran")
	}

	s.SetCutoverCrashHook(nil)
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := s.virt.DumpXML("app"); err != nil {
		t.Errorf("resume did not finish the handoff: %v", err)
	}
	if !exists(replacement) {
		t.Error("resume destroyed the replacement's disk")
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("the operation is not finished: %+v", left)
	}
}

// A transient redefine failure must not strand the operation. Undefining destroys
// the only copy of the replacement's domain definition, so it is journaled first —
// otherwise recovery has neither name defined and nothing left to redefine from.
func TestCutoverRestart_RedefineFailureLeavesTheDefinitionRecoverable(t *testing.T) {
	s, _, replacement, _ := restartFixture(t)
	ctx := adminCtx()

	// The redefine fails once, after the undefine has already happened.
	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		// A plain VM tolerates a redefine failure (the reconciler rebuilds), so the
		// call may succeed; either way the definition must survive.
		t.Logf("cutover reported: %v", err)
	}

	// Neither name is defined now — the state the journal has to survive.
	if _, err := s.virt.DumpXML("app"); err == nil {
		t.Skip("the redefine did not fail; nothing to recover")
	}
	// The definition is durably recorded, so recovery can finish.
	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := s.virt.DumpXML("app"); err != nil {
		t.Fatalf("recovery could not obtain the definition it needed: %v", err)
	}
	if !exists(replacement) {
		t.Error("recovery destroyed the replacement's disk")
	}
}

// A domain merely existing at the contested name is not the finished state. A
// start that failed leaves it defined and shut off, and recording the phase then
// strands a VM the operator asked to be running.
func TestCutoverRestart_UnstartedVMIsNotComplete(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()
	if err := s.db.Execute(ctx, `UPDATE vms SET state = 'running', updated_at = ? WHERE name = ?`,
		s.db.NowTS(), "app-next"); err != nil {
		t.Fatal(err)
	}

	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailStartDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Logf("cutover reported: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st == "running" {
		t.Skip("the start did not fail; nothing to recover")
	}
	// The operation must still be owed, not completed.
	if left := pendingCleanups(t, s); len(left) != 1 {
		t.Fatalf("an unstarted VM was recorded as a finished cutover: %+v", left)
	}

	s.virt.(*libvirtfake.Fake).FailStartDomain = nil
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st != "running" {
		t.Errorf("resume left the VM %q, want running", st)
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("the operation is still owed after a successful resume: %+v", left)
	}
}

// The temporary name is free and reusable the moment the transition commits, so
// the runtime handoff must act on the recorded IDENTITY, never on the name alone —
// or a delayed recovery undefines whatever VM now holds it and installs that
// identity at the contested name.
func TestCutoverRestart_RecoveryWillNotConsumeAReusedDomain(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()

	crashAt(s, "before-runtime")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon before the runtime handoff")
	}

	// Something else takes the freed name — a different VM, a different identity.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "app-next", HostName: s.hostName, Spec: `{"name":"app-next"}`, State: "stopped"},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(
		`<domain><name>app-next</name><uuid>a-completely-different-vm</uuid></domain>`); err != nil {
		t.Fatal(err)
	}

	s.SetCutoverCrashHook(nil)
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	// The other VM's domain is untouched…
	xml, err := s.virt.DumpXML("app-next")
	if err != nil {
		t.Fatalf("recovery consumed a VM that reused the temporary name: %v", err)
	}
	if !strings.Contains(xml, "a-completely-different-vm") {
		t.Fatalf("the domain at the reused name is not the VM that took it: %s", xml)
	}
	// …and its identity was not installed at the contested name.
	if got, dErr := s.virt.DumpXML("app"); dErr == nil && strings.Contains(got, "a-completely-different-vm") {
		t.Fatal("recovery installed an unrelated VM's identity at the contested name")
	}
}

// An operator stop acknowledged while the cutover is in flight must stand. The
// handoff reads the desired state from the database at the moment it acts, not
// from the snapshot taken before the transition.
func TestCutoverDoesNotUndoAnOperatorStop(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()
	// The replacement is running, so a stale snapshot would start it.
	if err := s.db.Execute(ctx, `UPDATE vms SET state = 'running', updated_at = ? WHERE name = ?`,
		s.db.NowTS(), "app-next"); err != nil {
		t.Fatal(err)
	}

	// The stop lands after the transition commits, before the handoff.
	s.SetCutoverCrashHook(func(stage string) error {
		if stage == "before-runtime" {
			if err := s.db.Execute(ctx,
				`UPDATE vms SET state = 'stopped', state_detail = 'operator-stop', updated_at = ? WHERE name = ?`,
				s.db.NowTS(), "app"); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}

	if st, _ := s.virt.DomainState("app"); st == "running" {
		t.Fatal("the handoff started a VM the operator had stopped, from a stale snapshot")
	}
	vm, err := corrosion.GetVM(ctx, s.db, "app")
	if err != nil || vm == nil {
		t.Fatalf("VM after the cutover: %+v err=%v", vm, err)
	}
	if vm.State != "stopped" {
		t.Errorf("database state = %q, want the operator's stop to stand", vm.State)
	}
}
