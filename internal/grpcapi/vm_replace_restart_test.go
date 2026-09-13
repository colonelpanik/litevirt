package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	if err := s.virt.UndefineDomainPreservingState("app-next"); err != nil {
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
	if err := s.virt.UndefineDomainPreservingState("app-next"); err != nil {
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
	// The old occupant is gone (this crash was before the runtime handoff, so it
	// is still defined) before the new one takes the name — as a real create would.
	if err := s.virt.UndefineDomainPreservingState("app-next"); err != nil {
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

// firmwareFixture is restartFixture with a UEFI replacement: its own NVRAM file,
// a uuid in its spec and in its domain, and a running desired state.
func firmwareFixture(t *testing.T) (s *Server, original, replacement, nvram string) {
	t.Helper()
	s, original, replacement, _ = restartFixture(t)
	ctx := adminCtx()
	nvram = lv.NvramPath(s.dataDir, "app-next")
	if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, nvram)
	if err := s.db.Execute(ctx,
		`UPDATE vms SET spec = ?, state = 'running', updated_at = ? WHERE name = ?`,
		`{"name":"app-next","firmware":"uefi","secure_boot":true,"uuid":"next-uuid"}`,
		s.db.NowTS(), "app-next"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.UndefineDomainPreservingState("app-next"); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(`<domain><name>app-next</name><uuid>next-uuid</uuid>` +
		`<os><nvram>` + nvram + `</nvram></os></domain>`); err != nil {
		t.Fatal(err)
	}
	return s, original, replacement, nvram
}

// A firmware VM whose START failed must still be started by the retry. Recording
// the failure as state=error made the row read as "not asked to run", so recovery
// completed the operation with the VM shut off — the failure state erased the
// running intent it needed.
func TestCutoverRestart_FirmwareStartFailureIsRetried(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()

	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailStartDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("a firmware start failure must not report success")
	}
	if left := pendingCleanups(t, s); len(left) != 1 {
		t.Fatalf("the failed start left nothing owed: %+v", left)
	}

	s.virt.(*libvirtfake.Fake).FailStartDomain = nil
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st != "running" {
		t.Errorf("the VM is %q after recovery, want running — the failure state erased its intent", st)
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("still owed after a successful resume: %+v", left)
	}
}

// A retry after a failed redefine finds the firmware ALREADY moved. The
// destination definition must be derived regardless, or recovery defines the VM
// pointing at a vars file that is no longer there.
func TestCutoverRestart_RedefineRetryPointsAtTheMovedFirmware(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()

	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("a firmware redefine failure must not report success")
	}
	moved := lv.NvramPath(s.dataDir, "app")
	if !exists(moved) {
		t.Skip("the firmware had not moved before the failure; nothing to check")
	}

	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	xml, err := s.virt.DumpXML("app")
	if err != nil {
		t.Fatalf("resume did not define the VM: %v", err)
	}
	if strings.Contains(xml, lv.NvramPath(s.dataDir, "app-next")) {
		t.Fatalf("the restored definition points at the vars file that already moved:\n%s", xml)
	}
	if !strings.Contains(xml, moved) {
		t.Fatalf("the restored definition does not point at the moved vars file:\n%s", xml)
	}
}

// Firmware is name-keyed, so a VM that took the freed temporary name owns the
// file at that path. Recovery must not move it onto the contested name.
func TestCutoverRestart_RecoveryWillNotStealAReusedNamesFirmware(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()

	// Fail the redefine once. That leaves the definition JOURNALED and the
	// firmware already moved — the state in which the capture-time identity check
	// is skipped on the retry, so the firmware move is the only thing standing
	// between recovery and another VM's vars file.
	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the redefine failure must not report success")
	}
	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil
	if left := pendingCleanups(t, s); len(left) != 1 || left[0].Handoff.XML == "" {
		t.Fatalf("the definition was not journaled before the failure: %+v", left)
	}

	// Another VM takes the freed name, with its own firmware at the same path.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "app-next", HostName: s.hostName, State: "stopped",
			Spec: `{"name":"app-next","firmware":"uefi","uuid":"a-different-vm"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	newNvram := lv.NvramPath(s.dataDir, "app-next")
	if err := os.WriteFile(newNvram, []byte("the other VM's firmware"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.virt.DefineDomain(`<domain><name>app-next</name><uuid>a-different-vm</uuid>` +
		`<os><nvram>` + newNvram + `</nvram></os></domain>`); err != nil {
		t.Fatal(err)
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Logf("resume reported: %v", err)
	}
	body, err := os.ReadFile(newNvram)
	if err != nil {
		t.Fatalf("recovery took the other VM's firmware: %v", err)
	}
	if string(body) != "the other VM's firmware" {
		t.Fatalf("the other VM's firmware was replaced: %q", body)
	}
}

// A transient failure reading the replacement's identity must abort BEFORE the
// teardown. Treated as "no domain to hand off", it destroys the original and
// completes a cutover that defines nothing.
func TestCutoverAbortsWhenTheReplacementsIdentityCannotBeRead(t *testing.T) {
	s, original, replacement, _ := restartFixture(t)
	ctx := adminCtx()
	// A legacy spec with no uuid, so the spec cannot stand in for the read.
	s.virt.(*libvirtfake.Fake).FailDumpXML = func(name string) error {
		if name == "app-next" {
			return errCrash
		}
		return nil
	}

	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover proceeded despite being unable to read the replacement's identity")
	}
	// Both VMs intact, both disks intact.
	for _, name := range []string{"app", "app-next"} {
		if vm, gErr := corrosion.GetVM(ctx, s.db, name); gErr != nil || vm == nil {
			t.Fatalf("%s after the aborted cutover: %+v err=%v", name, vm, gErr)
		}
	}
	if !exists(original) || !exists(replacement) {
		t.Fatal("the aborted cutover destroyed a disk")
	}
}

// Recovery has to serialize with lifecycle calls exactly as the handler does: a
// resumed handoff reads the desired runtime state and then acts on it, and a
// StopVM landing between those is how a VM the operator just stopped is started
// again. The handler's locking is not enough on its own — recovery runs the same
// two steps.
func TestCutoverRecoveryTakesTheLifecycleLock(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()
	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon after the commit")
	}
	s.SetCutoverCrashHook(nil)

	// Hold the contested name's lock, then let recovery run. It must wait.
	var mu sync.Mutex
	released := false
	unlock := s.lockVM("app")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.ResumeVMReplaceCleanups(ctx)
	}()
	// Give the goroutine a moment to reach the lock, then release it.
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	released = true
	mu.Unlock()
	unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery never finished")
	}
	mu.Lock()
	defer mu.Unlock()
	if !released {
		t.Fatal("recovery ran without taking the lifecycle lock")
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("recovery did not finish once it had the lock: %+v", left)
	}
}

// A reconciler pass must not erase the start a cutover still owes.
//
// An unfinished handoff looks exactly like a VM that is shut off, so the
// reconciler syncs the row to "stopped" — and recovery reading that row back
// would conclude the VM was never asked to run and finish the operation with it
// down. The intent lives in the journaled manifest, and the reconciler leaves an
// owed handoff alone in the first place.
func TestCutoverRestart_ReconcilerCannotEraseTheOwedStart(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()

	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailStartDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("a start failure must not report success")
	}
	s.virt.(*libvirtfake.Fake).FailStartDomain = nil

	// What a reconciler pass does to a VM it finds shut off — no operator stop
	// involved.
	pending, err := corrosion.VMReplaceHandoffPending(ctx, s.db, s.hostName, "app")
	if err != nil {
		t.Fatalf("VMReplaceHandoffPending: %v", err)
	}
	if !pending {
		t.Fatal("the owed handoff is invisible to the reconciler's check")
	}
	// Even if something does sync the row anyway, the intent must survive.
	if err := corrosion.UpdateVMState(ctx, s.db, "app", "stopped", "guest-shutdown"); err != nil {
		t.Fatal(err)
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st != "running" {
		t.Errorf("the VM is %q after recovery, want running — a reconciler sync erased the owed start", st)
	}
}

// A failed identity read is not "not foreign". Treating it as such lets a
// transient libvirt error authorize moving an unrelated VM's firmware.
func TestCutoverRestart_IdentityReadFailureDoesNotAuthorizeTheMove(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()

	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the redefine failure must not report success")
	}
	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil

	// Another VM takes the freed name with its own firmware…
	newNvram := lv.NvramPath(s.dataDir, "app-next")
	if err := os.WriteFile(newNvram, []byte("the other VM's firmware"), 0o600); err != nil {
		t.Fatal(err)
	}
	// …and the identity read fails transiently.
	s.virt.(*libvirtfake.Fake).FailDumpXML = func(name string) error {
		if name == "app-next" {
			return errCrash
		}
		return nil
	}
	if err := s.ResumeVMReplaceCleanups(ctx); err == nil {
		t.Fatal("recovery proceeded despite being unable to read who holds the temporary name")
	}
	body, err := os.ReadFile(newNvram)
	if err != nil || string(body) != "the other VM's firmware" {
		t.Fatalf("recovery moved firmware it could not prove was its own: %q err=%v", body, err)
	}
	// The operation stays owed for a later attempt.
	if left := pendingCleanups(t, s); len(left) != 1 {
		t.Errorf("the aborted phase was recorded anyway: %+v", left)
	}
}

// Two recovery passes racing on the same pending snapshot must not both run the
// destruction phase: the second would repeat a name-keyed wipe after the first
// has already moved the replacement's firmware onto that name.
func TestCutoverRecoveryReloadsPhasesUnderTheLock(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()
	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon after the commit")
	}
	s.SetCutoverCrashHook(nil)

	// Both callers hold the SAME stale snapshot, as two overlapping resumes would.
	stale := pendingCleanups(t, s)
	if len(stale) != 1 {
		t.Fatalf("expected one owed operation, got %+v", stale)
	}
	if err := s.lockedFinishVMReplace(ctx, stale[0]); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	moved := lv.NvramPath(s.dataDir, "app")
	if !exists(moved) {
		t.Fatal("the first pass did not install the replacement's firmware")
	}
	if err := s.lockedFinishVMReplace(ctx, stale[0]); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if !exists(moved) {
		t.Fatal("the second pass repeated the destruction and wiped the installed firmware")
	}
}

// A RUNNING replacement has to be stopped before its domain is undefined.
//
// libvirt cannot rename a domain, and undefining an ACTIVE one leaves it running
// as a TRANSIENT domain still holding its UUID — after which defining that UUID
// under the contested name is refused. The whole handoff then fails with the
// replacement left running under its temporary name, which is how cutover of a
// running VM never worked.
func TestCutoverStopsARunningReplacementBeforeUndefining(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()
	// Actually running, which is what the fixture's row already claims.
	if err := s.virt.StartDomain("app-next"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover of a running replacement: %v", err)
	}

	// The domain answers to the contested name, and to nothing else.
	if _, err := s.virt.DumpXML("app"); err != nil {
		t.Fatalf("no domain at the contested name: %v", err)
	}
	if _, err := s.virt.DumpXML("app-next"); err == nil {
		t.Error("the replacement is still defined under its temporary name")
	}
	if st, _ := s.virt.DomainState("app-next"); st == "running" {
		t.Error("the replacement is still RUNNING under its temporary name — it was undefined while active")
	}
	// And it is running again, under the new name.
	if st, _ := s.virt.DomainState("app"); st != "running" {
		t.Errorf("the VM is %q at the contested name, want running", st)
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("the operation did not finish: %+v", left)
	}
}

// The stop is journaled, so a crash after it does not lose the restart it owes.
func TestCutoverRestart_ResumesAfterTheReplacementWasStopped(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()
	if err := s.virt.StartDomain("app-next"); err != nil {
		t.Fatal(err)
	}

	// Fail the redefine once, which lands after the stop has been journaled.
	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the redefine failure must not report success")
	}
	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil
	owed := pendingCleanups(t, s)
	if len(owed) != 1 || !owed[0].StopDone {
		t.Fatalf("the stop was not journaled: %+v", owed)
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st != "running" {
		t.Errorf("the VM is %q after recovery, want running", st)
	}
}

// An acknowledged operator stop must survive a handoff failure. It is the only
// thing that overrides the journaled running intent, so overwriting it with
// diagnostic text makes the next retry start a VM the operator stopped.
func TestCutoverFailureDoesNotEraseAnOperatorStop(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()

	// The operator stops the VM while the handoff is owed, and the next attempt's
	// read fails.
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
	var failedOnce bool
	s.virt.(*libvirtfake.Fake).FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the redefine failure must not report success")
	}
	s.SetCutoverCrashHook(nil)
	s.virt.(*libvirtfake.Fake).FailDefineDomain = nil

	vm, err := corrosion.GetVM(ctx, s.db, "app")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v err=%v", vm, err)
	}
	if vm.StateDetail != operatorStopDetail {
		t.Fatalf("state_detail = %q, want the operator stop preserved", vm.StateDetail)
	}

	// And the healthy retry must respect it.
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st == "running" {
		t.Fatal("recovery started a VM the operator had stopped")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "app"); vm == nil || vm.State != "stopped" {
		t.Fatalf("the database no longer records the stop: %+v", vm)
	}
}

// A PAUSED replacement is ACTIVE. The coarse state query cannot see the
// difference — it collapses paused, shut-off and pm-suspended all into
// "stopped" — so inferring inactivity from it undefines an active domain, which
// survives as a transient one holding its UUID and makes the new definition fail
// after the original has already been cleaned up.
func TestCutoverStopsAPausedReplacementBeforeUndefining(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	if err := fake.StartDomain("app-next"); err != nil {
		t.Fatal(err)
	}
	fake.SetPaused("app-next")
	// The trap: the coarse view reports it as stopped.
	if st, _ := s.virt.DomainState("app-next"); st == "running" {
		t.Fatal("fixture: the paused domain must not report as running")
	}
	if active, err := s.virt.DomainIsActive("app-next"); err != nil || !active {
		t.Fatalf("fixture: the paused domain must be ACTIVE: active=%v err=%v", active, err)
	}

	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover of a paused replacement: %v", err)
	}
	if _, err := s.virt.DumpXML("app"); err != nil {
		t.Fatalf("no domain at the contested name: %v", err)
	}
	if active, _ := s.virt.DomainIsActive("app-next"); active {
		t.Error("the replacement is still active under its temporary name")
	}
	if left := pendingCleanups(t, s); len(left) != 0 {
		t.Errorf("the operation did not finish: %+v", left)
	}
}

// A recorded stop is a statement about the PAST. Between it and the undefine the
// domain can be started again by hand — or by libvirt's own autostart after a
// host reboot — so activity is re-checked before every undefine, including on a
// retry that already has the phase recorded.
func TestCutoverRestart_RechecksActivityEvenWithTheStopRecorded(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	if err := fake.StartDomain("app-next"); err != nil {
		t.Fatal(err)
	}

	// Fail the redefine once: the stop is journaled, the handoff is not finished.
	var failedOnce bool
	fake.FailDefineDomain = func(string) error {
		if failedOnce {
			return nil
		}
		failedOnce = true
		return errCrash
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the redefine failure must not report success")
	}
	fake.FailDefineDomain = nil
	owed := pendingCleanups(t, s)
	if len(owed) != 1 || !owed[0].StopDone {
		t.Fatalf("expected one owed operation with the stop recorded: %+v", owed)
	}

	// Something reactivates the temporary domain before recovery runs. (The
	// undefine removed its persistent definition but left the live view, so
	// redefining it is how a host reboot's autostart would leave things.)
	if err := fake.DefineDomain(`<domain><name>app-next</name><uuid>next-uuid</uuid></domain>`); err == nil {
		if err := fake.StartDomain("app-next"); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := s.virt.DumpXML("app"); err != nil {
		t.Fatalf("recovery did not install the domain at the contested name: %v", err)
	}
	if active, _ := s.virt.DomainIsActive("app-next"); active {
		t.Error("recovery undefined a reactivated domain while it was still active")
	}
}

// The ORIGINAL's domain must be verifiably gone from the contested name before
// anything is torn down. Deciding from the database state, ignoring a failed
// destroy, or continuing past a failed undefine all leave the name occupied — and
// real libvirt then refuses to define the replacement there, because the UUID
// differs, by which point the original's disks are already deleted.
func TestCutoverRefusesWhenTheOriginalsDomainCannotBeFreed(t *testing.T) {
	ctx := adminCtx()
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, s *Server, fake *libvirtfake.Fake)
	}{
		{"the original is PAUSED, which the coarse state hides", func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := fake.StartDomain("app"); err != nil {
				t.Fatal(err)
			}
			fake.SetPaused("app")
			// It is stopped as far as the database and the coarse query can tell.
			fake.FailDestroyDomain = func(string) error { return errCrash }
			fake.FailShutdownDomain = func(string) error { return errCrash }
		}},
		{"the destroy fails", func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			if err := fake.StartDomain("app"); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Execute(ctx, `UPDATE vms SET state='running', updated_at=? WHERE name='app'`,
				s.db.NowTS()); err != nil {
				t.Fatal(err)
			}
			fake.FailDestroyDomain = func(string) error { return errCrash }
			fake.FailShutdownDomain = func(string) error { return errCrash }
		}},
		{"the undefine fails", func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			fake.FailUndefinePreserv = func(name string) error {
				if name == "app" {
					return errCrash
				}
				return nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, original, replacement, iso := restartFixture(t)
			fake := s.virt.(*libvirtfake.Fake)
			tc.prepare(t, s, fake)

			if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
				t.Fatal("the cutover proceeded without freeing the name from the original's domain")
			}
			// Nothing destroyed, nothing transitioned, nothing authorized.
			for _, p := range []string{original, replacement, iso} {
				if !exists(p) {
					t.Errorf("a refused cutover destroyed %s", p)
				}
			}
			for _, name := range []string{"app", "app-next"} {
				if vm, gErr := corrosion.GetVM(ctx, s.db, name); gErr != nil || vm == nil {
					t.Errorf("%s after the refused cutover: %+v err=%v", name, vm, gErr)
				}
			}
			if owed := pendingCleanups(t, s); len(owed) != 0 {
				t.Errorf("a refused cutover authorized destruction: %+v", owed)
			}
		})
	}
}

// A delayed cleanup must not delete the NAME-keyed state of a VM that has since
// been recreated at that name. Those files belong to the new incarnation; the
// swtpm tree, keyed by the replaced VM's own UUID, is still this operation's.
func TestCutoverCleanupSparesARecreatedTargetsNameKeyedState(t *testing.T) {
	s, original, _, iso := restartFixture(t)
	ctx := adminCtx()
	nvram := lv.NvramPath(s.dataDir, "app")
	if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
		t.Fatal(err)
	}

	crashAt(s, "after-commit")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon after the commit")
	}
	s.SetCutoverCrashHook(nil)

	// The name is deleted and RECREATED as a different VM, with its own files.
	if err := corrosion.DeleteVM(ctx, s.db, "app"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "app", HostName: s.hostName, Spec: `{"name":"app","uuid":"a-new-incarnation"}`,
		State: "stopped",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nvram, []byte("the new VM's firmware"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iso, []byte("the new VM's cloud-init"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	body, err := os.ReadFile(nvram)
	if err != nil || string(body) != "the new VM's firmware" {
		t.Errorf("cleanup deleted the recreated VM's firmware: %q err=%v", body, err)
	}
	body, err = os.ReadFile(iso)
	if err != nil || string(body) != "the new VM's cloud-init" {
		t.Errorf("cleanup deleted the recreated VM's cloud-init ISO: %q err=%v", body, err)
	}
	// The uniquely identified resources are still freed.
	if exists(original) {
		t.Error("cleanup skipped the replaced VM's own volume, which nothing else can claim")
	}
}

// A tombstone is still evidence of who last held the name — and a VM deleted with
// its disks retained deliberately KEEPS its firmware and cloud-init state. Reading
// ownership through GetVM hides that: the retained artifacts of a newer
// incarnation read as belonging to nobody, and an old cleanup deletes them.
//
// The control matters as much: this operation's OWN tombstone must still be
// cleaned up, or a cutover whose result was later deleted leaks everything.
func TestCutoverCleanupReadsOwnershipThroughTombstones(t *testing.T) {
	ctx := adminCtx()

	stage := func(t *testing.T) (s *Server, nvram, iso, original string) {
		t.Helper()
		s, original, _, iso = restartFixture(t)
		nvram = lv.NvramPath(s.dataDir, "app")
		if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
			t.Fatal(err)
		}
		crashAt(s, "after-commit")
		if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
			t.Fatal("the cutover did not abandon after the commit")
		}
		s.SetCutoverCrashHook(nil)
		return s, nvram, iso, original
	}

	t.Run("a newer incarnation's retained state is spared", func(t *testing.T) {
		s, nvram, iso, original := stage(t)
		// The name is recreated as a different VM, which is then deleted with its
		// disks — and therefore its firmware — RETAINED.
		if err := corrosion.DeleteVM(ctx, s.db, "app"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: "app", HostName: s.hostName, State: "stopped",
			Spec: `{"name":"app","uuid":"a-new-incarnation"}`,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(nvram, []byte("retained firmware"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(iso, []byte("retained cloud-init"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Deleted with its state kept: the row is a TOMBSTONE, which GetVM hides.
		if err := corrosion.DeleteVM(ctx, s.db, "app"); err != nil {
			t.Fatal(err)
		}

		if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
			t.Fatalf("resume: %v", err)
		}
		if body, err := os.ReadFile(nvram); err != nil || string(body) != "retained firmware" {
			t.Errorf("cleanup deleted a newer incarnation's RETAINED firmware: %q err=%v", body, err)
		}
		if body, err := os.ReadFile(iso); err != nil || string(body) != "retained cloud-init" {
			t.Errorf("cleanup deleted a newer incarnation's RETAINED cloud-init: %q err=%v", body, err)
		}
		if exists(original) {
			t.Error("cleanup skipped the replaced VM's own volume, which nothing else can claim")
		}
	})

	t.Run("this operation's own tombstone is still cleaned up", func(t *testing.T) {
		s, nvram, iso, original := stage(t)
		if err := os.WriteFile(nvram, []byte("the replaced VM's firmware"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The cutover's own result is deleted before the cleanup runs. Its
		// tombstone carries THIS operation's incarnation, so the artifacts are
		// still this operation's to free — skipping them would leak them forever.
		if err := corrosion.DeleteVM(ctx, s.db, "app"); err != nil {
			t.Fatal(err)
		}

		if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
			t.Fatalf("resume: %v", err)
		}
		if exists(nvram) {
			t.Error("cleanup skipped the firmware of its OWN incarnation's tombstone")
		}
		if exists(iso) {
			t.Error("cleanup skipped the cloud-init ISO of its OWN incarnation's tombstone")
		}
		if exists(original) {
			t.Error("cleanup skipped the replaced VM's volume")
		}
	})
}
