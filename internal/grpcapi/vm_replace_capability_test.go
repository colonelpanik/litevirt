package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// enableVMReplace makes `lv cutover` runnable on s: the operator opted in AND
// vm_replace_v1 has latched cluster-wide. Both halves are required, so a test
// that drives a real cutover has to say so explicitly.
func enableVMReplace(s *Server) {
	s.SetVMReplaceEnforce(true)
	// operation_protocol_v1 too: the cleanup manifest lives in the operation
	// journal, and cutover treats a missing journal as not-active.
	s.SetOperationProtocol(true)
	s.gate = fakeServerGate{enforcedTok: map[string]bool{
		capabilities.VMReplaceV1:         true,
		capabilities.OperationProtocolV1: true,
	}}
}

// A cutover on a cluster that has not latched vm_replace_v1 must refuse, and must
// refuse having changed NOTHING — not the domain, not either VM's rows. The
// guarded replace batch carries a protocol an un-upgraded receiver cannot
// evaluate, so discovering this after the teardown would destroy the replaced VM
// for a transition that can never be emitted.
func TestCutoverRefusedWithoutVMReplaceCapability(t *testing.T) {
	ctx := adminCtx()

	for _, tc := range []struct {
		name    string
		prepare func(s *Server)
	}{
		{"neither flag nor latch", func(*Server) {}},
		{"flag on, not latched", func(s *Server) {
			s.SetVMReplaceEnforce(true)
			s.gate = fakeServerGate{enforcedTok: map[string]bool{}}
		}},
		{"latched, flag off", func(s *Server) {
			s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.VMReplaceV1: true}}
		}},
		// The operation journal is a HARD dependency, not an additional safety
		// check: it is what carries the cleanup manifest across the gap between the
		// transition and the destruction it makes necessary. Without it a crash in
		// between leaks the replaced VM's volumes with nothing left in the database
		// naming them, so a missing journal means cutover is not available at all.
		{"vm_replace latched, no operation journal", func(s *Server) {
			s.SetVMReplaceEnforce(true)
			s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.VMReplaceV1: true}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			tc.prepare(s)
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "app", HostName: s.hostName, Spec: `{"cpu":2}`, State: "running"},
				nil, nil); err != nil {
				t.Fatalf("InsertVM replaced: %v", err)
			}
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "app-next", HostName: s.hostName, Spec: `{"cpu":4}`, State: "running"},
				nil, nil); err != nil {
				t.Fatalf("InsertVM replacement: %v", err)
			}

			_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})
			if c := status.Code(err); c != codes.FailedPrecondition {
				t.Fatalf("code = %v (%v), want FailedPrecondition", c, err)
			}

			// Both VMs untouched: still live, still under their own names, still
			// carrying their own specs.
			replaced, gErr := corrosion.GetVM(ctx, s.db, "app")
			if gErr != nil || replaced == nil {
				t.Fatalf(`replaced VM after a refused cutover: %+v err=%v`, replaced, gErr)
			}
			if replaced.Spec != `{"cpu":2}` {
				t.Errorf("replaced VM spec = %q, want its own", replaced.Spec)
			}
			replacement, gErr := corrosion.GetVM(ctx, s.db, "app-next")
			if gErr != nil || replacement == nil {
				t.Fatalf("replacement after a refused cutover: %+v err=%v", replacement, gErr)
			}
		})
	}
}

// The refusal must name the flag an operator has to set — a bare
// FailedPrecondition on the most destructive VM operation is not actionable.
func TestCutoverRefusalNamesTheEnforcementFlag(t *testing.T) {
	s := testServer(t)
	_, err := s.CutoverVM(adminCtx(), &pb.CutoverVMRequest{VmName: "app"})
	if err == nil {
		t.Fatal("cutover did not refuse")
	}
	for _, want := range []string{
		"enforcement.vm_replace", "vm_replace_v1",
		"enforcement.operation_protocol", "operation_protocol_v1",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
}

// The advertisement half: a node withholds vm_replace_v1 while its flag is off,
// so the cluster cannot latch — and therefore no node starts emitting a guard
// protocol its peers may not understand — until every operator has opted in.
func TestVMReplaceAdvertisedOnlyWithTheFlag(t *testing.T) {
	s := &Server{hostName: "h"}
	if capabilities.Has(s.advertisedCapabilities(), capabilities.VMReplaceV1) {
		t.Error("vm_replace_v1 advertised with enforcement.vm_replace off")
	}
	s.SetVMReplaceEnforce(true)
	if !capabilities.Has(s.advertisedCapabilities(), capabilities.VMReplaceV1) {
		t.Error("vm_replace_v1 not advertised with enforcement.vm_replace on")
	}
}

// cutoverFixture is a host holding a VM and its ready replacement, each with a
// real disk file and a defined domain.
func cutoverFixture(t *testing.T) (s *Server, fake *libvirtfake.Fake, originalDisk, replacementDisk string) {
	t.Helper()
	s = testServerWithLocks(t)
	t.Cleanup(func() { s.db.Close() })
	fake = libvirtfake.New()
	s.virt = fake
	enableVMReplace(s)
	ctx := adminCtx()
	paths := []string{
		filepath.Join(s.dataDir, "disks", "app-root.qcow2"),
		filepath.Join(s.dataDir, "disks", "app-next-root.qcow2"),
	}
	if err := os.MkdirAll(filepath.Dir(paths[0]), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"app", "app-next"} {
		mustWrite(t, paths[i])
		if err := corrosion.InsertVM(ctx, s.db,
			corrosion.VMRecord{Name: name, HostName: s.hostName, Spec: `{"name":"` + name + `"}`, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{
				VMName: name, DiskName: "root", HostName: s.hostName,
				Path: paths[i], StorageType: "local",
			}}); err != nil {
			t.Fatal(err)
		}
		if err := fake.DefineDomain(`<domain><name>` + name + `</name><uuid>uuid-` + name + `</uuid></domain>`); err != nil {
			t.Fatal(err)
		}
	}
	return s, fake, paths[0], paths[1]
}

// The replaced VM's UEFI vars must survive a database failure. UndefineDomain
// ALWAYS passes DomainUndefineNvram — libvirt requires either that or KeepNvram to
// undefine a UEFI domain — so undefining destructively before the transition
// commits leaves a Secure-Boot original that cannot start if anything after it
// fails. The teardown uses the state-preserving undefine and frees the firmware
// explicitly, after the transition.
func TestCutoverKeepsTheOriginalsNVRAMWhenTheTransitionFails(t *testing.T) {
	s, fake, _, _ := cutoverFixture(t)
	ctx := adminCtx()
	nvram := lv.NvramPath(s.dataDir, "app")
	if err := os.MkdirAll(filepath.Dir(nvram), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, nvram)
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?`,
		`{"name":"app","firmware":"uefi","secure_boot":true,"uuid":"old-uuid"}`,
		s.db.NowTS(), "app"); err != nil {
		t.Fatal(err)
	}
	if err := fake.UndefineDomainPreservingState("app"); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(
		`<domain><name>app</name><uuid>old-uuid</uuid><os><nvram>` + nvram + `</nvram></os></domain>`); err != nil {
		t.Fatal(err)
	}
	// Model the production flag: the destructive undefine takes the vars file with it.
	fake.FailUndefineDomain = func(name string, _ bool) error {
		if name == "app" {
			if err := os.Remove(nvram); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	if err := s.db.Execute(ctx, `CREATE TRIGGER block_old_delete BEFORE UPDATE OF deleted_at ON vms
 WHEN OLD.name = 'app' AND NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("expected the injected delete failure")
	}
	if _, err := os.Stat(nvram); err != nil {
		t.Fatalf("the original's NVRAM was destroyed before the transition committed: %v", err)
	}
}

// A cutover that fails AFTER tombstoning the original leaves its disks on disk and
// its rows tombstoned. GetVM hides a tombstone, so a retry that trusted it would
// read no original at all, skip the whole cleanup block, and report success while
// leaking the volumes. The tombstone is the record that they were never freed.
func TestCutoverRetryStillFreesTheOriginalsDisks(t *testing.T) {
	s, _, original, replacement := cutoverFixture(t)
	ctx := adminCtx()
	// Fail the transition itself, after DeleteVM has already committed.
	if err := s.db.Execute(ctx, `CREATE TRIGGER block_replace BEFORE INSERT ON vms
 WHEN NEW.name = 'app' BEGIN SELECT RAISE(ABORT,'injected replace failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("expected the injected replace failure")
	}
	if !exists(original) || !exists(replacement) {
		t.Fatal("a failed transition must leave both disks intact")
	}
	if tomb, err := corrosion.GetDeletedVM(ctx, s.db, "app"); err != nil || tomb == nil {
		t.Fatalf("the original should be tombstoned after the failed attempt: %+v err=%v", tomb, err)
	}

	if err := s.db.Execute(ctx, `DROP TRIGGER block_replace`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if exists(original) {
		t.Error("the retry left the original's disk behind — it read no original because GetVM hid the tombstone")
	}
	if !exists(replacement) {
		t.Error("the retry deleted the replacement's disk")
	}
}
