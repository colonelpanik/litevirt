package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// phaseFailStream is a migrate progress stream whose client goes away at one
// phase: the Send of failOn fails, as it does once the CLI is Ctrl-C'd.
type phaseFailStream struct {
	mockMigrateStream
	failOn pb.MigratePhase
}

func (m *phaseFailStream) Send(p *pb.MigrateProgress) error {
	if p.GetPhase() == m.failOn {
		return status.Error(codes.Canceled, "client went away")
	}
	return m.mockMigrateStream.Send(p)
}

// cleanupCountingDest is the always-admitting destination that also counts the
// target-side cleanup a failed migration sends it.
type cleanupCountingDest struct {
	*fakeDestPeer
	mu       sync.Mutex
	cleanups []string
}

func (d *cleanupCountingDest) CleanupMigrationArtifacts(_ context.Context, r *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanups = append(d.cleanups, r.GetVmName())
	return &emptypb.Empty{}, nil
}

func (d *cleanupCountingDest) cleaned() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.cleanups...)
}

func (d *cleanupCountingDest) reserved() int {
	d.fakeDestPeer.mu.Lock()
	defer d.fakeDestPeer.mu.Unlock()
	return len(d.fakeDestPeer.reserveCalls)
}

func abortTestServer(t *testing.T, name string) (*Server, *cleanupCountingDest, *libvirtfake.Fake) {
	t.Helper()
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	dest := &cleanupCountingDest{fakeDestPeer: &fakeDestPeer{leaseID: "dest-lease-1"}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return dest, func() {}, nil
	}
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, name, "test-host", "running")
	insertTestHost(t, ctx, s.db, "target-host", "active")
	fake.SetState(name, "running")
	return s, dest, fake
}

// TestMigrateVM_AnAbortBeforeTheCopyLeavesNothingBehind: a migration that
// ends after it has started preparing the target but before libvirt is asked
// to move the guest must leave the VM as it found it — `running` on the source
// — and remove what it pre-created on the target.
//
// The client stream going away (a Ctrl-C) used to strand it. A failed COPYING
// send returned right after the row was written `migrating`, with nothing to
// restore it: the reconciler and owner-assert skip `migrating`, snapshot
// refuses it, and a retry is refused because the VM is not running, so the row
// stayed `migrating` while the guest ran on, untouched, on the source. A
// failed PREPARING send, earlier, left the state alone but leaked the target's
// stubs and cloud-init ISO all the same.
func TestMigrateVM_AnAbortBeforeTheCopyLeavesNothingBehind(t *testing.T) {
	for _, phase := range []pb.MigratePhase{pb.MigratePhase_MIGRATE_PREPARING, pb.MigratePhase_MIGRATE_COPYING} {
		t.Run(phase.String(), func(t *testing.T) {
			s, dest, fake := abortTestServer(t, "abort-vm")
			ctx := adminCtx()
			migrateCalls := 0
			fake.FailMigrateToTarget = func(string, string) error {
				migrateCalls++
				return errors.New("libvirt must not be reached")
			}

			err := s.MigrateVM(&pb.MigrateVMRequest{
				VmName: "abort-vm", TargetHost: "target-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			}, &phaseFailStream{mockMigrateStream: mockMigrateStream{ctx: ctx}, failOn: phase})
			if err == nil {
				t.Fatal("the migration succeeded; the scenario needs the client to go away")
			}

			vm, gerr := corrosion.GetVM(ctx, s.db, "abort-vm")
			if gerr != nil || vm == nil {
				t.Fatalf("GetVM: %+v %v", vm, gerr)
			}
			if vm.State != "running" || vm.HostName != "test-host" {
				t.Fatalf("after the client went away at %s the VM is %q on %q, want running on test-host — "+
					"nothing heals `migrating`, and the guest never left", phase, vm.State, vm.HostName)
			}
			if st, _ := fake.DomainState("abort-vm"); st != "running" {
				t.Fatalf("the guest is %q on the source, want running", st)
			}
			if migrateCalls != 0 {
				t.Fatalf("libvirt was asked to migrate %d time(s), want 0", migrateCalls)
			}
			if got := dest.cleaned(); len(got) == 0 || got[0] != "abort-vm" {
				t.Fatalf("the target was not cleaned up after the abort (cleanups %v); its stubs and "+
					"cloud-init ISO are leaked", got)
			}
		})
	}
}

// TestMigrateVM_NoLibvirtRefusesBeforeTouchingAnything: a host with no libvirt
// connection cannot migrate, and it must say so before it has reserved
// capacity on the target, prepared it, or written the row `migrating`. The
// check used to sit after the state write, where it returned with the row
// stranded in `migrating`.
func TestMigrateVM_NoLibvirtRefusesBeforeTouchingAnything(t *testing.T) {
	s, dest, _ := abortTestServer(t, "novirt-vm")
	s.virt = nil
	ctx := adminCtx()

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName: "novirt-vm", TargetHost: "target-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	}, &mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "libvirt not connected") {
		t.Fatalf("got %v, want Internal \"libvirt not connected\"", err)
	}
	vm, gerr := corrosion.GetVM(ctx, s.db, "novirt-vm")
	if gerr != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, gerr)
	}
	if vm.State != "running" {
		t.Fatalf("state = %q, want running — a refusal must not strand the row", vm.State)
	}
	if n := dest.reserved(); n != 0 {
		t.Fatalf("reserved capacity on the target %d time(s) before refusing; want 0", n)
	}
}
