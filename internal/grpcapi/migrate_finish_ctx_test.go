package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

// cancelOnPhaseStream is a migrate progress stream whose client goes away as
// phase is sent: the request context is cancelled, the send itself succeeds.
type cancelOnPhaseStream struct {
	mockMigrateStream
	phase  pb.MigratePhase
	cancel context.CancelFunc
	fired  bool
}

func (m *cancelOnPhaseStream) Send(p *pb.MigrateProgress) error {
	if p.GetPhase() == m.phase && !m.fired {
		m.fired = true
		m.cancel()
	}
	return m.mockMigrateStream.Send(p)
}

// TestMigrateVM_ClientGoneAfterCutoverStillFinishesOnTarget: libvirt has cut
// the guest over and the client goes away. The ownership commit already runs
// detached, so the cluster agrees the VM moved — and the rest of the finish
// (DNS, FDB, VFs, post_migrate hook, notifying the target) must happen too,
// because nothing retries it.
//
// finishMigrationOnTarget used to run on the request context on the watched
// path, so its database reads and writes failed once the client was gone: the
// interface lookup came back empty and the VM's DNS record was never written,
// nor its FDB entries moved to the target's VTEP.
//
// Deterministic: the request is cancelled as MIGRATE_COMPLETING is sent, after
// libvirt returned success and before the ownership commit.
//
// Mutation: drop the `ctx = context.WithoutCancel(ctx)` at the top of
// finishMigrationOnTarget — red.
func TestMigrateVM_ClientGoneAfterCutoverStillFinishesOnTarget(t *testing.T) {
	const name = "finish-cancel-vm"
	s, _, _ := abortTestServer(t, name)
	s.dnsDomain = "litevirt.local"
	ctx := adminCtx()
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: name, NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.42",
	}); err != nil {
		t.Fatalf("seed interface: %v", err)
	}

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	st := &cancelOnPhaseStream{
		mockMigrateStream: mockMigrateStream{ctx: reqCtx},
		phase:             pb.MigratePhase_MIGRATE_COMPLETING,
		cancel:            cancel,
	}
	// The final DONE send succeeds on the mock stream; the error, if any, is
	// beside the point — the finish is what is asserted.
	_ = s.MigrateVM(&pb.MigrateVMRequest{
		VmName: name, TargetHost: "target-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	}, st)
	if !st.fired {
		t.Fatal("the migration never reached MIGRATE_COMPLETING — this scenario proves nothing")
	}

	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	if vm.HostName != "target-host" {
		t.Fatalf("VM is on %q after the cutover, want target-host — the commit did not land", vm.HostName)
	}
	if rec := dns.VMRecordName(name, vm.StackName, s.dnsDomain); !dnsRecordActive(t, s, rec) {
		t.Fatalf("no DNS record %s after the cutover — finishMigrationOnTarget ran on the "+
			"cancelled request context", rec)
	}
}
