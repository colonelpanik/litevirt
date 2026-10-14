package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// ownedBy returns the addresses on this host whose inventory owner is vmName.
func ownedBy(t *testing.T, ctx context.Context, s *Server, vmName string) map[string]bool {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	owned := map[string]bool{}
	for _, d := range devs {
		if d.VMName == vmName {
			owned[d.Address] = true
		}
	}
	return owned
}

// TestAllocateDevices_SRIOVBindFailureReleasesTheAllocatedVF is lab finding L1: an
// SR-IOV attach whose vfio bind fails AFTER allocateSRIOVVFs CAS-claimed the VF left
// the VF owned by the VM, though it was back on its host driver and in neither copy
// of the domain. acquireDeviceLeases saw the VF as self-owned, so it was not in the
// rollback set, and nothing reclaimed it: every failed attempt leaked one more VF.
// The attempt must leave nothing owned, and must not touch a device the VM got from
// an earlier, successful attach.
func TestAllocateDevices_SRIOVBindFailureReleasesTheAllocatedVF(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.SetSRIOVPolicy(false, 8, nil)

	pf := "0000:41:00.0"
	vfs := fakeSysfsPF(t, pf, 8, 2)
	seedPCIDevice(t, ctx, s, pf, true)
	for _, vf := range vfs {
		seedPCIDevice(t, ctx, s, vf, false)
	}
	// vfs[0] came from an earlier attach that succeeded: owned and bound.
	if err := corrosion.AssignPCIDevice(ctx, s.db, s.hostName, vfs[0], "vm1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	fake := &failBindFS{pciBindFakeFS: newPCIBindFakeFS(), failAddr: vfs[1]}
	fake.bound[vfs[0]] = true
	defer vfio.SetFS(fake)()

	for attempt := 1; attempt <= 2; attempt++ {
		_, _, err := s.allocateDevices(ctx, "vm1",
			[]*pb.DeviceSpec{{Sriov: true, Type: "network", Parent: pf}}, deviceLeaseStageInProgress)
		if err == nil {
			t.Fatalf("attempt %d: allocateDevices succeeded through a failing bind", attempt)
		}
		owned := ownedBy(t, ctx, s, "vm1")
		if owned[vfs[1]] {
			t.Fatalf("attempt %d: the VF the failed attach allocated (%s) is still owned by vm1: %v", attempt, vfs[1], owned)
		}
		if !owned[vfs[0]] {
			t.Fatalf("attempt %d: the failed attach released %s, which an earlier attach holds", attempt, vfs[0])
		}
	}
}

// TestAllocateDevices_LaterSpecFailureReleasesAnEarlierSpecsVF: allocateSRIOVVFs
// claims as it resolves, so a later spec in the same request that fails to resolve
// must release the VF an earlier spec already took.
func TestAllocateDevices_LaterSpecFailureReleasesAnEarlierSpecsVF(t *testing.T) {
	pf := "0000:41:00.0"
	for _, tc := range []struct {
		name   string
		second *pb.DeviceSpec
	}{
		// Fails in acquireDeviceLeases' ownership claim.
		{"claim", &pb.DeviceSpec{Address: "0000:99:00.0"}},
		// Fails in allocateSRIOVVFs itself: the PF's one VF is already taken.
		{"resolve", &pb.DeviceSpec{Sriov: true, Type: "network", Parent: pf}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			ctx := context.Background()
			s.SetSRIOVPolicy(false, 8, nil)
			defer vfio.SetFS(newPCIBindFakeFS())()

			vfs := fakeSysfsPF(t, pf, 8, 1)
			seedPCIDevice(t, ctx, s, pf, true)
			seedPCIDevice(t, ctx, s, vfs[0], false)

			_, _, err := s.allocateDevices(ctx, "vm1", []*pb.DeviceSpec{
				{Sriov: true, Type: "network", Parent: pf},
				tc.second,
			}, deviceLeaseStageBound)
			if err == nil {
				t.Fatal("allocateDevices succeeded with an unsatisfiable second spec")
			}
			if owned := ownedBy(t, ctx, s, "vm1"); len(owned) != 0 {
				t.Fatalf("a failed request left %v owned by vm1", owned)
			}
		})
	}
}

// TestStartVM_PCIPreflight_SRIOVBindFailureReleasesTheVF is L1 on the start path:
// pciStartPreflight CAS-claims an SR-IOV intent's VF before acquireDeviceLeases, so a
// bind failure there must release it too.
func TestStartVM_PCIPreflight_SRIOVBindFailureReleasesTheVF(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.SetSRIOVPolicy(false, 8, nil)
	ctx := adminCtx()

	pf := "0000:41:00.0"
	vfs := fakeSysfsPF(t, pf, 8, 1)
	seedPCIDevice(t, ctx, s, pf, true)
	seedPCIDevice(t, ctx, s, vfs[0], false)
	defer vfio.SetFS(&failBindFS{pciBindFakeFS: newPCIBindFakeFS(), failAddr: vfs[0]})()
	seedNICVM(t, s, "vm1", "stopped")

	payload, err := protojson.Marshal(&pb.DeviceSpec{Sriov: true, Type: "network", Parent: pf})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := corrosion.UpsertPCIIntent(ctx, s.db, corrosion.PCIIntentRecord{
		VMName: "vm1", DeviceID: "dev-sriov", HostName: "test-host",
		SelectorKind: "sriov", SelectorPayload: string(payload),
	}); err != nil {
		t.Fatalf("seed intent: %v", err)
	}

	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err == nil {
		t.Fatal("start succeeded through a failing bind")
	}
	if owned := ownedBy(t, ctx, s, "vm1"); len(owned) != 0 {
		t.Fatalf("a failed start left %v owned by vm1", owned)
	}
}
