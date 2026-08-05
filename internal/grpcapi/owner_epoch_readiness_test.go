package grpcapi

import (
	"context"
	"fmt"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Every readiness predicate must INDEPENDENTLY withhold advertisement — the
// latch requires every node, so one node's blind spot must be enough to keep
// the whole regime from forming.

func stampVMEpoch(t *testing.T, s *Server, name string, epoch int64) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`UPDATE vms SET vm_owner_epoch = ? WHERE name = ?`, epoch, name); err != nil {
		t.Fatalf("stamp epoch: %v", err)
	}
}

func readinessServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := inventoryServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	return s, fake
}

func requireWithheld(t *testing.T, s *Server, wantSubstr string) {
	t.Helper()
	s.invalidateInventoryCache()
	ready, reason := s.OwnerEpochReadiness(context.Background())
	if ready {
		t.Fatalf("readiness advertised, want withheld (%s)", wantSubstr)
	}
	if wantSubstr != "" && !stringsContains(reason, wantSubstr) {
		t.Fatalf("withhold reason = %q, want it to mention %q", reason, wantSubstr)
	}
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestOwnerEpochReadiness_CleanNodeAdvertises(t *testing.T) {
	s, fake := readinessServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm1", 3)
	fake.SetState("vm1", libvirtfake.StateRunning)
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 3); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	ready, reason := s.OwnerEpochReadiness(ctx)
	if !ready {
		t.Fatalf("clean node withheld: %s", reason)
	}
}

func TestOwnerEpochReadiness_EachPredicateWithholds(t *testing.T) {
	// 1. Incomplete local inventory.
	s, _ := readinessServer(t)
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	requireWithheld(t, s, "inventory incomplete")

	// 2. An owned workload still at epoch 0.
	s, fake := readinessServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "legacy", HostName: s.hostName, Spec: "{}", State: "stopped", OwnerEpoch: 0,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	requireWithheld(t, s, "epoch 0")

	// 3. A running workload whose marker is MISSING.
	s, fake = readinessServer(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-nomark", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm-nomark", 2)
	fake.SetState("vm-nomark", libvirtfake.StateRunning)
	requireWithheld(t, s, "missing")

	// 4. A running workload whose marker DISAGREES with the DB epoch.
	s, fake = readinessServer(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-drift", HostName: s.hostName, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	stampVMEpoch(t, s, "vm-drift", 5)
	fake.SetState("vm-drift", libvirtfake.StateRunning)
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm-drift", 4); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	requireWithheld(t, s, "marker epoch 4 != DB epoch 5")

	// 5. An active ownership condition anywhere in the cluster.
	s, _ = readinessServer(t)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "runtime_owner_mismatch", SubjectKind: "vm", SubjectID: "elsewhere",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
	}); err != nil {
		t.Fatalf("seed condition: %v", err)
	}
	requireWithheld(t, s, "active ownership condition")
}
