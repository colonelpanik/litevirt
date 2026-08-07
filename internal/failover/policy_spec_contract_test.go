package failover

import (
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestVMFailurePolicy_ReadsPersistedVMSpec pins the product-path contract
// end to end: CreateVM persists the pb.VMSpec with encoding/json, and
// vmFailurePolicy must resolve the policy from that exact serialization.
// Before VMSpec.OnHostFailure existed, a compose "on-host-failure:
// restart-any" died in MigrationPolicy's enum (RESTART_ANY = 0, dropped by
// omitempty) and every compose VM was silently skipped on host failure.
func TestVMFailurePolicy_ReadsPersistedVMSpec(t *testing.T) {
	for _, tc := range []struct {
		policy string
		want   string
	}{
		{"restart-any", "restart-any"},
		{"restart-same", "restart-same"},
		{"none", "none"},
		{"", ""},
	} {
		spec := &pb.VMSpec{
			Name: "vm1", Cpu: 1, MemoryMib: 256,
			OnHostFailure: tc.policy,
			// The enum path alone must NOT be able to produce a policy —
			// this mirrors what compose sent before the string field.
			Migrate: &pb.MigrationPolicy{OnHostFailure: pb.HostFailurePolicy_RESTART_ANY},
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got := vmFailurePolicy(corrosion.VMRecord{Name: "vm1", Spec: string(raw)})
		if got != tc.want {
			t.Errorf("policy %q: vmFailurePolicy = %q, want %q", tc.policy, got, tc.want)
		}
	}
}
