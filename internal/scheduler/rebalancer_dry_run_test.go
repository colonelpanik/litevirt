package scheduler

import "testing"

// TestAutoApproves_ForceDryRunApprovesNothing: a forced dry run leaves every
// proposal pending, including an auto-mode VM's; without it the per-VM mode
// still decides.
func TestAutoApproves_ForceDryRunApprovesNothing(t *testing.T) {
	cases := []struct {
		mode  Mode
		force bool
		want  bool
	}{
		{ModeAuto, false, true},
		{ModeAuto, true, false},
		{ModeDryRun, false, false},
		{ModeDryRun, true, false},
	}
	for _, tc := range cases {
		r := &Rebalancer{ForceDryRun: tc.force}
		if got := r.autoApproves(Proposal{Mode: tc.mode}); got != tc.want {
			t.Errorf("mode=%s ForceDryRun=%t: autoApproves = %t, want %t", tc.mode, tc.force, got, tc.want)
		}
	}
}
