package health

import "testing"

// Exhaustive coverage of the restart decision across cause × condition ×
// managed-save, including the guest-stick override and the state_detail fallback.
func TestRestartDecision(t *testing.T) {
	cases := []struct {
		name        string
		cause       string
		detail      string
		managedSave bool
		condition   string
		want        bool
	}{
		// condition gate
		{"none-never", "crashed", "", false, "none", false},
		{"empty-condition-never", "crashed", "", false, "", false},
		{"bogus-condition-failsafe", "crashed", "", false, "weird", false},

		// managed-save blocks restart regardless of cause/condition (never lose RAM)
		{"managed-save-blocks-always", "crashed", "", true, "always", false},
		{"managed-save-blocks-onfailure", "crashed", "", true, "on-failure", false},

		// operator stop sticks under any condition, even over a failure cause
		{"operator-stop-onfailure", "destroyed", operatorStopDetail, false, "on-failure", false},
		{"operator-stop-beats-crash", "crashed", operatorStopDetail, false, "always", false},

		// guest-stick override: clean guest shutdown never restarts, even under `always`
		{"guest-shutdown-onfailure", "guest-shutdown", "", false, "on-failure", false},
		{"guest-shutdown-always", "guest-shutdown", "", false, "always", false},

		// suspended / paused / moved → skip
		{"saved-skip", "saved", "", false, "always", false},
		{"pmsuspended-skip", "pmsuspended", "", false, "always", false},
		{"paused-skip", "paused", "", false, "always", false},
		{"migrated-skip", "migrated", "", false, "always", false},
		{"from-snapshot-skip", "from-snapshot", "", false, "always", false},
		{"shutting-down-skip", "shutting-down", "", false, "always", false},

		// failures → restart under both on-failure and always
		{"crashed-onfailure", "crashed", "", false, "on-failure", true},
		{"crashed-always", "crashed", "", false, "always", true},
		{"failed-onfailure", "failed", "", false, "on-failure", true},
		{"fence-destroy-onfailure", "destroyed", "", false, "on-failure", true}, // no operator-stop → fence
		{"fence-destroy-always", "destroyed", "", false, "always", true},

		// indeterminate live cause → fall back to persisted detail
		{"unknown-no-evidence-stick", "unknown", "", false, "on-failure", false},
		{"empty-no-evidence-stick", "", "", false, "always", false},
		{"daemon-no-evidence-stick", "daemon", "", false, "always", false},
		{"unknown-crashed-detail-restart", "unknown", crashedDetail, false, "on-failure", true},
		{"empty-outofband-detail-restart", "", outOfBandDestroyDetail, false, "always", true},
		{"unknown-operator-detail-stick", "unknown", operatorStopDetail, false, "always", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := restartDecision(tc.cause, tc.detail, tc.managedSave, tc.condition)
			if got != tc.want {
				t.Errorf("restartDecision(cause=%q detail=%q ms=%v cond=%q) = %v (%q); want %v",
					tc.cause, tc.detail, tc.managedSave, tc.condition, got, reason, tc.want)
			}
		})
	}
}

func TestClassifyStop(t *testing.T) {
	cases := []struct {
		reason, state         string
		wantState, wantDetail string
		wantSync              bool
	}{
		{"guest-shutdown", "stopped", "stopped", guestShutdownDetail, true},
		{"crashed", "error", "error", crashedDetail, true},
		{"failed", "stopped", "error", crashedDetail, true},
		{"destroyed", "stopped", "stopped", outOfBandDestroyDetail, true},
		{"saved", "stopped", "stopped", suspendedDetail, true},
		{"pmsuspended", "stopped", "stopped", suspendedDetail, true},
		{"migrated", "stopped", "", "", false},
		{"paused", "stopped", "", "", false},
		{"from-snapshot", "stopped", "", "", false},
		{"running", "running", "", "", false},
		{"unknown", "stopped", "stopped", "stopped out-of-band", true},
		{"unknown", "running", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.reason+"/"+tc.state, func(t *testing.T) {
			gs, gd, gsync := classifyStop(tc.state, tc.reason)
			if gs != tc.wantState || gd != tc.wantDetail || gsync != tc.wantSync {
				t.Errorf("classifyStop(%q,%q) = (%q,%q,%v); want (%q,%q,%v)",
					tc.state, tc.reason, gs, gd, gsync, tc.wantState, tc.wantDetail, tc.wantSync)
			}
		})
	}
}
