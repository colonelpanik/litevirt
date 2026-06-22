package health

// Restart-policy decision logic, factored out as a pure function so every
// (cause × condition × managed-save) combination is table-testable without
// libvirt/lxc. Shared by the VM checker (vmcheck.go) and the container
// reconciler (containercheck.go).
//
// Semantics ("guest-stick overrides", per the design decision): a clean
// guest-initiated shutdown OR an operator stop is NEVER auto-restarted under any
// condition. Only an UNEXPECTED stop (crash, failure, fence/external destroy)
// triggers a restart. Because clean stops always stick, "on-failure" and
// "always" currently behave identically here — the distinction is reserved for a
// future mode that would also restart clean exits.

// state_detail markers, written by the operators/reconcilers and read back by
// the decision when the live stop-reason isn't available.
const (
	operatorStopDetail     = "operator-stop"       // set by StopVM/StopContainer
	guestShutdownDetail    = "guest-shutdown"      // clean ACPI poweroff from inside the guest
	crashedDetail          = "crashed"             // kernel panic / guest crash / failed start
	outOfBandDestroyDetail = "out-of-band-destroy" // libvirt destroy not initiated by an operator stop (e.g. a fence)
	suspendedDetail        = "suspended"           // managed-save / pm-suspend / RAM-snapshot
)

// classifyStop maps a domain's coarse state + normalized stop reason to the
// (state, state_detail) the reconciler should persist when it finds a VM that
// the cluster thinks is running but libvirt no longer is. sync=false means
// "leave it alone" — the VM isn't really down (paused, migrated elsewhere) or
// another loop owns the transition. The persisted detail is what restartDecision
// reads back when the live reason is later unavailable, so it uses the same
// marker vocabulary.
func classifyStop(state, reason string) (newState, detail string, sync bool) {
	switch reason {
	case "guest-shutdown":
		return "stopped", guestShutdownDetail, true
	case "crashed", "failed":
		return "error", crashedDetail, true
	case "destroyed":
		return "stopped", outOfBandDestroyDetail, true
	case "saved", "pmsuspended":
		return "stopped", suspendedDetail, true
	case "migrated", "from-snapshot", "shutting-down", "paused", "running":
		// Not genuinely down, or owned by migration/snapshot/pause flows.
		return "", "", false
	default:
		// Indeterminate reason but the domain is genuinely not running: still
		// sync the coarse state so the cluster/UI aren't stale, with a generic
		// detail the restart engine treats as "no failure evidence" → stick.
		if state == "running" || state == "" {
			return "", "", false
		}
		return state, "stopped out-of-band", true
	}
}

// restartDecision reports whether a stopped workload should be auto-restarted,
// plus a human-readable reason for logs/events.
//
//	cause          — normalized stop reason (libvirt DomainStatus.Reason), or "" when unknown
//	stateDetail    — the persisted vms/containers.state_detail (intent/cause fallback)
//	hasManagedSave — true if the domain has a suspend-to-disk image (never cold-boot)
//	condition      — restart policy: "" | "none" | "on-failure" | "always"
func restartDecision(cause, stateDetail string, hasManagedSave bool, condition string) (restart bool, reason string) {
	switch condition {
	case "", "none":
		return false, "restart policy: none"
	case "on-failure", "always":
		// fall through to cause analysis
	default:
		// Unknown/garbled condition → fail safe: never restart.
		return false, "restart policy: unrecognized condition " + condition
	}

	// A suspended workload must be resumed, never cold-booted (would lose RAM).
	if hasManagedSave {
		return false, "suspended (managed-save) — resume, never cold-restart"
	}
	// Operator explicitly stopped it → stick.
	if stateDetail == operatorStopDetail {
		return false, "operator stop — stick"
	}

	switch cause {
	case "guest-shutdown":
		return false, "clean guest shutdown — stick"
	case "saved", "pmsuspended", "paused":
		return false, "suspended/paused — skip"
	case "migrated", "from-snapshot", "shutting-down":
		return false, "skip: " + cause
	case "crashed", "failed", "destroyed":
		return true, "unexpected stop (" + cause + ") — restart per policy"
	case "", "unknown", "daemon":
		// Live reason unavailable/indeterminate: only restart if the persisted
		// detail already evidences a failure; otherwise stick (don't reboot on
		// a guess).
		if stateDetail == crashedDetail || stateDetail == outOfBandDestroyDetail {
			return true, "unexpected stop (detail=" + stateDetail + ") — restart per policy"
		}
		return false, "indeterminate stop — stick (no failure evidence)"
	default:
		return false, "unrecognized cause " + cause + " — stick"
	}
}
