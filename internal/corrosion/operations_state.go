package corrosion

// Operation-journal state machine (F1, v41). The operation_steps table records
// an append-only, per-kind transition graph; this file is the PURE logic that
// defines the legal steps per operation kind and reduces a set of recorded steps
// to the authoritative current state, applying terminal precedence. No DB, no
// I/O — exhaustively unit-testable and identical on every node (recovery reduces
// the SAME steps to the SAME state everywhere).

// OperationKind identifies the workflow an operation drives. Each kind has its
// own happy-path step sequence; all kinds share the terminal states and the
// failure/cancellation/rollback/takeover transitions.
type OperationKind string

const (
	OpResourceUpdateRunning OperationKind = "resource_update_running"
	OpResourceUpdateStopped OperationKind = "resource_update_stopped"
	OpDeviceLease           OperationKind = "device_lease"
	OpRestart               OperationKind = "restart"
)

// Step names. The happy-path steps differ per kind; the terminal + rollback
// steps are shared.
const (
	OpStepPlanned          = "planned"
	OpStepReserved         = "reserved"
	OpStepDesiredPersisted = "desired_persisted"
	OpStepConfigApplied    = "config_applied"
	OpStepLiveApplied      = "live_applied"
	OpStepObserved         = "observed"
	OpStepJournaled        = "journaled"
	OpStepStopped          = "stopped"
	OpStepRedefined        = "redefined"
	OpStepStarted          = "started"
	OpStepClaimed          = "claimed"
	OpStepBound            = "bound"
	OpStepAttached         = "attached"

	// Shared, cross-kind steps.
	OpStepRollbackCompleted = "rollback_completed" // a rollback ran to completion; only then is a failed/cancelled terminal safe
	OpStepCompleted         = "completed"
	OpStepFailed            = "failed"
	OpStepCancelled         = "cancelled"
	OpStepSuperseded        = "superseded" // an older owner epoch was taken over; never terminates the CURRENT epoch
)

// opHappyPath is the ordered happy-path (non-terminal) step sequence per kind.
// The furthest-advanced happy-path step present is the operation's progress when
// no terminal is recorded.
var opHappyPath = map[OperationKind][]string{
	OpResourceUpdateRunning: {OpStepPlanned, OpStepReserved, OpStepDesiredPersisted, OpStepConfigApplied, OpStepLiveApplied, OpStepObserved},
	OpResourceUpdateStopped: {OpStepPlanned, OpStepReserved, OpStepDesiredPersisted, OpStepConfigApplied, OpStepObserved},
	OpDeviceLease:           {OpStepPlanned, OpStepReserved, OpStepClaimed, OpStepBound, OpStepAttached},
	OpRestart:               {OpStepPlanned, OpStepReserved, OpStepDesiredPersisted, OpStepJournaled, OpStepStopped, OpStepRedefined, OpStepStarted, OpStepObserved},
}

var opTerminalStates = map[string]bool{
	OpStepCompleted:  true,
	OpStepFailed:     true,
	OpStepCancelled:  true,
	OpStepSuperseded: true,
}

// IsOperationKind reports whether k is a known operation kind.
func IsOperationKind(k OperationKind) bool { _, ok := opHappyPath[k]; return ok }

// IsTerminalStep reports whether a step name is a terminal state.
func IsTerminalStep(step string) bool { return opTerminalStates[step] }

// IsLegalStep reports whether step is a legal step name for the given kind: a
// happy-path step for that kind, or one of the shared rollback/terminal steps.
func IsLegalStep(kind OperationKind, step string) bool {
	if opTerminalStates[step] || step == OpStepRollbackCompleted {
		return true
	}
	for _, s := range opHappyPath[kind] {
		if s == step {
			return true
		}
	}
	return false
}

// ReduceOperationState reduces the recorded step names of ONE operation (for a
// single authorized owner epoch) to its authoritative current state, applying
// terminal precedence:
//
//   - completed DOMINATES any delayed non-terminal step; cancelled/failed never
//     override a recorded completed.
//   - two conflicting terminals for the same epoch (e.g. completed AND failed, or
//     failed AND cancelled) are a SAFETY FAULT — faulted=true — surfaced rather
//     than silently coin-flipped. The dominant terminal is still returned
//     (completed if present, else failed) so callers have a deterministic value.
//   - superseded applies only to an OLDER owner epoch; if it is the only terminal
//     recorded it is returned, but it never overrides completed.
//   - with no terminal, the state is the furthest-advanced happy-path step (or
//     rollback_completed if a rollback ran), or "" if nothing legal was recorded.
func ReduceOperationState(kind OperationKind, stepNames []string) (state string, faulted bool) {
	present := make(map[string]bool, len(stepNames))
	for _, s := range stepNames {
		present[s] = true
	}

	// Count distinct hard terminals (superseded excluded — it's an epoch-takeover
	// marker, not a completion of THIS epoch's work).
	hardTerminals := 0
	for _, t := range []string{OpStepCompleted, OpStepFailed, OpStepCancelled} {
		if present[t] {
			hardTerminals++
		}
	}
	faulted = hardTerminals > 1

	switch {
	case present[OpStepCompleted]:
		return OpStepCompleted, faulted
	case present[OpStepFailed]:
		return OpStepFailed, faulted
	case present[OpStepCancelled]:
		return OpStepCancelled, faulted
	case present[OpStepSuperseded]:
		return OpStepSuperseded, false
	}

	// A completed rollback undoes forward progress, so it dominates any recorded
	// happy-path step (it is the operation's state until a failed/cancelled
	// terminal is recorded — handled by the terminal switch above).
	if present[OpStepRollbackCompleted] {
		return OpStepRollbackCompleted, false
	}
	// Non-terminal: furthest-advanced happy-path step.
	best, bestIdx := "", -1
	for i, s := range opHappyPath[kind] {
		if present[s] && i > bestIdx {
			best, bestIdx = s, i
		}
	}
	return best, false
}

// IsOperationTerminal reports whether an operation whose steps reduce to `state`
// is finished (a hard terminal or superseded).
func IsOperationTerminal(state string) bool { return opTerminalStates[state] }
