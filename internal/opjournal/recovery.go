package opjournal

// Recovery decision logic for the startup recovery barrier. Kept pure (no DB, no
// I/O) so it is exhaustively testable; the daemon supplies the replicated
// operation state and then acts on the returned action. The rule mirrors F1's
// takeover contract: the original host performs an external rollback ONLY while
// it is still the authorized owner of the operation; once ownership has moved
// (or the operation is gone) it does NO external rollback — it only supersedes
// and archives its local journal.

// RecoveryAction is what the original host should do with a host-local journal
// entry at startup, given the current replicated operation state.
type RecoveryAction int

const (
	// RecoveryResume: the operation is still live and this host is still the
	// authorized owner at the entry's epoch — resume/roll back using the entry's
	// artifacts (the resource coordinator drives the actual continuation).
	RecoveryResume RecoveryAction = iota
	// RecoveryCleanup: the operation is terminal and this host is still the
	// authorized owner — the artifacts are no longer needed; remove the entry.
	RecoveryCleanup
	// RecoverySupersede: the operation is gone (GC'd) or ownership has moved to a
	// newer epoch — the original host must NOT perform any external rollback; it
	// archives/removes the now-superseded entry.
	RecoverySupersede
)

func (a RecoveryAction) String() string {
	switch a {
	case RecoveryResume:
		return "resume"
	case RecoveryCleanup:
		return "cleanup"
	case RecoverySupersede:
		return "supersede"
	default:
		return "unknown"
	}
}

// DecideRecovery decides the action for one journal entry.
//
//   - opExists is whether the replicated operations header still exists (a GC'd
//     operation is gone).
//   - currentOwnerEpoch is the VM's CURRENT authorized owner epoch (vms row); if
//     it has advanced past the entry's epoch, ownership was taken over.
//   - opTerminal is whether the operation's steps reduce to a terminal state.
//
// A takeover or a vanished operation → supersede (no external rollback). Still
// the authorized owner → resume if non-terminal, cleanup if terminal.
func DecideRecovery(entry Entry, opExists bool, currentOwnerEpoch int64, opTerminal bool) RecoveryAction {
	if !opExists || currentOwnerEpoch != entry.OwnerEpoch {
		return RecoverySupersede
	}
	if opTerminal {
		return RecoveryCleanup
	}
	return RecoveryResume
}

// OpStateLookup returns the replicated state the recovery decision needs for one
// operation: whether its header still exists, the VM's CURRENT authorized owner
// epoch, and whether the operation's steps reduce to a terminal state. The
// daemon supplies this backed by the state DB (keeping this package DB-free).
type OpStateLookup func(operationID string) (exists bool, currentOwnerEpoch int64, terminal bool, err error)

// PlannedRecovery pairs a journal entry with the action decided for it.
type PlannedRecovery struct {
	Entry  Entry
	Action RecoveryAction
}

// PlanRecovery lists the journal and decides an action for every entry using the
// supplied lookup. It returns the plan plus the filenames of any corrupt entries
// (the caller marks the host degraded and blocks affected mutations if the list
// is non-empty — a corrupt entry is never silently ignored). The plan is not
// executed here; the caller removes cleanup/supersede entries and hands resume
// entries to the resource coordinator.
func (j *Journal) PlanRecovery(lookup OpStateLookup) (plan []PlannedRecovery, corrupt []string, err error) {
	entries, corrupt, err := j.List()
	if err != nil {
		return nil, corrupt, err
	}
	for _, e := range entries {
		exists, epoch, terminal, lerr := lookup(e.OperationID)
		if lerr != nil {
			return plan, corrupt, lerr
		}
		plan = append(plan, PlannedRecovery{Entry: e, Action: DecideRecovery(e, exists, epoch, terminal)})
	}
	return plan, corrupt, nil
}
