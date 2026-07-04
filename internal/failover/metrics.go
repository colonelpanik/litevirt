package failover

// Metrics is the optional, nil-safe observability sink for the failover
// coordinator. It is defined here (not imported from internal/metrics) so the
// failover package stays free of a Prometheus dependency and tests can use a
// trivial fake. *metrics.FailoverMetrics satisfies it structurally.
type Metrics interface {
	// Attempt records a decision point: a failover phase reaching a result,
	// optionally with a bounded error class.
	Attempt(phase, result, errorClass string)
	// VMAction records a per-VM failover action outcome (promote, reschedule).
	VMAction(action, result, errorClass string)
	// ContainerAction records a per-container failover action outcome (relocate).
	ContainerAction(action, result, errorClass string)
}

// Phases, results, actions, and error classes are a CLOSED vocabulary kept as
// constants so a typo can't mint a stray Prometheus series and the label
// cardinality stays bounded (a few × a few × a few).
const (
	PhaseLease      = "lease"
	PhaseQuorum     = "quorum"
	PhaseHealth     = "health-query"
	PhaseSkip       = "skip"
	PhaseFence      = "fence"
	PhaseSplitBrain = "split-brain-guard"
	PhaseRecovery   = "recovery"

	ResultOK        = "ok"
	ResultSkipped   = "skipped"
	ResultSuccess   = "success"
	ResultPartial   = "partial"
	ResultRefused   = "refused"
	ResultError     = "error"
	ResultRecovered = "recovered"

	ActionPromote    = "promote"
	ActionReschedule = "reschedule"
	ActionRelocate   = "relocate"

	// errClassNone is the empty error class (a clean outcome).
	errClassNone = ""

	ErrNoQuorum          = "no_quorum"
	ErrDestUngated       = "dest_ungated" // target no longer advertises the split-brain gate
	ErrSelfFenced        = "self_fenced"  // this coordinator self-fenced; skips driving failover until reboot
	ErrLeaseLost         = "lease_lost"
	ErrNotLeader         = "not_leader"
	ErrTerminalState     = "terminal_state"
	ErrAlreadyFenced     = "already_fenced"
	ErrUpgrading         = "upgrading"
	ErrRecentlyFenced    = "recently_fenced"
	ErrFirmwareState     = "firmware_state_missing"
	ErrPolicyNone        = "policy_none"
	ErrNoCandidates      = "no_candidates"
	ErrPlacementFailed   = "placement_failed"
	ErrFenceFailed       = "fence_failed"
	ErrManualUnconfirmed = "manual_unconfirmed"
	ErrBestEffort        = "best_effort"
	ErrManualConfirmed   = "manual_confirmed"
	ErrNonRepullable     = "non_repullable_image"
	ErrDBError           = "db_error"
	ErrFenceLogWrite     = "fence_log_write_failed"
	ErrPromoteFailed     = "promote_failed"
	ErrRelocateFailed    = "relocate_failed"
	ErrRestoreUnknown    = "restore_unknown"
)

// nil-safe wrappers so the coordinator can increment unconditionally.
func (c *Coordinator) mAttempt(phase, result, errClass string) {
	if c.Metrics != nil {
		c.Metrics.Attempt(phase, result, errClass)
	}
}

func (c *Coordinator) mVM(action, result, errClass string) {
	if c.Metrics != nil {
		c.Metrics.VMAction(action, result, errClass)
	}
}

func (c *Coordinator) mCt(action, result, errClass string) {
	if c.Metrics != nil {
		c.Metrics.ContainerAction(action, result, errClass)
	}
}
