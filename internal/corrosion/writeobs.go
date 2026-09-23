package corrosion

import (
	"context"
	"errors"
)

// Closed vocabulary for the state-write-failure observer (litevirt_state_write_
// failures_total). These name the AUTHORITATIVE ownership/state writes whose
// failure the daemon must not swallow. Kept here (not in internal/metrics) so the
// health/failover/grpcapi packages can label a failure without importing
// Prometheus — they call a nil-safe func(op, class string) observer, mirroring the
// split-brain gate-refused observer. The op set is bounded (never a host/vm NAME).
const (
	OpVMState        = "vm_state"
	OpVMHost         = "vm_host"
	OpDiskHostPath   = "disk_host_path"
	OpImage          = "image"
	OpImageHost      = "image_host"
	OpContainerState = "container_state"
)

// Error classes distinguish the KIND of write failure. A no-rows result is not a
// transport error — it means the row vanished (a legitimate concurrent delete at
// some call sites, a lost-update bug at others); a precondition failure is a
// guarded-batch predicate that no longer held. Keeping them separate preserves the
// distinction operators (and the split-brain work) rely on.
const (
	WriteClassDBError      = "db_error"
	WriteClassNoRows       = "no_rows"
	WriteClassPrecondition = "precondition_failed"
	// WriteClassOwnershipMoved: the row named another host by the time the write
	// reached it. On a rebalancing or draining fleet that is routine, and bucketing
	// it as db_error made the metric report store faults that never happened.
	WriteClassOwnershipMoved = "ownership_moved"
	// WriteClassCancelled: the daemon is shutting down, or the RPC's caller hung
	// up. Nothing about the store is wrong, so a shutdown must not read as an
	// outage on the dashboard.
	WriteClassCancelled = "cancelled"
)

// ErrOwnershipMoved reports that the row a write was about to touch names a
// different host. Callers treat it as "not mine to write", not as a fault.
//
// Here rather than in internal/health so ClassifyWriteErr can recognize it:
// health imports corrosion, never the reverse, and a sentinel the classifier
// cannot see is one every call site has to special-case by hand.
var ErrOwnershipMoved = errors.New("ownership moved to another host before the write")

// ClassifyWriteErr maps a write error to its closed error class. A guard-decline
// (no error, applied=false) is reported by the caller as WriteClassPrecondition.
func ClassifyWriteErr(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoRowsAffected):
		return WriteClassNoRows
	case errors.Is(err, ErrOwnershipMoved):
		return WriteClassOwnershipMoved
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return WriteClassCancelled
	default:
		return WriteClassDBError
	}
}

// Routine reports whether a write failure is an expected outcome rather than a
// fault — an ownership move or a cancelled shutdown. Call sites use it to pick a
// log level, so a draining fleet does not fill the log with ERROR lines for
// transitions that were correctly declined.
func Routine(err error) bool {
	switch ClassifyWriteErr(err) {
	case WriteClassOwnershipMoved, WriteClassCancelled:
		return true
	}
	return false
}
