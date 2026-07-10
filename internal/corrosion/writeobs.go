package corrosion

import "errors"

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
)

// ClassifyWriteErr maps a write error to its closed error class. A guard-decline
// (no error, applied=false) is reported by the caller as WriteClassPrecondition.
func ClassifyWriteErr(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoRowsAffected):
		return WriteClassNoRows
	default:
		return WriteClassDBError
	}
}
