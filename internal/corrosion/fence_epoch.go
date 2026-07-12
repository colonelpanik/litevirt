package corrosion

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SharedDiskFenceWindow bounds how recent a proof-grade fence must be to authorize
// a shared-disk cross-host transfer — a stale prior fence of the old owner must not
// authorize a fresh transfer. Matches the coordinator's recentFenceWindow.
const SharedDiskFenceWindow = 5 * time.Minute

// FenceCheck classifies a proof-grade-fence verification: OK to proceed, RETRY
// (the referenced fencing_log row hasn't replicated here yet — transient), or
// REJECT (no/inadequate proof-grade fence — terminal).
type FenceCheck int

const (
	FenceOK FenceCheck = iota
	FenceRetry
	FenceReject
)

// CheckProofGradeFence re-reads the fence_epoch's fencing_log row and classifies
// whether it PROVES a proof-grade power-off within window. It never trusts a stale
// hosts.state=="fenced" — only the append-only fencing_log row the fence_epoch
// names. The caller maps the tri-state to its own error vocabulary (grpc
// Unavailable for RETRY, FailedPrecondition + storage_unverified for REJECT).
//
// oldOwner is the VM's ACTUAL recorded owner when the caller knows it independently
// (the promote path, whose vm.HostName is still the pre-transfer owner) — an extra
// cross-check that the coordinator's fence_epoch binds that exact host. Pass "" when
// the caller can't independently derive the old owner (the reschedule/reconciler
// path re-points host_name to the target before the reconciler runs); the check then
// trusts the proof-protected fence_epoch.Host and only re-verifies that host's
// fencing_log row is proof-grade + recent.
func CheckProofGradeFence(ctx context.Context, c *Client, fenceEpoch, oldOwner string, window time.Duration) (FenceCheck, string) {
	ref, ok := ParseFenceEpoch(fenceEpoch)
	if !ok {
		// Empty includes a proof minted by a pre-fence_epoch node (mixed-version).
		return FenceReject, "no proof-grade fence bound"
	}
	expectHost := ref.Host
	if oldOwner != "" {
		if ref.Host != oldOwner {
			return FenceReject, fmt.Sprintf("fence_epoch binds host %q, not old owner %q", ref.Host, oldOwner)
		}
		expectHost = oldOwner
	}
	row, found, err := GetFenceLog(ctx, c, ref.FenceID)
	if err != nil {
		return FenceRetry, fmt.Sprintf("read fence log %s: %v", ref.FenceID, err)
	}
	if !found {
		// The row rides the same replication as the carried proof — retry, not refuse.
		return FenceRetry, fmt.Sprintf("fence_epoch row %s for %q not yet replicated", ref.FenceID, expectHost)
	}
	if row.HostName != expectHost || !FenceProofGrade(row.Method, row.Result) {
		return FenceReject, fmt.Sprintf("fence %s of %q is not proof-grade (method=%s result=%s)",
			ref.FenceID, row.HostName, row.Method, row.Result)
	}
	if ts, perr := time.Parse(time.RFC3339, row.Timestamp); perr != nil || time.Since(ts) > window {
		return FenceReject, fmt.Sprintf("fence %s is stale or undated", ref.FenceID)
	}
	return FenceOK, ""
}

// FenceProofGrade reports whether a fencing_log (method, result) pair PROVES the
// old owner is actually powered off — the bar a cross-host SHARED-disk ownership
// transfer must clear (capabilities.SharedStorageFenceV1). It accepts ONLY a
// confirmed power-off:
//
//   - result "fenced" + method "ipmi": IPMI/BMC power-off with verify.
//   - result "manual-confirmed": an operator ran `lv host fence-confirm` after
//     physically powering the host off.
//
// It REJECTS a best-effort / plain SSH "fenced" (a lenient SSH poweroff reports
// success but never confirms the host is down), a "partial" (failed) fence, an
// unconfirmed "manual", and a "watchdog" result (a self-fence timer can't be
// positively verified on all hardware). This is deliberately STRICTER than the
// per-host safe_fence gate, which a best-effort success can satisfy — a shared
// writable disk started on a second host while the first may still write it
// corrupts the disk, so only a proven power-off is acceptable.
func FenceProofGrade(method, result string) bool {
	switch {
	case result == "manual-confirmed":
		return true
	case result == "fenced" && method == "ipmi":
		return true
	default:
		return false
	}
}

// FenceEpochRef binds a cross-host transfer proof to the SPECIFIC fence of the old
// owner that authorizes it. It is carried in RuntimeActionProof.fence_epoch and the
// executor re-reads FenceID from fencing_log to re-verify a proof-grade power-off
// (never a stale hosts.state=="fenced").
type FenceEpochRef struct {
	Host    string // old owner that was fenced
	FenceID string // fencing_log row id
	TS      string // RFC3339 event time of that fence (audit/recency hint)
}

// String renders the wire form "host=<h>;fence_id=<id>;ts=<ts>", or "" when there
// is no fence to bind (FenceID empty) — an empty fence_epoch means "no proof-grade
// fence", which a new executor treats as fail-closed for a shared-disk transfer.
func (r FenceEpochRef) String() string {
	if r.FenceID == "" {
		return ""
	}
	return fmt.Sprintf("host=%s;fence_id=%s;ts=%s", r.Host, r.FenceID, r.TS)
}

// ParseFenceEpoch parses the wire form written by FenceEpochRef.String. ok=false
// for an empty string (no binding) or a malformed value (missing host/fence_id).
func ParseFenceEpoch(s string) (FenceEpochRef, bool) {
	if s == "" {
		return FenceEpochRef{}, false
	}
	var ref FenceEpochRef
	for _, part := range strings.Split(s, ";") {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch k {
		case "host":
			ref.Host = v
		case "fence_id":
			ref.FenceID = v
		case "ts":
			ref.TS = v
		}
	}
	if ref.Host == "" || ref.FenceID == "" {
		return FenceEpochRef{}, false
	}
	return ref, true
}

// GetFenceLog reads a single fencing_log row by id (append-only, wall-clock —
// NOT an LWW row). found=false when no such row has replicated here yet, which
// the caller treats as retryable (the row rides the same replication as a
// carried proof), never as a terminal refusal.
func GetFenceLog(ctx context.Context, c *Client, id string) (FenceLogRecord, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id, host_name, method, result, timestamp, detail FROM fencing_log WHERE id = ?`, id)
	if err != nil {
		return FenceLogRecord{}, false, err
	}
	if len(rows) == 0 {
		return FenceLogRecord{}, false, nil
	}
	r := rows[0]
	return FenceLogRecord{
		ID: r.String("id"), HostName: r.String("host_name"), Method: r.String("method"),
		Result: r.String("result"), Detail: r.String("detail"), Timestamp: r.String("timestamp"),
	}, true, nil
}
