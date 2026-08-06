package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// D1 — project-admission authority. Project quota is a HARD admission guarantee, so
// one deterministic holder per NORMALIZED project serializes it. Authority is
// STICKY: the initial holder is minted once; it does not move merely because
// membership changes. A PLANNED handoff records an explicit transfer; an UNPLANNED
// takeover requires PROOF-GRADE fencing of the prior holder (a fence_proof_ref).
// Every transfer mints a monotonic authority_epoch; admission accepts reservations
// only from the CURRENT epoch, so a stale ex-holder's writes are rejected.

// ErrFenceProofRequired is returned when an unplanned ("fenced") takeover is
// attempted without a proof reference for the prior holder's fence.
var ErrFenceProofRequired = errors.New("corrosion: a fenced project-authority takeover requires a fence_proof_ref")

// ProjectAuthority is a project's admission-authority record. The CURRENT authority
// is the row with the maximum live authority_epoch for the project.
type ProjectAuthority struct {
	Project       string
	Epoch         int64
	Holder        string
	TransferKind  string // initial | planned | fenced
	FenceProofRef string
}

// CurrentProjectAuthority returns the highest live authority epoch for a project,
// or ok=false when the project has no authority yet.
func CurrentProjectAuthority(ctx context.Context, c *Client, project string) (ProjectAuthority, bool, error) {
	project = projectOrDefault(project)
	// ORDER BY … holder ASC: the tie-break matters. A cluster that ran an older
	// build may already hold two epoch-1 rows for one project (two nodes minted
	// concurrently; see ClaimInitialProjectAuthority's warning). The PK
	// (project, authority_epoch) makes that pair an immutable_conflict that is
	// kept-local on both sides and never resolved, so the rows persist. Picking
	// deterministically among equal epochs at least makes every node AGREE on
	// which one wins, turning permanent divergence into a stable answer.
	rows, err := c.Query(ctx,
		`SELECT project, authority_epoch, holder, transfer_kind, fence_proof_ref
		 FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL
		 ORDER BY authority_epoch DESC, holder ASC LIMIT 1`, project)
	if err != nil {
		return ProjectAuthority{}, false, err
	}
	if len(rows) == 0 {
		return ProjectAuthority{}, false, nil
	}
	r := rows[0]
	return ProjectAuthority{
		Project:       r.String("project"),
		Epoch:         r.Int64("authority_epoch"),
		Holder:        r.String("holder"),
		TransferKind:  r.String("transfer_kind"),
		FenceProofRef: r.String("fence_proof_ref"),
	}, true, nil
}

// ClaimInitialProjectAuthority mints epoch 1 for a project with holder, iff no
// authority exists yet. Returns applied=false (no error) if another node already
// established authority (the caller re-reads the current holder).
//
// DO NOT CALL THIS TO ESTABLISH AN INITIAL AUTHORITY. Use ResolveProjectAuthority.
//
// The guard runs inside ExecuteBatchGuarded, which is a LOCAL transaction, so it
// cannot make this a cluster-wide single writer: on two nodes both guards see
// COUNT(*) = 0 before either has replicated and both insert epoch 1. The PK is
// (project, authority_epoch), so those two rows collide with DIFFERENT facts, and
// project_authority_epochs merges via immutableMergeKeepLocalRow — which
// deliberately refuses to coin-flip an immutable row and instead keeps both sides
// locally and flags immutable_conflict, PERMANENTLY. The project then has two
// holders until an operator repairs it. (immutableFactsEqual compares created_at,
// per-node wall time, so even two claims naming the same holder conflict — making
// the holder agree is not sufficient; only one node may write.)
//
// A "deterministic candidate" is not enough either: the candidate is computed from
// the replicated host set, which is delivered ASYNCHRONOUSLY, so two nodes with
// different views of hosts/states compute different winners and both mint.
//
// The initial authority is therefore DERIVED, never written. Only an explicit
// transfer records a row (TakeoverProjectAuthority), and a transfer has a real
// single writer: the CAS on expectedPrevEpoch.
func ClaimInitialProjectAuthority(ctx context.Context, c *Client, project, holder string) (applied bool, err error) {
	project = projectOrDefault(project)
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		var n int
		qerr := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL`, project).Scan(&n)
		return n == 0, qerr
	}
	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO project_authority_epochs
		      (project, authority_epoch, holder, transfer_kind, fence_proof_ref, created_at, updated_at, deleted_at)
		      VALUES (?, 1, ?, 'initial', '', ?, ?, NULL)`,
		Params: []interface{}{project, holder, wall, now},
	}}
	return c.ExecuteBatchGuarded(ctx, guard, stmts)
}

// TakeoverProjectAuthority mints epoch = expectedPrevEpoch+1 with the new holder.
// transferKind must be "planned" (an explicit relinquish/handoff) or "fenced" (an
// unplanned takeover, which REQUIRES fenceProofRef — proof the prior holder was
// fenced). Returns applied=false (no error) on a CAS miss (the current epoch is no
// longer expectedPrevEpoch — someone else transferred first).
func TakeoverProjectAuthority(ctx context.Context, c *Client, project, holder, transferKind, fenceProofRef string, expectedPrevEpoch int64) (newEpoch int64, applied bool, err error) {
	project = projectOrDefault(project)
	switch transferKind {
	case "planned":
	case "fenced":
		if fenceProofRef == "" {
			return 0, false, ErrFenceProofRequired
		}
	default:
		return 0, false, fmt.Errorf("corrosion: invalid project-authority transfer_kind %q (want planned|fenced)", transferKind)
	}
	newEpoch = expectedPrevEpoch + 1
	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		var maxEpoch sql.NullInt64
		qerr := tx.QueryRowContext(ctx,
			`SELECT MAX(authority_epoch) FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL`, project).Scan(&maxEpoch)
		if qerr != nil {
			return false, qerr
		}
		// No rows means the project's authority is DERIVED, not recorded (see
		// ResolveProjectAuthority) — a derived authority is epoch 0, so a first
		// explicit transfer legitimately expects 0 and mints epoch 1.
		if !maxEpoch.Valid {
			return expectedPrevEpoch == 0, nil
		}
		return maxEpoch.Int64 == expectedPrevEpoch, nil
	}
	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO project_authority_epochs
		      (project, authority_epoch, holder, transfer_kind, fence_proof_ref, created_at, updated_at, deleted_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{project, newEpoch, holder, transferKind, fenceProofRef, wall, now},
	}}
	applied, err = c.ExecuteBatchGuarded(ctx, guard, stmts)
	return newEpoch, applied, err
}

// ValidateProjectAuthority reports whether (project, epoch, holder) is the CURRENT
// authority — the admission check that rejects a stale ex-holder's reservation.
func ValidateProjectAuthority(ctx context.Context, c *Client, project string, epoch int64, holder string) (bool, error) {
	cur, ok, err := CurrentProjectAuthority(ctx, c, project)
	if err != nil || !ok {
		return false, err
	}
	return cur.Epoch == epoch && cur.Holder == holder, nil
}

// DeterministicAuthorityCandidate picks the single node that may MINT a project's
// initial authority, by rendezvous hash over the eligible hosts.
//
// This is not a load-balancing nicety — it is required for correctness.
// project_authority_epochs uses immutableMergeKeepLocalRow (see customMergeTables),
// so two nodes each minting epoch 1 is not resolved by last-writer-wins: it is
// flagged as an immutable_conflict and kept-local on BOTH sides, permanently, so
// the project has two holders until an operator repairs it. And because
// immutableFactsEqual compares created_at (per-node wall time), even two claims
// naming the SAME holder conflict. "Have every node write the same holder" is
// therefore not sufficient; exactly one node may write at all.
//
// ClaimInitialProjectAuthority's guard cannot prevent this on its own —
// ExecuteBatchGuarded is a LOCAL transaction, so both nodes see COUNT(*) = 0 before
// either has replicated.
//
// Eligible = state "active", not a witness (witnesses never carry workloads, so
// they must not carry admission authority either). Returns ok=false when no host
// qualifies, in which case the caller must not claim.
func DeterministicAuthorityCandidate(hosts []HostRecord, project string) (host string, ok bool) {
	project = projectOrDefault(project)
	var best string
	var bestScore uint64
	for _, h := range hosts {
		if h.State != "active" || strings.EqualFold(h.Role, "witness") {
			continue
		}
		// Rendezvous ("highest random weight") hashing: every node computes the
		// same winner from the same host set without any coordination, and losing
		// one host reassigns only the projects it held.
		sum := sha256.Sum256([]byte(project + "\x00" + h.Name))
		score := binary.BigEndian.Uint64(sum[:8])
		if best == "" || score > bestScore || (score == bestScore && h.Name < best) {
			best, bestScore = h.Name, score
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// ResolveProjectAuthority reports who serializes a project's admission.
//
// An explicitly RECORDED authority wins: a transfer is a deliberate operator or
// coordinator act, is CAS-guarded on the previous epoch, and is sticky.
//
// With no record — the common case — the authority is DERIVED from the current host
// set and nothing is written. That is the whole point: a derived authority cannot
// produce a conflicting row, so the permanent-divergence class above simply does
// not exist. Epoch 0 marks "derived".
//
// The trade this makes, stated plainly: a derived authority is NOT sticky. Two nodes
// whose replicated host views differ can briefly disagree about the holder, so both
// may serialize the same project independently — a bounded over-admission window
// that closes as soon as host state converges, and one the admission RPC actively
// corrects (it refuses a non-holder and reports the holder it sees). That is
// strictly better than a permanently divergent pair of epoch-1 rows that needs an
// operator to repair and silently leaves the project with two holders forever.
//
// ok=false means no authority could be resolved at all (no eligible host); the
// caller must not treat itself as the holder.
func ResolveProjectAuthority(ctx context.Context, c *Client, project string) (ProjectAuthority, bool, error) {
	cur, ok, err := CurrentProjectAuthority(ctx, c, project)
	if err != nil {
		return ProjectAuthority{}, false, err
	}
	if ok {
		return cur, true, nil
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return ProjectAuthority{}, false, err
	}
	candidate, hasCandidate := DeterministicAuthorityCandidate(hosts, project)
	if !hasCandidate {
		return ProjectAuthority{}, false, nil
	}
	return ProjectAuthority{
		Project:      projectOrDefault(project),
		Epoch:        0, // derived, not recorded
		Holder:       candidate,
		TransferKind: "derived",
	}, true, nil
}
