package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
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

// DeriveProjectAuthorityHolder picks a project's INITIAL authority holder from the
// eligible hosts, deterministically.
//
// Every node claiming authority for ITSELF looks reasonable and is useless: each node
// serves its own creates, so each becomes the holder of its own replica, every
// admission stays local, and delegation never happens. Worse, the claims then collide
// — one epoch, two holders — and the cluster is back to two deciders while believing
// it has one. That is not a hypothetical: the lab produced exactly it, with node-1 and
// node-2 each holding /qa at epoch 1.
//
// Choosing by hash of the project name over the SORTED host list makes concurrent
// claimants mint an IDENTICAL row instead of competing ones, so the race stops
// mattering: the rows converge because they agree. It also spreads different projects
// across different hosts rather than piling every project onto one.
//
// Membership is itself eventually consistent, so two nodes with different views of the
// host list can still choose differently. That window is far narrower than claiming for
// self (which collides every single time) and heals the same way — the losing claim's
// node sees FailedPrecondition and retries against the winner.
func DeriveProjectAuthorityHolder(project string, candidates []string) string {
	eligible := append([]string(nil), candidates...)
	sort.Strings(eligible)
	if len(eligible) == 0 {
		return ""
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(projectOrDefault(project)))
	return eligible[int(h.Sum32()%uint32(len(eligible)))]
}

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
	rows, err := c.Query(ctx,
		`SELECT project, authority_epoch, holder, transfer_kind, fence_proof_ref
		 FROM project_authority_epochs WHERE project = ? AND deleted_at IS NULL
		 ORDER BY authority_epoch DESC LIMIT 1`, project)
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
		return maxEpoch.Valid && maxEpoch.Int64 == expectedPrevEpoch, nil
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
