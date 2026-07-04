package corrosion

import (
	"context"
	"fmt"
	"time"
)

// secResolution is the 19-char "YYYY-MM-DDTHH:MM:SS" prefix shared by both
// RFC3339 (created_at) and fixed-width RFC3339Nano (NowTS updated_at). Comparing
// substr(ts,1,19) avoids the 'Z'-vs-'.' lexical pitfall between the two formats
// and gives clean second-resolution age comparison — plenty for a GC cutoff.
const tsSecLayout = "2006-01-02T15:04:05"

// gcVacuumPages bounds the post-sweep incremental vacuum (mirrors the
// mutation_log prune). Best-effort: only returns pages to the OS when the DB was
// created with incremental auto_vacuum; otherwise it's a no-op and the win is
// just fewer logical rows + a smaller replicated/anti-entropy payload.
const gcVacuumPages = 2000

// GCSupersededRows hard-deletes auth + LB rows that can never validate or render
// again, reclaiming space that re-enroll / LB-recreate churn would otherwise grow
// without bound. It is LOCAL-only (each node runs the same deterministic sweep on
// its own copy via execLocalRows — NO mutation_log row): a replicated DELETE is
// union-unsafe, but a superseded row is inert so an independent local delete is
// safe, and the transient re-merge of one from a not-yet-swept peer is harmless.
//
// Predicates are graded by how strongly inert a row is:
//
//   - resurrection-proof (coreRetention): a recovery code whose set_id != the
//     user's active_set_id (under a live pointer), or an LB backend whose
//     generation doesn't match a live config (or whose config is tombstoned).
//     These are excluded by the v32 active-set gate / v31 generation join even if
//     a partitioned peer resurrects them, so deleting them can't revive auth/LB.
//   - cautious (orphanRetention, longer): a row whose owning pointer/config row is
//     entirely ABSENT. A delayed pointer/config could in principle arrive and make
//     it valid again, so this is treated as malformed/partial-state cleanup on a
//     longer retention, NOT the same resurrection-proof guarantee.
//
// CURRENT-active-set / current-generation rows are NEVER touched (a resurrected
// copy of one of those could validate/render). Returns per-table delete counts.
func GCSupersededRows(ctx context.Context, c *Client, coreRetention, orphanRetention time.Duration) (map[string]int, error) {
	now := time.Now().UTC()
	coreCutoff := now.Add(-coreRetention).Format(tsSecLayout)
	orphanCutoff := now.Add(-orphanRetention).Format(tsSecLayout)
	counts := map[string]int{}

	sweep := func(table, sql string, args ...interface{}) error {
		n, err := c.execLocalRows(ctx, sql, args...)
		if err != nil {
			return err
		}
		counts[table] += int(n)
		return nil
	}

	// recovery_codes — core: superseded set under a live active-set pointer.
	if err := sweep("recovery_codes",
		`DELETE FROM recovery_codes -- full-state-delete-ok: superseded set_id, inert (validity gated on the active-set pointer)
		 WHERE substr(COALESCE(NULLIF(updated_at, ''), created_at), 1, 19) < ?
		   AND EXISTS (SELECT 1 FROM recovery_code_sets s
		               WHERE s.username = recovery_codes.username AND s.deleted_at IS NULL)
		   AND set_id != (SELECT active_set_id FROM recovery_code_sets s
		                  WHERE s.username = recovery_codes.username AND s.deleted_at IS NULL)`,
		coreCutoff); err != nil {
		return counts, err
	}
	// recovery_codes — cautious: orphaned (no live pointer at all).
	if err := sweep("recovery_codes",
		`DELETE FROM recovery_codes -- full-state-delete-ok: orphaned (no live active-set pointer); malformed-state cleanup, longer retention
		 WHERE substr(COALESCE(NULLIF(updated_at, ''), created_at), 1, 19) < ?
		   AND NOT EXISTS (SELECT 1 FROM recovery_code_sets s
		                   WHERE s.username = recovery_codes.username AND s.deleted_at IS NULL)`,
		orphanCutoff); err != nil {
		return counts, err
	}

	// lb_backends — core: a config row exists but no LIVE config matches this
	// backend's generation (stale generation under a live config, OR a tombstoned
	// config — the render JOIN gates on cfg.deleted_at IS NULL + matching generation,
	// so both are inert). Current-generation-under-live-config rows are NOT matched.
	if err := sweep("lb_backends",
		`DELETE FROM lb_backends -- full-state-delete-ok: stale generation / tombstoned config, inert (render JOIN gates on live config + matching generation)
		 WHERE substr(updated_at, 1, 19) < ?
		   AND EXISTS (SELECT 1 FROM lb_configs c WHERE c.name = lb_backends.lb_name)
		   AND NOT EXISTS (SELECT 1 FROM lb_configs c
		                   WHERE c.name = lb_backends.lb_name
		                     AND c.deleted_at IS NULL
		                     AND c.generation = lb_backends.generation)`,
		coreCutoff); err != nil {
		return counts, err
	}
	// lb_backends — cautious: orphaned (no lb_configs row at all).
	if err := sweep("lb_backends",
		`DELETE FROM lb_backends -- full-state-delete-ok: orphaned (no lb_configs row); malformed-state cleanup, longer retention
		 WHERE substr(updated_at, 1, 19) < ?
		   AND NOT EXISTS (SELECT 1 FROM lb_configs c WHERE c.name = lb_backends.lb_name)`,
		orphanCutoff); err != nil {
		return counts, err
	}

	// NOTE: runtime_action_proofs must NEVER be added to THIS local-only sweep. Unlike the
	// inert rows above, a plain local delete of a proof is union-unsafe: a direct-RPC
	// executor re-seeds a carried proof via WriteActionProof (INSERT OR IGNORE) and then
	// claims it, and a lagging prepared/in_progress copy on a partitioned peer re-merges
	// after a local delete — either can revive a spent proof to prepared/in_progress and let
	// its action run again (a delete is not a lattice state). Proof-table GC is instead
	// handled by ReapSpentProofs (below): a REPLICATED monotone tombstone plus a
	// convergence-gated local reclaim of long-tombstoned rows. The daemon GC loop calls it
	// alongside this sweep.

	// Bounded, best-effort space reclaim (no-op without incremental auto_vacuum).
	// A PRAGMA argument can't be a bound parameter, so format it (gcVacuumPages is
	// a trusted int constant) — mirrors the mutation_log prune.
	_ = c.execLocal(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", gcVacuumPages))
	return counts, nil
}

// ReapSpentProofs bounds the runtime_action_proofs table once the split-brain gate is
// flipped (pre-flip the table is empty, so this is a no-op). A proof is NOT a plain inert
// row, so it CANNOT be reclaimed by GCSupersededRows' local-only delete: a direct-RPC
// carrier re-seeds a proof via INSERT OR IGNORE, and a lagging prepared/in_progress copy on
// a partitioned peer re-merges after a local delete — either could resurrect a spent proof
// to a non-terminal state and re-run its action. Reaping therefore runs in TWO phases with
// different guarantees:
//
//   Phase A — TOMBSTONE (replicated, monotone, ALWAYS safe): a terminal (completed/failed)
//     proof older than tombstoneAfter gets deleted_at set via a REPLICATED guarded UPDATE.
//     This is a lattice state, not a delete — it can't un-terminal a row, it no-ops on any
//     peer whose copy is still non-terminal (WHERE status IN terminal), and every proof
//     consume path already filters `deleted_at IS NULL`, so the tombstone renders the proof
//     inert cluster-wide. A tombstone keeps its terminal rank, so it still BEATS any lagging
//     non-terminal copy on merge — it actively protects against resurrection during
//     convergence rather than opening a gap.
//
//   Phase B — HARD DELETE (local-only, convergence-gated): a TOMBSTONED proof older than
//     reapAfter is hard-deleted locally (execLocalRows, no mutation_log row) ONLY when the
//     cluster is fully healthy — every current host is `active` (allHostsActive). A stale
//     non-terminal copy can only survive on a node that never converged the terminal state,
//     i.e. one that has been offline/partitioned; if every host is active (and thus
//     replicating) none holds such a copy, so no peer can re-merge a non-terminal proof into
//     the reaped gap. With reapAfter >= the WAL retention window (MaxLogRetention), any
//     mutation_log entry that could re-seed a stale copy is already pruned too. Each node
//     runs the same deterministic sweep on its own copy; a transient re-merge of the (inert)
//     tombstone from a not-yet-swept peer is harmless and re-reaped next cycle — the same
//     property GCSupersededRows relies on. If ANY host is not active, Phase B is SKIPPED
//     (fail safe): tombstones — tiny and inert — simply accumulate until the cluster is whole.
func ReapSpentProofs(ctx context.Context, c *Client, tombstoneAfter, reapAfter time.Duration) (tombstoned, reaped int, err error) {
	now := time.Now().UTC()
	tombstoneCutoff := now.Add(-tombstoneAfter).Format(tsSecLayout)
	reapCutoff := now.Add(-reapAfter).Format(tsSecLayout)

	// Phase A — replicated monotone tombstone of spent (terminal) proofs.
	ts := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET deleted_at = ?, updated_at = ?
		  WHERE deleted_at IS NULL
		    AND status IN ('completed','failed')
		    AND substr(updated_at, 1, 19) < ?`,
		ts, ts, tombstoneCutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("tombstone spent proofs: %w", err)
	}
	tombstoned = int(n)

	// Phase B — convergence-gated local reclaim of long-tombstoned proofs.
	healthy, herr := allHostsActive(ctx, c)
	if herr != nil {
		return tombstoned, 0, fmt.Errorf("proof reap membership check: %w", herr)
	}
	if !healthy {
		return tombstoned, 0, nil // a host may rejoin with a stale copy → don't reclaim yet
	}
	rn, rerr := c.execLocalRows(ctx,
		`DELETE FROM runtime_action_proofs -- full-state-delete-ok: convergence-gated reclaim of an ALREADY-tombstoned proof (every host active + past WAL retention); a re-merged tombstone is inert and re-reaped next cycle
		   WHERE deleted_at IS NOT NULL
		     AND status IN ('completed','failed')
		     AND substr(COALESCE(NULLIF(deleted_at, ''), updated_at), 1, 19) < ?`,
		reapCutoff)
	if rerr != nil {
		return tombstoned, 0, fmt.Errorf("reap tombstoned proofs: %w", rerr)
	}
	return tombstoned, int(rn), nil
}

// allHostsActive reports whether EVERY current cluster host is in the `active` state
// (ListHosts already excludes soft-deleted / departed hosts). It gates the proof reaper's
// hard-delete phase: a stale non-terminal proof copy can only survive on a node that never
// converged the terminal state — one that has been offline/partitioned — so if any host is
// not active we must not reclaim (it could rejoin and re-merge a non-terminal copy into the
// reaped gap). Fails safe: an empty membership or a query error reports NOT-all-active.
func allHostsActive(ctx context.Context, c *Client) (bool, error) {
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return false, err
	}
	if len(hosts) == 0 {
		return false, nil // unknown membership → don't reclaim
	}
	for _, h := range hosts {
		if h.State != "active" {
			return false, nil
		}
	}
	return true, nil
}
