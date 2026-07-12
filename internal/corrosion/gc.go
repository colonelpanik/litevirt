package corrosion

import (
	"context"
	"fmt"
	"time"
)

// tsMsSQL returns a SQL expression that yields the wall-clock epoch-milliseconds of a
// timestamp column/expression in EITHER format: the HLC LWW-key form
// ("<13-digit-ms>-<logical>-<node>", detected by a 13-digit + '-' prefix via GLOB) uses
// its physical-ms prefix; otherwise the RFC3339 second-prefix is converted via julianday.
// Age/GC cutoffs must use this (compared against an epoch-ms bound) rather than a lexical
// `substr(ts,1,19) < cutoff`, which can't span the RFC3339 and HLC forms — post-hlc_lww
// an HLC "1752…" sorts below every RFC3339 cutoff and would make every row read as old.
func tsMsSQL(col string) string {
	return "(CASE WHEN (" + col + ") GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-*'" +
		" THEN CAST(substr((" + col + "),1,13) AS INTEGER)" +
		" ELSE CAST((julianday(substr((" + col + "),1,19))-2440587.5)*86400000 AS INTEGER) END)"
}

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
	coreCutoff := now.Add(-coreRetention).UnixMilli()
	orphanCutoff := now.Add(-orphanRetention).UnixMilli()
	counts := map[string]int{}

	sweep := func(table, sql string, args ...interface{}) error {
		n, err := c.execLocalRows(ctx, sql, args...)
		if err != nil {
			return err
		}
		counts[table] += int(n)
		return nil
	}

	rcAge := tsMsSQL("COALESCE(NULLIF(updated_at, ''), created_at)")
	// recovery_codes — core: superseded set under a live active-set pointer.
	if err := sweep("recovery_codes",
		`DELETE FROM recovery_codes -- full-state-delete-ok: superseded set_id, inert (validity gated on the active-set pointer)
		 WHERE `+rcAge+` < ?
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
		 WHERE `+rcAge+` < ?
		   AND NOT EXISTS (SELECT 1 FROM recovery_code_sets s
		                   WHERE s.username = recovery_codes.username AND s.deleted_at IS NULL)`,
		orphanCutoff); err != nil {
		return counts, err
	}

	// lb_backends — core: a config row exists but no LIVE config matches this
	// backend's generation (stale generation under a live config, OR a tombstoned
	// config — the render JOIN gates on cfg.deleted_at IS NULL + matching generation,
	// so both are inert). Current-generation-under-live-config rows are NOT matched.
	lbAge := tsMsSQL("updated_at")
	if err := sweep("lb_backends",
		`DELETE FROM lb_backends -- full-state-delete-ok: stale generation / tombstoned config, inert (render JOIN gates on live config + matching generation)
		 WHERE `+lbAge+` < ?
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
		 WHERE `+lbAge+` < ?
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

// ReapSpentProofs bounds the CONSUMABLE runtime_action_proofs set once the split-brain gate
// is flipped (pre-flip the table is empty, so this is a no-op). It REPLICATED-tombstones a
// terminal (completed/failed) proof older than tombstoneAfter — sets deleted_at via a guarded
// monotone UPDATE. This is a lattice state, NOT a delete: it can't un-terminal a row, it
// no-ops on any peer whose copy is still non-terminal (WHERE status IN terminal), and every
// proof consume path already filters `deleted_at IS NULL`, so the tombstone renders the proof
// inert cluster-wide while KEEPING its terminal rank — a tombstone still beats any lagging
// non-terminal copy on merge, so it can never resurrect a spent proof.
//
// It deliberately does NOT hard-delete (reclaim rows). A local hard delete of a proof is
// union-unsafe — a lagging prepared/in_progress copy on a partitioned peer, or a direct-RPC
// carrier's re-seed, can revive a spent proof AFTER the delete — and there is no CHEAP local
// signal that proves every enforcement-relevant member has observed the terminal/tombstone:
// the replicated hosts.state can read `active` for a peer this node hasn't actually reached
// since a partition, so it is NOT convergence evidence. Reclaiming tombstoned rows must wait
// on REAL local convergence evidence (per-peer replication watermarks past the tombstone's
// mutation_log seq) and is left as a separate follow-up; tombstones are tiny and inert until
// then, and the consumable set — all that gates a runtime action — is already bounded here.
func ReapSpentProofs(ctx context.Context, c *Client, tombstoneAfter time.Duration) (tombstoned int, err error) {
	tombstoneCutoff := time.Now().UTC().Add(-tombstoneAfter).UnixMilli()
	ts := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET deleted_at = ?, updated_at = ?
		  WHERE deleted_at IS NULL
		    AND status IN ('completed','failed')
		    AND `+tsMsSQL("updated_at")+` < ?`,
		ts, ts, tombstoneCutoff)
	if err != nil {
		return 0, fmt.Errorf("tombstone spent proofs: %w", err)
	}
	return int(n), nil
}
