package corrosion

import (
	"context"
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

	// Bounded, best-effort space reclaim (no-op without incremental auto_vacuum).
	_ = c.execLocal(ctx, "PRAGMA incremental_vacuum(?)", gcVacuumPages)
	return counts, nil
}
