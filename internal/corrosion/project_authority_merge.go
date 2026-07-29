package corrosion

import (
	"database/sql"
	"log/slog"
)

// authorityMergeRow is the anti-entropy merge for project_authority_epochs.
//
// It exists because this table breaks the assumption the other immutable tables
// are built on. operations and operation_steps are keyed by a globally-unique
// minted id, so one primary key arriving with two different fact sets really is a
// fault, and freezing it (keep local, flag unresolved, never coin-flip) is right.
// An authority row is keyed by (project, authority_epoch) — a name plus a small
// integer — and ClaimInitialProjectAuthority is DESIGNED for several nodes to race
// it, returning applied=false to the losers. Concurrent minting of one PK is the
// normal path here, not a fault.
//
// Two consequences, both observed on the lab:
//
//   - Two nodes deriving the SAME holder still wrote rows that differed in
//     created_at, because that column is a per-node wall clock. The immutable merge
//     counts created_at as a fact, so it classified one logical claim written twice
//     as a conflict, kept both sides, and anti-entropy re-reported the drift every
//     cycle — permanently, on an idle cluster. Timestamp provenance is not a fact.
//
//   - Rows that genuinely disagreed on holder never healed either, and here keeping
//     local is not the conservative choice it is for a journal. Two nodes each
//     believing they hold a project's authority both admit against its quota, which
//     is exactly the double-decider split D1 exists to prevent. Non-convergence is
//     the dangerous state, so a real conflict is resolved rather than frozen — and
//     still reported, because it means a node's admissions were being decided
//     somewhere it did not expect.
//
// The resolution is a deterministic join: a total order over the row's canonical
// bytes, minimum wins. Every node computes it from row content alone, so the
// result is independent of who merged first and of any local clock — which is what
// makes repeated merges idempotent and the table finally quiet.
func (c *Client) authorityMergeRow(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int, updatedAtIdx int) (bool, error) {
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return false, err
	}
	delIdx := indexOf(table.Columns, "deleted_at")
	if keepLocal, decided := tombstoneDominates(localRow, row, delIdx); decided {
		return keepLocal, nil
	}

	// Byte-identical rows are the steady state once converged. Returning early
	// keeps the conflict warning below scoped to genuine divergence: a table that
	// has settled never logs again, so a warning always means something new.
	local, incoming := encodeRowCells(localRow), encodeRowCells(row)
	if local == incoming {
		return true, nil
	}

	if authorityClaimsConflict(table.Columns, localRow, row, updatedAtIdx, delIdx) {
		slog.Warn("project authority: conflicting claims for one epoch, converging deterministically",
			"table", table.Name, "pk", pkKeyAt(row, pkIdx),
			"local_holder", cellAt(localRow, indexOf(table.Columns, "holder")),
			"incoming_holder", cellAt(row, indexOf(table.Columns, "holder")))
	}

	keepLocal := local < incoming
	c.observeTieBreak(table.Name, "project_authority", tieBreakWinner(keepLocal))
	return keepLocal, nil
}

// authorityClaimsConflict separates the two ways two authority rows can differ.
//
// A genuine conflict is a disagreement about the AUTHORITY — holder,
// transfer_kind, fence_proof_ref — which means the cluster briefly had two
// deciders for one project. Everything else is provenance: updated_at and
// deleted_at are already mutable metadata on any immutable row, and created_at
// joins them HERE specifically because several nodes may legitimately mint this
// primary key at once, each stamping its own wall clock on an otherwise identical
// claim. Counting that as a conflict is what made an idle cluster report drift
// forever, so the distinction has to be exact rather than approximate.
func authorityClaimsConflict(cols []string, local, incoming []interface{}, updatedAtIdx, deletedAtIdx int) bool {
	return !rowFactsEqual(cols, local, incoming, updatedAtIdx, deletedAtIdx, indexOf(cols, "created_at"))
}

// tieBreakWinner names the side a deterministic merge chose, for the tie-break
// metric's winner label.
func tieBreakWinner(keepLocal bool) string {
	if keepLocal {
		return "local"
	}
	return "incoming"
}

// cellAt reads one cell as a string, tolerating an absent column so a log line can
// never panic on a peer's unexpected column set.
func cellAt(row []interface{}, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return coerceString(row[idx])
}
