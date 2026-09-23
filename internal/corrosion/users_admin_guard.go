package corrosion

import (
	"context"
	"database/sql"
	"log/slog"
)

// The receiver-side half of the joining-node credential hazard (#186/#224).
//
// The sender-side guard — a node with join_peers configured declines to mint an
// admin credential — protects the cluster only for the code path and binary
// version it lives in. An operator whose workstation carries an older `lv`
// provisions a node whose daemon has no guard at all, and a node whose
// join_peers was reset (see `lv host init`) reaches the mint path with a current
// binary. Either way the minted row replicates, and the receiver had no opinion:
// applyLWWGated gates purely on updated_at, so a strictly-newer admin row was
// applied by BOTH lanes with no conflict raised, no unresolved marker and no
// metric. Nothing anywhere recorded that a cluster credential had been replaced.
//
// The invariant here is deliberately narrow, and it is keyed on created_at.
//
// users.created_at is written in exactly ONE place: the INSERT in InsertUser.
// No update path touches it — UpdateUserPassword sets password_hash/updated_at,
// InsertUser's reactivation branch sets role/password_hash/deleted_at/updated_at,
// and DeleteUser sets deleted_at/updated_at. So for a given username created_at
// is immutable in practice, and an incoming row that carries a DIFFERENT one is
// not a new password for the existing account — it is a different account minted
// somewhere else wearing that account's name. That is exactly the #186 event,
// and it is distinguishable from the legitimate operation (`lv user reset-admin`
// preserves created_at and keeps replicating normally).
//
// What this deliberately does NOT do:
//
//   - It does not refuse a second admin ACCOUNT. #224 proposed refusing any
//     incoming row that "creates an admin while a live admin exists", but that
//     would block `lv user create --role admin`, which is a legitimate operation
//     and is the remediation the last-admin delete guard tells operators to use.
//   - It does not refuse a promotion. Changing an existing account's role to
//     admin preserves created_at, so it is not a re-mint. (No `lv user`
//     subcommand does this today — `--role` only applies at create.)
//   - It does not use customMergeTables, which is what #224 proposed. That map
//     re-classifies every statement for its table to DispCustomMerge, and the
//     users shapes are recorded in the compatibility ledger as DispPlainInsert
//     and DispFullPKUpdate. Changing them is a wire-shape change for a
//     credential table — a mixed-version cluster would disagree about how to
//     apply users statements — so it needs a ReplicationGated capability token,
//     the way lease_term_ledger_v1 got one, rather than an edit to a map.
//     Refusing at the apply sites leaves every disposition untouched.
//
// The refusal is asymmetric during a rolling upgrade: an old node still takes
// the row, a new node keeps its own. That is the point — #224 asks for a
// guarantee that does not depend on the sender's binary version — but it does
// mean the two nodes hold different hashes until an operator acts, so the
// refusal is counted and logged rather than being silent like the overwrite was.

const adminRemintAdvice = "A peer offered a DIFFERENT admin account under an existing admin's " +
	"name (its created_at does not match). Run `lv user ls` on both nodes; if the credential was " +
	"replaced, `lv user reset-admin` on the node you trust re-establishes one both will accept"

// adminRemintRefused is the whole decision, as a pure function of four strings,
// so the rule can be tested without a replication lane around it.
//
// It refuses only when the LOCAL row is a live admin and the incoming row claims
// a different created_at. An unknown created_at on either side is not evidence
// of anything and falls through to ordinary LWW — a dump from a peer that does
// not project the column must not be turned into a cluster-wide refusal.
func adminRemintRefused(localRole, localDeletedAt, localCreatedAt, incomingCreatedAt string) bool {
	if localRole != "admin" {
		return false
	}
	if localDeletedAt != "" {
		// A tombstoned admin cannot log in, so there is no live credential to
		// protect and nothing to refuse.
		return false
	}
	if localCreatedAt == "" || incomingCreatedAt == "" {
		return false
	}
	return incomingCreatedAt != localCreatedAt
}

// usersAdminRemintIsRefused is the anti-entropy lane's adapter: it reads the
// local row for the incoming row's PK and applies adminRemintRefused. Its
// signature matches auditEvidenceGuard so it can only ever REFUSE.
func usersAdminRemintIsRefused(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (bool, string, error) {
	idx := columnIndexMap(table.Columns)
	if _, ok := idx["created_at"]; !ok {
		// A dump that does not carry created_at cannot be judged.
		return false, "", nil
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return false, "", err
	}
	if adminRemintRefused(
		cellStr(localRow, idx, "role"),
		cellStr(localRow, idx, "deleted_at"),
		cellStr(localRow, idx, "created_at"),
		cellStr(row, idx, "created_at"),
	) {
		return true, "admin_remint", nil
	}
	return false, "", nil
}

// credentialMergeGuards is the users-table floor under anti-entropy. It is kept
// separate from auditEvidenceGuards because the two answer different questions —
// that one protects immutable signed assertions, this one protects a live
// credential — and collapsing them would make one comment have to explain both.
var credentialMergeGuards = map[string]mergeFloor{
	"users": {usersAdminRemintIsRefused, adminRemintAdvice},
}

// usersInsertRemintsALiveAdmin is the WAL lane's adapter.
//
// Only INSERTs are inspected, and that is sufficient rather than partial: no
// UPDATE path writes created_at at all, so an UPDATE cannot violate the
// invariant this guard enforces.
func (r *Replicator) usersInsertRemintsALiveAdmin(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape) (bool, error) {
	if sh.Kind != KindInsert {
		return false, nil
	}
	incomingCreatedAt, ok := insertParamString(s, sh, "created_at")
	if !ok {
		return false, nil
	}
	username, ok := insertParamString(s, sh, "username")
	if !ok {
		return false, nil
	}

	var role, createdAt string
	var deletedAt sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT role, created_at, deleted_at FROM users WHERE username = ?`, username).
		Scan(&role, &createdAt, &deletedAt)
	if err == sql.ErrNoRows {
		return false, nil // first time we have seen this account
	}
	if err != nil {
		return false, err // unreadable is not "no live admin"
	}
	return adminRemintRefused(role, deletedAt.String, createdAt, incomingCreatedAt), nil
}

// insertParamString returns the bound parameter an INSERT binds to col. It
// reports false for a column the statement does not set, or one bound to a
// literal rather than a parameter.
func insertParamString(s Statement, sh StmtShape, col string) (string, bool) {
	for i, c := range sh.InsertCols {
		if c != col || i >= len(sh.InsertVals) {
			continue
		}
		v := sh.InsertVals[i]
		if !v.isParam() || v.ParamIndex < 0 || v.ParamIndex >= len(s.Params) {
			return "", false
		}
		str, ok := s.Params[v.ParamIndex].(string)
		return str, ok
	}
	return "", false
}

// noteAdminRemintRefused records the refusal on both lanes' shared counters. The
// overwrite it replaces was completely silent, so being visible IS the fix.
func (c *Client) noteAdminRemintRefused(path resolveTiePath) {
	c.observeMergeRejected("users", string(path), "admin_remint")
	slog.Warn("refused a replicated users row that re-mints a live admin account: "+
		"its created_at does not match the local row's, so it is a DIFFERENT account "+
		"under the same name, not a password change. "+adminRemintAdvice,
		"table", "users", "reason", "admin_remint", "path", string(path))
}
