package corrosion

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// ── THE PRERELEASE PERMANENT-LOSS TRUST TABLES, AND WHY THEY ARE HEALED ─────
//
// Three v51 tables briefly existed on this branch and never shipped in a
// release: netbox_recovery_manifests (an operator's account of a permanently
// lost host), netbox_host_retirements (the narrow grant that let that account
// stand in for machine evidence) and netbox_retirement_withdrawals (removing
// trust in one grant version). They were removed together with the RPC, CLI and
// premise resolvers that read them, so every premise in the NetBox proofs is
// machine-verified again and the recovery lifecycle is deferred to the frozen
// contract in docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md.
//
// THE HAZARD THAT MAKES THIS FILE NECESSARY. Dropping the tables is not enough.
// A binding row records `suspended`, `suspend_reason` and `validated_at` — it
// does NOT record which evidence its inventory proof rested on. So a binding
// that went live because a retirement excused a permanently lost peer's digest
// looks, once the grant is gone, exactly like one proved end to end against
// every participant. Left alone it would keep allocating on authority it never
// earned and that nothing can any longer review: a silent grandfather, which is
// the one outcome that is worse than either honest alternative.
//
// SO IT IS DETECTED AND SUSPENDED. The grant rows are append-only and were
// never deleted by anything, so their presence in a database is a reliable
// record that the mechanism was used here. Attribution to a PARTICULAR binding
// is not recoverable — the basis was never written down — so the fail-closed
// answer is the conservative one: if any grant or manifest row exists, every
// live binding is suspended and has to be re-proved. Re-proving is the ordinary
// path and needs no new machinery: `lv netbox resume` (and the re-key, and the
// revalidation pass) all run the full inventory corroboration before they lift
// a suspension, so a binding comes back only once every participant has
// actually answered.
//
// WHAT IS NOT TOUCHED. Claims (`ip_allocations`) and the NetBox objects behind
// them are left exactly as they are: a suspension refuses NEW allocation and
// says nothing about an address a guest already holds, and revoking live claims
// would turn a bookkeeping correction into an outage. A reclamation that already
// rested on a grant has already deleted a NetBox address and cannot be undone;
// that is stated in docs/networking.md rather than papered over here.
//
// LOCAL-ONLY, like every other schema-init repair: it must not emit replication
// mutations (schema work is per-host). Every node that carries these tables runs
// the same heal from its own database, so the cluster converges on suspension
// without a statement crossing the wire — and the fail-closed direction holds
// either way, since an unsuspended peer's row can only be lifted by a proof that
// now has no exception in it.
//
// IT IS IDEMPOTENT because it ends by dropping the tables: a second init finds
// nothing and does nothing. The warning it logs first names every grant it found,
// so the accounting is in the operator's log before the rows go, and the audit
// log's `netbox.retire-host` / `netbox.withdraw-retirement` entries keep the
// attribution permanently.

// prereleaseTrustTables are the three removed tables, in the order they are
// reported and dropped.
var prereleaseTrustTables = []string{
	"netbox_host_retirements",
	"netbox_recovery_manifests",
	"netbox_retirement_withdrawals",
}

// prereleaseTrustSuspendReason is the reason a healed binding carries.
//
// It names the boundary and the remedy, because an operator who finds a binding
// suspended by an upgrade has to be able to tell a known boundary from a fault —
// and the remedy is not a special command, it is the ordinary resume that
// re-proves.
const prereleaseTrustSuspendReason = "suspended by upgrade: this database recorded prerelease " +
	"permanent-loss trust grants, which have been removed, and a binding does not record " +
	"which evidence its inventory proof rested on — so this binding may have gone live on a " +
	"grant rather than on a complete proof. Nothing is wrong with the binding itself. Re-prove " +
	"it with `lv netbox resume <network>`, which requires every participant to answer for its " +
	"own address-bearing tables. Existing claims and NetBox objects are untouched."

// healPrereleaseTrustTables suspends every live binding in a database that
// recorded a prerelease permanent-loss trust grant, then drops the three removed
// tables. See the file comment for why both halves are necessary.
//
// A database that never ran those commits has no such tables and pays one
// sqlite_master lookup per table.
func healPrereleaseTrustTables(ctx context.Context, c *Client, now string) error {
	present := make([]string, 0, len(prereleaseTrustTables))
	for _, t := range prereleaseTrustTables {
		ok, err := tableExists(ctx, c, t)
		if err != nil {
			// Fail LOUD, never "assume it is not there": concluding absence from
			// an unreadable catalogue is exactly how a grandfathered binding
			// would slip through unnoticed.
			return fmt.Errorf("look for the prerelease trust table %s: %w", t, err)
		}
		if ok {
			present = append(present, t)
		}
	}
	if len(present) == 0 {
		return nil
	}

	// WHAT WAS GRANTED, read before anything is dropped. Reported even when it
	// turns out to be empty, because "the tables were here and held nothing" is
	// a different fact from "there were no tables" and only the first one can
	// end without a suspension.
	grants, err := readPrereleaseTrustGrants(ctx, c, present)
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		// The mechanism existed in this build but was never used, so no binding
		// can have been authorized by it. Drop the tables and leave the
		// bindings alone — suspending on the strength of an empty table would
		// be a needless outage, not caution.
		slog.Info("schema init: dropping the three prerelease permanent-loss trust tables; "+
			"they recorded nothing, so no binding rested on one",
			"tables", strings.Join(present, ","))
		return dropPrereleaseTrustTables(ctx, c, present)
	}

	// SAID OUT LOUD BEFORE THE ROWS GO. This is the only place the accounting
	// still exists; the audit log keeps who attested what and when.
	slog.Warn("schema init: this database recorded prerelease permanent-loss trust grants, "+
		"which have been REMOVED. Every live NetBox binding is being suspended because a "+
		"binding does not record whether its inventory proof rested on a grant, so it cannot "+
		"be told apart from one proved against every participant. Re-prove each with "+
		"`lv netbox resume <network>`. Claims and NetBox objects are untouched; a reclamation "+
		"that already rested on a grant cannot be undone",
		"grants", strings.Join(grants, "; "))

	// No bindings table means no bindings, which is a real answer rather than a
	// swallowed failure: nothing can have been authorized by anything.
	bound, err := tableExists(ctx, c, "netbox_bindings")
	if err != nil {
		return fmt.Errorf("look for netbox_bindings before suspending: %w", err)
	}
	if !bound {
		slog.Warn("schema init: no netbox_bindings table, so no binding can have rested on a " +
			"prerelease trust grant; dropping the grant tables")
		return dropPrereleaseTrustTables(ctx, c, present)
	}

	suspended, err := c.execLocalRows(ctx,
		`UPDATE netbox_bindings SET suspended = 1, suspend_reason = ?, updated_at = ?
		   WHERE suspended = 0 AND deleted_at IS NULL`,
		prereleaseTrustSuspendReason, now)
	if err != nil {
		// The drop does NOT happen: losing the evidence that the mechanism was
		// used, while a binding it may have authorized is still live, is the one
		// ordering this heal must never produce.
		return fmt.Errorf("suspend the bindings a prerelease trust grant may have authorized: %w", err)
	}
	slog.Warn("schema init: suspended NetBox bindings pending re-proof",
		"bindings", suspended)
	return dropPrereleaseTrustTables(ctx, c, present)
}

// readPrereleaseTrustGrants summarises what the tables hold, for the log line.
//
// Tombstoned rows are INCLUDED. A grant with a deleted_at is still a grant that
// was recorded and may have authorized a binding, and deleting a row was never a
// way to establish that it had not.
func readPrereleaseTrustGrants(ctx context.Context, c *Client, present []string) ([]string, error) {
	has := func(t string) bool {
		for _, p := range present {
			if p == t {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, t := range []string{"netbox_host_retirements", "netbox_recovery_manifests"} {
		if !has(t) {
			continue
		}
		rows, err := c.db.QueryContext(ctx,
			`SELECT host_name, premise, attested_by, attested_at FROM `+t)
		if err != nil {
			return nil, fmt.Errorf("read the prerelease trust table %s: %w", t, err)
		}
		func() {
			defer rows.Close()
			for rows.Next() {
				var host, premise, by, at string
				if err = rows.Scan(&host, &premise, &by, &at); err != nil {
					return
				}
				seen[fmt.Sprintf("%s premise=%s attested_by=%s attested_at=%s",
					host, premise, by, at)] = true
			}
			err = rows.Err()
		}()
		if err != nil {
			return nil, fmt.Errorf("read the prerelease trust table %s: %w", t, err)
		}
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

// dropPrereleaseTrustTables removes the tables in one local transaction.
func dropPrereleaseTrustTables(ctx context.Context, c *Client, present []string) error {
	stmts := make([]Statement, 0, len(present))
	for _, t := range present {
		stmts = append(stmts, Statement{SQL: `DROP TABLE IF EXISTS ` + t})
	}
	if err := c.execBatchLocal(ctx, stmts); err != nil {
		return fmt.Errorf("drop the prerelease trust tables: %w", err)
	}
	return nil
}
