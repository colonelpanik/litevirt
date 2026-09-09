package corrosion

import (
	"context"
	"fmt"
	"strings"
)

// ── THE PRERELEASE PERMANENT-LOSS TRUST SCHEMA IS AN UNSUPPORTED UPGRADE ────
//
// Three v51 tables briefly existed on this branch and never shipped in a
// release: netbox_recovery_manifests (an operator's account of a permanently
// lost host), netbox_host_retirements (the narrow grant that let that account
// stand in for machine evidence) and netbox_retirement_withdrawals (removing
// trust in one grant version). They were removed together with the RPC, CLI and
// premise resolvers that read them, so every premise in the NetBox proofs is
// machine-verified again, and the recovery lifecycle is deferred to the frozen
// contract in docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md.
//
// WHY A DATABASE THAT RAN THOSE COMMITS CANNOT SIMPLY BE MIGRATED. A binding row
// records `suspended`, `suspend_reason` and `validated_at` — it does NOT record
// which evidence its inventory proof rested on. So a binding that went live
// because a grant excused a permanently lost peer's digest looks, once the grant
// is gone, exactly like one proved end to end against every participant. The
// authority is unattributable, and every automatic answer is a guess:
//
//   - Leaving it alone grandfathers authority nothing can any longer review.
//   - Suspending everything and dropping the grant tables — which is what this
//     file used to do — erases the only surviving account of what the mechanism
//     was used for, while the binding it may have authorized is still there. It
//     was not even atomic: the suspending UPDATE committed on its own and the
//     DROPs followed in a separate batch, so a failure between them left a
//     database in neither state.
//
// REMOVING AUTHORITY MUST NOT ERASE KNOWLEDGE, and a build that cannot tell
// which bindings were affected has no business rewriting them. These builds
// never shipped, so the honest answer is the small one: REFUSE TO START, change
// nothing, and say exactly what was found. The evidence then survives intact for
// a deliberate offline recovery, which is where a decision that needs an
// operator's judgement belongs.
//
// TWO SHAPES ARE DETECTED, because there are two ways to be carrying this.
//
//  1. THE TABLES. A database that ran the prerelease commits has them, and they
//     are the whole record: the grant rows were append-only and nothing ever
//     deleted them, so their presence says the mechanism existed here.
//
//  2. THE ORPHANED CONDITION ROWS. A database that already ran the automatic
//     migration this file replaced has had its tables DROPPED — but that
//     migration never touched health_conditions, so the removed evaluator's rows
//     are still there with no lifecycle owner: nothing writes them, and nothing
//     will ever resolve them. A tables-only check would let exactly that
//     database start, and it is the one that has already been rewritten once.
//
// Neither signal is filtered on `deleted_at` or on lifecycle. A tombstoned grant
// is still a grant that was recorded, and a resolved advisory is still an
// advisory that stood — deleting or resolving a row was never a way to establish
// that the mechanism had not been used. Fail closed, and leak over collision:
// refusing a database that turns out to have been harmless costs an operator one
// deliberate procedure, and starting on one that was not costs a live guest's
// address.
//
// NOTHING HERE WRITES. Two catalogue lookups per signal and one COUNT per code,
// before any DDL, any ledger heal and any data fix — so the refusal is reached
// with the database in precisely the state the daemon found it in, and the
// message can say so without qualification.

// prereleaseTrustTables are the three removed tables, in the order they are
// reported.
var prereleaseTrustTables = []string{
	"netbox_host_retirements",
	"netbox_recovery_manifests",
	"netbox_retirement_withdrawals",
}

// prereleaseTrustConditionCodes are the health condition codes the removed
// attestation evaluator wrote. Nothing writes or resolves them now, so a row
// under one of these codes is a database that ran the removed mechanism.
//
// Matched on the CODE alone, not on (evaluator, code). The evaluator name is
// shared with findings that are still live, and narrowing the match would let a
// row written under any other evaluator name through — the wrong direction for a
// check whose whole job is to notice that this database has been here before.
var prereleaseTrustConditionCodes = []string{
	"netbox_premise_attested",
	"netbox_attestation_unvalidatable",
}

// prereleaseTrustFinding is what one scan found. Empty means a database with no
// prerelease trust artifacts at all, which is every ordinary database and must
// start exactly as it always has.
type prereleaseTrustFinding struct {
	// Tables are the prerelease trust tables present, in declared order.
	Tables []string
	// Conditions are the orphaned condition codes found, each with its row
	// count, in declared order.
	Conditions []string
}

func (f prereleaseTrustFinding) empty() bool {
	return len(f.Tables) == 0 && len(f.Conditions) == 0
}

// findPrereleaseTrustSchema looks for both shapes. It reads and never writes.
//
// A lookup that FAILS is reported as a failure, never as absence: concluding
// "not present" from an unreadable catalogue would start a daemon on exactly the
// database this boundary exists to stop.
func findPrereleaseTrustSchema(ctx context.Context, c *Client) (prereleaseTrustFinding, error) {
	var f prereleaseTrustFinding
	for _, t := range prereleaseTrustTables {
		ok, err := tableExists(ctx, c, t)
		if err != nil {
			return f, fmt.Errorf("look for the prerelease trust table %s: %w", t, err)
		}
		if ok {
			f.Tables = append(f.Tables, t)
		}
	}

	// The second shape. No health_conditions table means a database older than
	// the durable health model, which never had the removed evaluator either —
	// a real answer, not a swallowed failure.
	has, err := tableExists(ctx, c, "health_conditions")
	if err != nil {
		return f, fmt.Errorf("look for health_conditions: %w", err)
	}
	if !has {
		return f, nil
	}
	for _, code := range prereleaseTrustConditionCodes {
		var n int
		row := c.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM health_conditions WHERE code = ?`, code)
		if err := row.Scan(&n); err != nil {
			return f, fmt.Errorf("count the removed evaluator's %s conditions: %w", code, err)
		}
		if n > 0 {
			f.Conditions = append(f.Conditions, fmt.Sprintf("%s (%d row(s))", code, n))
		}
	}
	return f, nil
}

// refusal is the message an operator gets. It is the deliverable of this whole
// boundary: somebody looking at a daemon that will not start has to be able to
// tell a deliberate refusal from a fault, in one read, without the source.
//
// It says four things, in this order, because that is the order the questions
// arrive in: what was found, why this build cannot upgrade it, that nothing was
// modified, and what to do.
//
// WHAT IT DELIBERATELY DOES NOT SAY is that `lv netbox resume` fixes this. The
// approach this replaced advertised exactly that, and it was the unsafe part:
// resume re-proves a binding against the participants that answer NOW, so on a
// database whose accounting has been dropped it proves a smaller universe and
// succeeds — which is how a stopped-but-defined guest's address came to be
// reclaimed. Re-proving is the right operation once an operator has established
// what the lost machine held; it is not a substitute for establishing it.
func (f prereleaseTrustFinding) refusal() string {
	var found []string
	if len(f.Tables) > 0 {
		found = append(found, "prerelease trust tables: "+strings.Join(f.Tables, ", "))
	}
	if len(f.Conditions) > 0 {
		found = append(found, "health conditions from the removed attestation evaluator, "+
			"which nothing writes and nothing will resolve: "+strings.Join(f.Conditions, ", "))
	}

	var b strings.Builder
	b.WriteString("REFUSING TO START: this database carries the prerelease NetBox " +
		"permanent-loss trust schema, and this build cannot upgrade it.\n\n")

	b.WriteString("WHAT WAS FOUND — " + strings.Join(found, "; ") + ".\n\n")

	b.WriteString("WHY THIS BUILD CANNOT UPGRADE IT. The permanent-loss trust mechanism " +
		"(an operator's account of a destroyed machine, and a narrow grant letting it stand in " +
		"for machine evidence) existed only in prerelease builds of this feature and was " +
		"removed before any release, so no released version ever wrote these rows. A binding " +
		"does not record which evidence its inventory proof rested on, so one that went live on " +
		"a grant cannot be told apart from one proved against every participant — and this " +
		"build has no way to work out which bindings were affected. Rewriting them on a guess, " +
		"or dropping the only surviving account of what was granted, are both worse than " +
		"stopping. This is a deliberate boundary, not a fault.\n\n")

	b.WriteString("NOTHING HAS BEEN MODIFIED. No table was dropped, no binding was suspended, " +
		"no allocation or NetBox object was touched, and no row was written: this check runs " +
		"before any schema work, so the database is exactly as it was found and every piece of " +
		"evidence is intact.\n\n")

	b.WriteString("WHAT TO DO. Take a backup of the cluster database on every node before " +
		"anything else — it is the only remaining record of what was granted. Recovery is a " +
		"deliberate OFFLINE procedure against that evidence, decided by an operator who can " +
		"establish what the lost machine held; it is not something this build can do for you, " +
		"and there is no flag that skips this check. `lv netbox resume` is NOT sufficient and " +
		"must not be relied on here: it re-proves a binding against the participants that " +
		"answer now, which cannot establish what a removed grant once authorized. The recovery " +
		"lifecycle is specified in docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md, " +
		"and the boundary it sits behind is documented under permanent host loss in " +
		"docs/networking.md. Until that recovery path ships, a cluster in this state stays on " +
		"the prerelease build that wrote these rows, which is the only build that understands " +
		"them.")

	return b.String()
}

// refusePrereleaseTrustDatabase is the boundary: it refuses to let a database
// carrying the prerelease trust schema be migrated by this build.
//
// Called FIRST in InitSchema, before the DDL loop, so a refusal happens with the
// database untouched. A clean database pays one catalogue lookup per removed
// table plus one COUNT per removed code, and proceeds exactly as before.
func refusePrereleaseTrustDatabase(ctx context.Context, c *Client) error {
	f, err := findPrereleaseTrustSchema(ctx, c)
	if err != nil {
		return err
	}
	if f.empty() {
		return nil
	}
	return fmt.Errorf("%s", f.refusal())
}
