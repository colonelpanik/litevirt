package corrosion

import "testing"

// TestCurrentLedgerCategories (finding 6): a generated-ledger safety net independent of the
// derivation tests — every DispBulkUpdate entry is EXACTLY CatPerRowLWW (the only valid bulk
// category), and every non-bulk entry is CatNone. This catches a corrupted/hand-edited generated
// ledger even if derivation is correct. The bulk count is pinned so a silently dropped bulk entry
// (which would let that builder's shape back-pressure a peer) is caught; update it deliberately when
// a replicated bulk-update builder is added or removed.
func TestCurrentLedgerCategories(t *testing.T) {
	const wantBulk = 30
	bulk := 0
	for fp, e := range stmtLedger {
		if e.Disposition == DispBulkUpdate {
			bulk++
			if e.Category != CatPerRowLWW {
				t.Errorf("bulk entry %s has category %q, want CatPerRowLWW", fp, e.Category)
			}
			continue
		}
		if e.Category != CatNone {
			t.Errorf("non-bulk entry %s (disposition %s) has category %q, want CatNone", fp, e.Disposition, e.Category)
		}
	}
	if bulk != wantBulk {
		t.Errorf("current ledger has %d DispBulkUpdate entries, want %d — a dropped bulk entry would back-pressure that builder's peer stream; update wantBulk only when deliberately adding/removing a replicated bulk-update builder", bulk, wantBulk)
	}
}

// TestNoUnsupportedCategoryInLedgers (finding 2): CatUnsupported must NEVER appear in a shipped
// ledger — deriveDisposition errors for an unsafe bulk update, so generation fails rather than
// emitting one. (The runtime keeps CatUnsupported only to reject it as defense against corrupt or
// historical data.)
func TestNoUnsupportedCategoryInLedgers(t *testing.T) {
	for name, m := range map[string]map[string]LedgerEntry{"current": stmtLedger, "historical": historicalLedger} {
		for fp, e := range m {
			if e.Category == CatUnsupported {
				t.Errorf("%s ledger entry %s uses CatUnsupported — an unsafe bulk update must fail generation, not ship", name, fp)
			}
		}
	}
}

// TestDeriveRejectsIdentityReferenceColumn (review 3): a builder that binds/assigns a self-reference
// column on an identity table (snapshots.parent_id) must FAIL ledger derivation, so the guard rejects
// it source-wide (generation errors; the shape can't be registered) — a new snapshot-chain writer
// cannot silently invalidate H1's fail-closed reference handling. A normal identity-table write still
// derives cleanly. Complements the integration test TestSnapshotWritersNeverBindParentID.
func TestDeriveRejectsIdentityReferenceColumn(t *testing.T) {
	bad := []string{
		`INSERT INTO snapshots (id, vm_name, host_name, name, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		`UPDATE snapshots SET parent_id = ?, updated_at = ? WHERE vm_name = ? AND name = ?`,
	}
	for _, sql := range bad {
		if _, err := LedgerEntryFor(sql); err == nil {
			t.Errorf("a builder binding snapshots.parent_id must fail derivation: %q", sql)
		}
	}
	ok := `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := LedgerEntryFor(ok); err != nil {
		t.Errorf("a normal snapshot INSERT (no parent_id) must derive cleanly: %v", err)
	}
}

// TestShapeInvariantBeatsExplicitPolicy (review 3): a non-overridable shape invariant is checked
// BEFORE the explicit-policy lookup, so even an explicit policy that would authorize a
// snapshots.parent_id writer cannot bypass it.
func TestShapeInvariantBeatsExplicitPolicy(t *testing.T) {
	const sql = `INSERT INTO snapshots (id, vm_name, host_name, name, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	sh, _, err := parseResolved(sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fp := stmtFingerprint(sh)
	// Inject an explicit policy that WOULD authorize this shape, then confirm the invariant still wins.
	explicitPolicyByFP[fp] = LedgerEntry{Disposition: DispPlainInsert}
	defer delete(explicitPolicyByFP, fp)
	if _, ok := explicitPolicy(fp); !ok {
		t.Fatal("precondition: the explicit policy must be registered for this test")
	}
	if _, err := LedgerEntryFor(sql); err == nil {
		t.Fatal("an explicit policy must NOT authorize a snapshots.parent_id writer (invariant checked first)")
	}
}

// TestDeriveRejectsUnsafeBulkUpdate (finding 2): ledger generation must FAIL for a bulk update with
// no LWW-compatible updated_at (rather than emit a CatUnsupported entry). vm_disks' PK is
// (vm_name, disk_name), so a WHERE on vm_name alone is a non-full-PK bulk update; without a bound
// updated_at it cannot be per-row LWW-gated.
func TestDeriveRejectsUnsafeBulkUpdate(t *testing.T) {
	const sql = `UPDATE vm_disks SET host_name = ? WHERE vm_name = ?`
	if _, err := LedgerEntryFor(sql); err == nil {
		t.Fatal("a bulk update with no bound updated_at must fail ledger derivation, not emit CatUnsupported")
	}
}
