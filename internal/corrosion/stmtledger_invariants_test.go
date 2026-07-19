package corrosion

import "testing"

// TestCurrentLedgerCategories (finding 6): a generated-ledger safety net independent of the
// derivation tests — every DispBulkUpdate entry is EXACTLY CatPerRowLWW (the only valid bulk
// category), and every non-bulk entry is CatNone. This catches a corrupted/hand-edited generated
// ledger even if derivation is correct. The bulk count is pinned so a silently dropped bulk entry
// (which would let that builder's shape back-pressure a peer) is caught; update it deliberately when
// a replicated bulk-update builder is added or removed.
func TestCurrentLedgerCategories(t *testing.T) {
	const wantBulk = 29
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
