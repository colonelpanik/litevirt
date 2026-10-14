package corrosion

import (
	"context"
	"strings"
	"testing"
)

// Pre-v45 history under a signing contract.
//
// The v45 migration added audit_log.seq with DEFAULT 0, so every row a cluster
// wrote before it carries seq 0. A legacy host adopts at startSeq 0 (its tail
// has no numbering yet), and the verifier treated `seq == 0` as "after the
// contract start" — so the day an upgraded cluster turned signing on, which is
// the default, `lv audit verify` reported its entire history as tampering.

// writeLegacyRows inserts pre-v45 rows for host the way an upgraded database
// holds them: hashed, chained per host, unsigned, seq 0. It returns the hash of
// the last one.
func writeLegacyRows(t *testing.T, c *Client, host string, ids ...string) string {
	t.Helper()
	ctx := context.Background()
	prev := ""
	for i, id := range ids {
		rec := AuditRecord{
			ID: id, Timestamp: "2026-07-29T10:00:0" + string(rune('1'+i)) + "Z", Username: "u",
			HostName: host, Action: "vm.start", Target: "x", Result: "ok", PrevHash: prev,
		}
		rec.ContentHash = HashAuditRow(rec)
		if err := c.Execute(ctx,
			`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
			                        result, prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '', '', 0)`,
			rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
			rec.Result, rec.PrevHash, rec.ContentHash); err != nil {
			t.Fatalf("insert legacy row %s: %v", id, err)
		}
		prev = rec.ContentHash
	}
	return prev
}

// adoptSigning turns signing on over whatever c already holds, as a daemon
// does on its first start after the upgrade.
func adoptSigning(t *testing.T, c *Client, host string) {
	t.Helper()
	kr, err := LoadAuditKeyring(testPKI(t, host), host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if _, err := AdoptAuditKey(context.Background(), c, kr, host); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
}

func TestEnforcement_PreV45HistoryUnderAContractIsNotTampering(t *testing.T) {
	c := newAuditTestClient(t)
	writeLegacyRows(t, c, "node-0", "r1", "r2", "r3", "r4")
	adoptSigning(t, c, "node-0")
	ins(t, c, "r5", "node-0", "2026-07-29T10:00:05Z") // signed, seq 1

	res := verify(t, c)
	if len(res.UnsignedAfterSigned) > 0 {
		t.Fatalf("pre-v45 rows were reported as written after signing began: %v\n"+
			"seq 0 is the column default every pre-upgrade row carries, not a position "+
			"after the contract start", res.UnsignedAfterSigned)
	}
	if res.Tampered() {
		t.Fatalf("an untouched upgraded log reports tampering once signing is on: %+v", res)
	}
	if res.Unsigned != 4 {
		t.Errorf("want the 4 legacy rows still COUNTED as unsigned, got %d", res.Unsigned)
	}
}

// The window between adoption and the host's first post-upgrade row. Nothing
// writes an audit row at startup, so on an idle host this lasts until the first
// operator action — and the verdict there must not be "tampered" either.
func TestEnforcement_PreV45HistoryWithNoRowSinceAdoptionIsNotTampering(t *testing.T) {
	c := newAuditTestClient(t)
	writeLegacyRows(t, c, "node-0", "r1", "r2", "r3")
	adoptSigning(t, c, "node-0")

	if res := verify(t, c); res.Tampered() || len(res.UnsignedAfterSigned) > 0 {
		t.Fatalf("an upgraded host that has written nothing since adopting reports its "+
			"history as tampering: %+v", res)
	}
}

// The forgery the seq-0 excuse must not admit: a fabricated row carrying seq 0,
// chained correctly onto the legacy tail and timestamped after it, so it sorts
// at the end of the legacy region. Its own hash verifies. What gives it away is
// the host's first post-upgrade row, whose stored hash commits to the REAL
// legacy tail and so no longer links.
func TestEnforcement_ASeqZeroRowSplicedOntoTheLegacyTailIsFlagged(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	tail := writeLegacyRows(t, c, "node-0", "r1", "r2", "r3", "r4")
	adoptSigning(t, c, "node-0")
	ins(t, c, "r5", "node-0", "2026-07-29T10:00:05Z")

	rec := AuditRecord{
		ID: "forged", Timestamp: "2026-07-29T10:00:09Z", Username: "root", HostName: "node-0",
		Action: "user.grant", Target: "mallory:admin", Result: "success", PrevHash: tail,
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
		                        result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '', '', 0)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target,
		rec.Result, rec.PrevHash, HashAuditRow(rec)); err != nil {
		t.Fatalf("insert the forged row: %v", err)
	}

	res := verify(t, c)
	if !res.Tampered() {
		t.Fatalf("a seq-0 row spliced onto the legacy tail verified clean: %+v", res)
	}
	if !strings.Contains(strings.Join(res.UnsignedAfterSigned, " "), "forged") {
		t.Fatalf("the spliced seq-0 row was excused as legacy history: %v\n"+
			"seq 0 must be placed by chain linkage, and this row breaks the link the "+
			"first post-upgrade row commits to", res.UnsignedAfterSigned)
	}
}
