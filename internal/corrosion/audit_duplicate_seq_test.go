package corrosion

import (
	"context"
	"strings"
	"testing"
)

// TestAuditVerify_ARepeatedSeqIsADuplicateNotADeletion: two rows at one seq are
// a forked chain, and the finding says so instead of "rows deleted".
func TestAuditVerify_ARepeatedSeqIsADuplicateNotADeletion(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	ins(t, c, "orig-1", "node-0", "")
	ins(t, c, "orig-2", "node-0", "")
	orig := rowsByID(t, c, "orig-1", "orig-2")
	// A second chain under the same name, appended to an empty tail — what a
	// rebuilt host did before it held its rows.
	if err := c.Execute(ctx, `DELETE FROM audit_log WHERE host_name = 'node-0'`); err != nil {
		t.Fatal(err)
	}
	c.ResetAuditChainForTests()
	ins(t, c, "fork-1", "node-0", "")
	ins(t, c, "fork-2", "node-0", "")
	restoreRows(t, c, orig)

	res := verify(t, c)
	if len(res.SeqGaps) == 0 {
		t.Fatalf("no sequence finding for a forked chain: %+v", res)
	}
	for _, g := range res.SeqGaps {
		if !strings.Contains(g, "duplicate") || strings.Contains(g, " after ") {
			t.Errorf("finding %q does not call a repeated seq a duplicate", g)
		}
	}
}
