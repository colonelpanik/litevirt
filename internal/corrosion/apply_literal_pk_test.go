package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// leaderElectionUpsert is the failover-coordinator lease writer: a full-image explicit upsert whose
// PK (key) is a canonical LITERAL 'failover', not a bound param, guarded by a lease WHERE clause.
const leaderElectionUpsert = `INSERT INTO leader_election (key, holder, expires_at, updated_at) ` +
	`VALUES ('failover', ?, ?, ?) ON CONFLICT(key) DO UPDATE SET holder = excluded.holder, ` +
	`expires_at = excluded.expires_at, updated_at = excluded.updated_at ` +
	`WHERE leader_election.expires_at < ? OR leader_election.holder = excluded.holder`

// TestLiteralPKResolvesForLWW (regression): a canonical-literal primary key resolves as a full-PK
// identity, so a literal-PK explicit upsert can be LWW-gated instead of failing "cannot resolve
// primary key for LWW". Ephemeral-cluster finding: the leader_election failover lease back-pressured.
func TestLiteralPKResolvesForLWW(t *testing.T) {
	sh, err := parseStmtShape(leaderElectionUpsert, []string{"key"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !sh.HasFullPKIdentity {
		t.Fatal("a literal PK must count as a full-PK identity (its value is exactly known)")
	}
	// The bound params are holder, expires_at, updated_at, where-expires (4).
	s := Statement{SQL: leaderElectionUpsert, Params: []interface{}{"node-a", "2999-01-01T00:00:00Z", "3000000000000-0000-n2", "3000000000000-0000-n2"}}
	pk, ok := pkValuesFromShape(sh, s)
	if !ok || len(pk) != 1 || coerceString(pk[0]) != "failover" {
		t.Fatalf("literal PK must resolve to ['failover'], got ok=%v %v", ok, pk)
	}
}

// TestApplyLeaderElectionLiteralPKUpsert (regression, WAL path): the leader_election lease upsert
// APPLIES instead of back-pressuring, and an older incoming lease write is LWW-skipped.
func TestApplyLeaderElectionLiteralPKUpsert(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	seq := int64(0)
	apply := func(holder, expires, updated string) error {
		seq++
		stmts := fmt.Sprintf(`[{"SQL":%q,"Params":[%q,%q,%q,%q]}]`, leaderElectionUpsert, holder, expires, updated, updated)
		_, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: seq, Hlc: updated, Origin: "peer", Stmts: stmts}})
		return err
	}
	holder := func() string {
		rows, _ := c.Query(ctx, "SELECT holder FROM leader_election WHERE key = 'failover'")
		if len(rows) == 0 {
			return ""
		}
		return rows[0].String("holder")
	}

	// APPLIES (the bug: this used to fail "cannot resolve primary key for LWW on leader_election").
	if err := apply("node-a", "2999-01-01T00:00:00Z", "3000000000000-0000-n2"); err != nil {
		t.Fatalf("leader_election literal-PK upsert must apply, not back-pressure: %v", err)
	}
	if holder() != "node-a" {
		t.Fatalf("lease must be recorded, holder=%q", holder())
	}

	// An OLDER incoming lease write is LWW-skipped (newer local lease survives) — no error.
	if err := apply("node-b", "2999-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("older lease apply must not error: %v", err)
	}
	if holder() != "node-a" {
		t.Fatalf("an older lease write must be LWW-skipped; got holder=%q", holder())
	}

	// A same-holder renewal (newer updated_at, WHERE holder = excluded.holder ⇒ fires) applies.
	if err := apply("node-a", "3000-01-01T00:00:00Z", "4000000000000-0000-n3"); err != nil {
		t.Fatalf("lease renewal must apply: %v", err)
	}
	rows, _ := c.Query(ctx, "SELECT expires_at FROM leader_election WHERE key = 'failover'")
	if len(rows) != 1 || rows[0].String("expires_at") != "3000-01-01T00:00:00Z" {
		t.Fatalf("renewal must advance expires_at, got %v", rows)
	}
}
