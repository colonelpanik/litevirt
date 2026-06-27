// Fleet scenario: multi-version (N-step) rolling-upgrade coexistence.
//
// The replication handshake now keys off each node's effective DB-APPLIED
// schema (what columns the DB actually has, equalized by the pre-stage pass),
// not the binary const. So during a v(N)→v(N+k) rolling window — DBs all
// pre-staged forward, binaries swapping one at a time — replication keeps
// flowing (gap 0) instead of the old `gap>1` refusal that forced one-binary-
// version-per-round rolls.
//
// The binary's CurrentSchemaVersion const can't vary within one test binary, so
// we model per-node DB-applied schema with the SetEffectiveDBSchemaForTest seam.
// We assert the asymmetric rule (refuse only when the sender's DB is strictly
// ahead) and that the runtime back-pressure net still catches a real gap.

package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestFleet_NStepRollingUpgrade(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	sender, receiver := c.Nodes[0], c.Nodes[1]
	client := c.PeerClient(sender, receiver)

	// One valid INSERT into an existing replicated table (service_endpoints),
	// keyed by a distinct service_name + seq per push so dedup doesn't interfere.
	push := func(seq int64, svc string, senderDBSchema int) error {
		entry := &pb.MutationEntry{
			Seq:    seq,
			Hlc:    sender.HLCClock().Now().String(),
			Origin: sender.Name,
			Stmts:  fmt.Sprintf(`[{"SQL":"INSERT INTO service_endpoints (service_name, ip, region, weight, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)","Params":[%q,"10.0.0.1","ny",1,"2026-05-11T00:00:00Z","2026-05-11T00:00:00Z"]}]`, svc),
		}
		_, err := client.PushMutations(ctx, &pb.ReplicateRequest{
			Sender:              sender.Name,
			SenderVersion:       "fleet-test",
			SenderSchemaVersion: int32(senderDBSchema),
			AfterSeq:            seq - 1,
			Entries:             []*pb.MutationEntry{entry},
		})
		return err
	}
	landed := func(svc string) bool {
		rows, _ := receiver.DB.Query(ctx,
			`SELECT COUNT(*) AS n FROM service_endpoints WHERE service_name = ?`, svc)
		return len(rows) > 0 && rows[0].Int("n") > 0
	}

	cur := corrosion.CurrentSchemaVersion

	// (A) Headline: both DBs pre-staged forward to N+3 (binaries may differ).
	// Old code compared sender(N+3) vs binary const(N) → gap 3 → REFUSE.
	// New code compares sender(N+3) vs receiver EFFECTIVE(N+3) → gap 0 → ACCEPT.
	receiver.DB.SetEffectiveDBSchemaForTest(cur + 3)
	if err := push(1, "nstep-equal", cur+3); err != nil {
		t.Fatalf("(A) equal forward schema must be accepted, got: %v", err)
	}
	if !landed("nstep-equal") {
		t.Error("(A) accepted push did not land")
	}

	// (B) Asymmetric refuse: receiver genuinely behind (not pre-staged). Sender
	// DB ahead → refuse with an actionable error (the protective case, now keyed
	// off a trustworthy DB-applied fact).
	receiver.DB.SetEffectiveDBSchemaForTest(cur)
	err := push(2, "nstep-ahead", cur+3)
	if err == nil {
		t.Fatal("(B) sender DB ahead of receiver must be refused")
	}
	if !strings.Contains(err.Error(), "missing migrations") {
		t.Errorf("(B) refusal should be actionable; got: %v", err)
	}
	if landed("nstep-ahead") {
		t.Error("(B) refused push must not land")
	}

	// (C) Sender behind: additive-only ⇒ the sender touches a subset of the
	// receiver's columns → accept.
	receiver.DB.SetEffectiveDBSchemaForTest(cur + 3)
	if err := push(3, "nstep-behind", cur); err != nil {
		t.Fatalf("(C) sender behind must be accepted, got: %v", err)
	}
	if !landed("nstep-behind") {
		t.Error("(C) accepted push did not land")
	}

	// (D) Back-pressure net intact: even when the handshake accepts (equal
	// effective), a genuinely-missing TABLE still aborts the batch and does NOT
	// advance mutation_seen — the final correctness guard, unchanged. (A and C
	// legitimately recorded seen rows, so assert the refused push adds none.)
	seenCount := func() int {
		rows, _ := receiver.DB.Query(ctx,
			`SELECT COUNT(*) AS n FROM mutation_seen WHERE origin = ?`, sender.Name)
		if len(rows) == 0 {
			return 0
		}
		return rows[0].Int("n")
	}
	before := seenCount()
	receiver.DB.SetEffectiveDBSchemaForTest(cur)
	if err := receiver.DB.Execute(ctx, "DROP TABLE service_endpoints"); err != nil {
		t.Fatalf("(D) drop table: %v", err)
	}
	err = push(4, "nstep-missing", cur)
	if err == nil || !strings.Contains(err.Error(), "schema-missing") {
		t.Fatalf("(D) missing table must back-pressure with schema-missing; got: %v", err)
	}
	if after := seenCount(); after != before {
		t.Errorf("(D) back-pressured mutation advanced mutation_seen: %d → %d", before, after)
	}
}
