package corrosion

import (
	"context"
	"errors"
	"testing"
)

// Capability latches form on each node independently, so a coordinator whose
// lease_term_ledger_v1 latch has formed can hand a STAMPED proof to a receiver
// whose own latch is still closed. WriteActionProofValidated then chose the
// released (pre-term) insert shape, which silently dropped lease_term and
// lease_key: the row was seeded WITHOUT the authorization fields the caller
// presented, and — because the presented statement is what replicates — every
// peer's permanent record of that proof lost them too.
//
// The first claim succeeded on that row. Retrying the identical proof — the
// normal recovery of an interrupted action — then compared a stamped proof
// against an unstamped row, found them divergent, and refused with
// ErrProofDiverges, which callers map to a non-retryable FailedPrecondition.
//
// A receiver that cannot emit the stamped shape must not persist a stripped
// row: it refuses RETRYABLY, before anything is written or logged, and the
// coordinator retries once the receiver's latch forms.
func TestWriteActionProofValidated_AStampedProofIsNotPersistedWithoutItsStamp(t *testing.T) {
	ctx := context.Background()
	stamped := ActionProof{
		ID: "p1", Action: ActionPromote, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a",
		LeaseTerm: 5, LeaseKey: LeaseKeyFailover,
	}

	t.Run("latch closed refuses retryably and writes nothing", func(t *testing.T) {
		c := apTestClient(t)
		c.SetLeaseTermLedgerGate(func() bool { return false })

		err := WriteActionProofValidated(ctx, c, stamped)
		if err == nil {
			t.Fatal("a stamped proof was persisted by a receiver whose ledger latch is closed; " +
				"the only shape it may emit drops lease_term and lease_key, so the row " +
				"(and every peer's copy of it) lost the fields that authorize the action")
		}
		if errors.Is(err, ErrProofDiverges) {
			t.Fatalf("refused as DIVERGENT (%v); nothing is persisted yet, so there is nothing "+
				"to diverge from — callers map that to a non-retryable refusal", err)
		}
		if !errors.Is(err, ErrTermStampNotEmittable) {
			t.Fatalf("err = %v, want ErrTermStampNotEmittable so the caller can refuse "+
				"retryably", err)
		}
		if _, ok, gerr := GetActionProof(ctx, c, "p1"); gerr != nil || ok {
			t.Fatalf("a row exists after the refusal (ok=%v err=%v); refusing must mean "+
				"nothing was written", ok, gerr)
		}
		var logged int
		if err := c.db.QueryRow(`SELECT COUNT(1) FROM mutation_log`).Scan(&logged); err != nil {
			t.Fatalf("read mutation_log: %v", err)
		}
		if logged != 0 {
			t.Fatalf("%d mutation_log row(s) after the refusal; a refused proof must not relay", logged)
		}
	})

	t.Run("the retry succeeds once the latch forms, and the stamp survives", func(t *testing.T) {
		c := apTestClient(t)
		open := false
		c.SetLeaseTermLedgerGate(func() bool { return open })
		if err := WriteActionProofValidated(ctx, c, stamped); !errors.Is(err, ErrTermStampNotEmittable) {
			t.Fatalf("pre-latch write: err = %v, want ErrTermStampNotEmittable", err)
		}
		open = true
		if err := WriteActionProofValidated(ctx, c, stamped); err != nil {
			t.Fatalf("post-latch write: %v", err)
		}
		// The identical proof presented again — an interrupted action retrying —
		// is the third outcome, not a divergence.
		if err := WriteActionProofValidated(ctx, c, stamped); err != nil {
			t.Fatalf("retrying the identical proof: %v", err)
		}
		pr, ok, err := GetActionProof(ctx, c, "p1")
		if err != nil || !ok {
			t.Fatalf("GetActionProof: ok=%v err=%v", ok, err)
		}
		if pr.LeaseTerm != 5 || pr.LeaseKey != LeaseKeyFailover {
			t.Fatalf("persisted stamp = (%d, %q), want (5, %q)", pr.LeaseTerm, pr.LeaseKey, LeaseKeyFailover)
		}
	})

	t.Run("a coordinator row already replicated needs no emit, so the closed latch is no bar", func(t *testing.T) {
		c := apTestClient(t)
		// The coordinator's genuine row arrived over replication (a local apply,
		// not an emit). Nothing here puts a statement on the wire.
		if _, err := c.db.Exec(insertProofSQL, proofInsertParams(stamped, c.NowTS())...); err != nil {
			t.Fatalf("seed replicated row: %v", err)
		}
		c.SetLeaseTermLedgerGate(func() bool { return false })
		if err := WriteActionProofValidated(ctx, c, stamped); err != nil {
			t.Fatalf("identical row present, latch closed: %v — nothing has to be emitted, so "+
				"there is nothing the closed latch protects", err)
		}
	})

	t.Run("an unstamped proof is unaffected by the latch", func(t *testing.T) {
		c := apTestClient(t)
		c.SetLeaseTermLedgerGate(func() bool { return false })
		plain := stamped
		plain.LeaseTerm, plain.LeaseKey = 0, ""
		if err := WriteActionProofValidated(ctx, c, plain); err != nil {
			t.Fatalf("unstamped proof pre-latch: %v — the released shape carries it exactly", err)
		}
	})
}

// The minting side has the same hole in principle: a proof this node stamped
// must never leave in a shape that drops the stamp. The mint and the emit are
// gated on one predicate and the latch is monotone, so this cannot happen
// through AcquireLeaseWithTerm — but a caller handing WriteActionProof a
// stamped proof while the gate is closed used to get a silently stripped row.
func TestWriteActionProof_AStampedProofIsRefusedNotStripped(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	c.SetLeaseTermLedgerGate(func() bool { return false })
	err := WriteActionProof(ctx, c, ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "node-a",
		LeaseTerm: 7, LeaseKey: LeaseKeyFailover,
	})
	if !errors.Is(err, ErrTermStampNotEmittable) {
		t.Fatalf("err = %v, want ErrTermStampNotEmittable; a stamped proof written through the "+
			"released shape loses its stamp on every peer", err)
	}
	if _, ok, _ := GetActionProof(ctx, c, "p1"); ok {
		t.Fatal("a stripped row was written")
	}
}
