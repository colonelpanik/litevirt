package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

// runtime_action_proofs accessors (split-brain hardening, Phase 1).
//
// A proof is the durable, single-use authorization a coordinator (holding the
// failover lease + local quorum) writes BEFORE a dangerous runtime-ownership
// action, so the executing host — which does not hold the lease — can validate
// it. The row carries a monotone action lifecycle:
//
//	prepared → in_progress → {completed | failed}
//
// enforced here by GUARDED updates (WHERE status IN legal-predecessors) so a
// state can only move forward and a terminal state never regresses. Starting a
// VM is itself a side effect, so it uses this lifecycle too (claim in_progress
// before libvirt.Start, detect already-running on retry, then complete).
//
// Replication (see sync.go, authoritative): the non-LWW monotone merge runs on both
// paths, but they differ — WAL relay is receiver-capability-gated (proof mutations are
// suppressed to a peer lacking split_brain_gate_v1), while anti-entropy carries the table
// UNCONDITIONALLY on the peer-mTLS sensitive lane (per-receiver exclusion isn't structural
// there; safe because the merging node always runs the v38 resolver and proof rows exist
// only once the gate is cluster-wide). It is NOT wholesale "excluded from replication".

// Proof lifecycle states.
const (
	ProofPrepared   = "prepared"
	ProofInProgress = "in_progress"
	ProofCompleted  = "completed"
	ProofFailed     = "failed"
)

// Proof action kinds.
const (
	ActionReschedule  = "reschedule"
	ActionPromote     = "promote"
	ActionRelocate    = "relocate"
	ActionLBApply     = "lb_apply"
	ActionOwnerAssert = "owner_assert"
)

// ErrProofSpent is returned when a proof can't be claimed because it is already
// terminal (completed/failed) or missing — distinct from a transient error so the
// caller refuses the action rather than retrying blindly.
var ErrProofSpent = errors.New("runtime action proof is terminal or missing")

// ActionProof is the authorization a coordinator mints before a gated action.
// Lifecycle/result columns are managed by the transition helpers, not set here.
type ActionProof struct {
	ID              string
	Action          string
	TargetKind      string
	TargetName      string
	DestHost        string
	Coordinator     string
	LeaseHolder     string
	LeaseExpiresAt  string
	QuorumLive      int
	QuorumNeeded    int
	OwnerEpoch      string
	FenceEpoch      string
	RelocationToken string
	// LeaseTerm is the fencing term of the lease incarnation that minted this
	// proof. It comes from the coordinator's own recorded term, never from a
	// fresh MAX(term) read — deriving it at stamp time would let a displaced
	// holder adopt the winner's term (the hole Phase 1 closed). 0 means the
	// proof was minted without one.
	LeaseTerm int64
	// LeaseKey names WHICH lease's ledger LeaseTerm belongs to. It is not
	// optional decoration: leader_lease_terms is shared by three subsystems
	// whose term numbers collide by design, so a term without its key cannot be
	// judged against anything. "" means the proof was minted without a lease,
	// and pairs with LeaseTerm 0.
	LeaseKey string
}

// ProofRecord is a read-back proof row including lifecycle state.
type ProofRecord struct {
	ActionProof
	Status       string
	StepState    string
	ResultCode   string
	ResultDetail string
	ExecutorHost string
}

// Terminal reports whether the proof has reached a terminal state.
func (p ProofRecord) Terminal() bool {
	return p.Status == ProofCompleted || p.Status == ProofFailed
}

// WriteVMRescheduleProof atomically writes a 'prepared' proof AND stamps the VM's
// pending transition (host_name, state='pending', pending_action_id) in ONE
// batch, so the proof is linked to that exact pending transition — never matched
// by a weak tuple. Used by the failover coordinator at the decide site.
func WriteVMRescheduleProof(ctx context.Context, c *Client, p ActionProof, vmName, destHost string) error {
	now := c.NowTS()
	// Guard: only mint the proof + stamp the pending link if the VM row still
	// exists (not deleted) AND no proof already carries this id — so we never
	// leave an orphan proof for a vanished VM or (astronomically) point a VM at a
	// pre-existing proof on an id collision. applied=false → ErrNoRowsAffected.
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var currentOwnerEpoch int64
		if err := tx.QueryRow(`SELECT vm_owner_epoch FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName).Scan(&currentOwnerEpoch); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		if p.OwnerEpoch != "" {
			expectedOwnerEpoch, err := strconv.ParseInt(p.OwnerEpoch, 10, 64)
			if err != nil {
				return false, err
			}
			if currentOwnerEpoch != expectedOwnerEpoch {
				return false, nil
			}
		}
		var existing int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM runtime_action_proofs WHERE id = ?`, p.ID).Scan(&existing); err != nil {
			return false, err
		}
		return existing == 0, nil
	}, []Statement{
		proofInsertStmt(c, p, now),
		{SQL: `UPDATE vms SET host_name = ?, state = 'pending', pending_action_id = ?, updated_at = ?
		        WHERE name = ? AND deleted_at IS NULL`,
			Params: []interface{}{destHost, p.ID, now, vmName}},
	})
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// WriteActionProof inserts a standalone 'prepared' proof (for direct-RPC actions
// that carry it in metadata rather than via a pending link). Idempotent by id.
//
// For a proof this node MINTED. For one an untrusted caller PRESENTED, use
// WriteActionProofValidated: this function relays whatever it is given.
func WriteActionProof(ctx context.Context, c *Client, p ActionProof) error {
	// Branched with LITERAL SQL on each arm rather than through
	// proofInsertStmt: stmtshapecheck resolves a replicated statement's shape
	// statically, and handing it `st.SQL` makes the builder dynamic and
	// unregisterable — correctly refused, since a shape it cannot see is a shape
	// that could back-pressure a peer.
	now := c.NowTS()
	if c.MayEmitTermCarryingProof() {
		return c.Execute(ctx, insertProofSQL, proofInsertParams(p, now)...)
	}
	return c.Execute(ctx, insertProofPreTermSQL, proofInsertParamsPreTerm(p, now)...)
}

// ErrProofDiverges means a row with this id already exists and disagrees with
// the presented proof on a field that AUTHORIZES the action. Distinct from
// ErrNoRowsAffected so a caller can refuse with FailedPrecondition rather than
// retrying.
var ErrProofDiverges = errors.New("a persisted proof with this id disagrees with the presented one")

// ProofBindingEqual compares the fields that AUTHORIZE an action.
//
// It is the ONE definition of that field set. claimCarriedProof compares the
// carried proto against the persisted row through it, and
// WriteActionProofValidated compares the presented proof against the persisted
// row through it, so the two can never drift — a field bound in one place and
// unchecked in the other is either forgeable or refuses valid actions. Three of
// this phase's findings were a field added to the row and silently left out of
// the hand-written comparison.
//
// The evidence-only fields are deliberately EXCLUDED. lease_holder,
// lease_expires_at, quorum_live and quorum_needed are an honesty record the
// coordinator persists and does not carry — leaseSnapshot returns "" on a read
// error by design, because an honesty record must not fabricate a holder — so
// binding them would refuse perfectly valid proofs.
func ProofBindingEqual(a, b ActionProof) bool {
	return a.Action == b.Action && a.TargetKind == b.TargetKind &&
		a.TargetName == b.TargetName && a.DestHost == b.DestHost &&
		a.Coordinator == b.Coordinator && a.RelocationToken == b.RelocationToken &&
		a.FenceEpoch == b.FenceEpoch && a.OwnerEpoch == b.OwnerEpoch &&
		a.LeaseTerm == b.LeaseTerm && a.LeaseKey == b.LeaseKey
}

// WriteActionProofValidated seeds a proof row from an UNTRUSTED presented proof,
// doing the seed and the divergence check in ONE guarded transaction.
//
// The ORDERING is the whole point. WriteActionProof followed by a separate
// GetActionProof comparison rejects correctly on the validating node, but by
// then the presented statement has already been committed to mutation_log —
// ExecuteBatchGuarded and Execute both write it inside the transaction and log
// the WHOLE batch, not only the statements that changed a row, so an INSERT OR
// IGNORE that is a local no-op still relays. A peer that has not yet received
// the coordinator's genuine row applies the forged one; the genuine row then
// arrives, collides on the primary key under INSERT OR IGNORE, and is silently
// dropped. The forged value becomes that peer's permanent record.
//
// Refusing therefore has to mean nothing was written AND nothing was logged,
// which is exactly what a false guard gives: ExecuteBatchGuarded rolls the
// transaction back before the mutation_log insert.
//
// Three outcomes, and the third is not an error:
//   - no row yet            → seed it, and replicate the seed
//   - a row that disagrees  → ErrProofDiverges, nothing written, nothing logged
//   - an identical row      → nothing to write, success
//
// A retried RPC and the coordinator's own replicated row both land in the third
// case. Conflating it with the second would refuse every retry.
//
// The lookup deliberately does NOT filter deleted_at IS NULL. A tombstone still
// occupies the primary key, and ReapSpentProofs tombstones every completed or
// failed proof and never hard-deletes — so every id ever spent would otherwise
// be a permanently open hole: the guard would see no row, return true, and
// relay the presented INSERT to every peer even though it no-ops locally on the
// PK. A peer that never received the genuine row would then apply the forged
// one at status 'prepared'. Facts must match a tombstoned row exactly as they
// must match a live one; whether a SPENT proof may be re-used is
// ClaimActionProof's question, and it has its own deleted_at filter.
func WriteActionProofValidated(ctx context.Context, c *Client, p ActionProof) error {
	now := c.NowTS()
	_, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var existing ActionProof
		err := tx.QueryRow(
			`SELECT action, target_kind, target_name, dest_host, coordinator,
			        relocation_token, fence_epoch, owner_epoch, lease_term, lease_key
			   FROM runtime_action_proofs WHERE id = ?`, p.ID).
			Scan(&existing.Action, &existing.TargetKind, &existing.TargetName,
				&existing.DestHost, &existing.Coordinator, &existing.RelocationToken,
				&existing.FenceEpoch, &existing.OwnerEpoch, &existing.LeaseTerm,
				&existing.LeaseKey)
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if !ProofBindingEqual(existing, p) {
			return false, ErrProofDiverges
		}
		return false, nil
	}, []Statement{
		proofInsertStmt(c, p, now),
	})
	return err
}

const insertProofSQL = `INSERT OR IGNORE INTO runtime_action_proofs
	(id, action, target_kind, target_name, dest_host, coordinator, lease_holder, lease_expires_at,
	 quorum_live, quorum_needed, owner_epoch, fence_epoch, relocation_token, lease_term, lease_key,
	 status, step_state, result_code, result_detail, started_at, completed_at, executor_host,
	 created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', '', '', '', '', '', '', ?, ?)`

// insertProofPreTermSQL is insertProofSQL without lease_term and lease_key: the
// shape the PREVIOUS RELEASE emits, and therefore the only proof insert every
// peer in a mixed-version fleet can resolve.
//
// It exists as a live emitter because widening insertProofSQL moved its
// fingerprint, and a fingerprint is a property of the BINARY. A peer on the
// previous release holds only this one, so it cannot resolve the widened form:
// its apply fails closed, the whole batch rolls back, and its replication
// watermark stalls, head-of-line blocking the stream into it. Nothing stopped
// that happening — a proof write is gated by split_brain_gate_v1, which such a
// peer DOES advertise, so peerLacksProofSupport is false and
// dropUnsupportedProofEntries never fires — and no CI guard could see it:
// runtime_action_proofs is in stmtshapecheck's replicatedTableBaseline, so the
// first-shape guard skips the table entirely. Proofs mint far more often than
// lease terms, so this was the wider exposure of the two.
//
// The retained receive-side entries in stmthistorical.go are the mirror of
// this and not a substitute: they let us ACCEPT what an old peer emits, and say
// nothing about what we emit at it.
//
// Dropping the two columns loses nothing pre-latch. Both take their DEFAULTs —
// 0 and ”, the "minted without a term" sentinels — and there is no term to
// carry anyway, because the mint is gated on the very same latch (see
// AcquireLeaseWithTerm, which reports term 0 until it forms).
const insertProofPreTermSQL = `INSERT OR IGNORE INTO runtime_action_proofs
	(id, action, target_kind, target_name, dest_host, coordinator, lease_holder, lease_expires_at,
	 quorum_live, quorum_needed, owner_epoch, fence_epoch, relocation_token,
	 status, step_state, result_code, result_detail, started_at, completed_at, executor_host,
	 created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', '', '', '', '', '', '', ?, ?)`

// proofInsertStmt picks the proof insert this node is allowed to emit.
//
// The wide form goes on the wire only once the term-carrying shapes are known
// to be decodable by every peer this node replicates to — the same
// lease_term_ledger_v1 latch that gates the mint, and for the same reason.
// Before then every proof is written in the released shape.
func proofInsertStmt(c *Client, p ActionProof, now string) Statement {
	if c.MayEmitTermCarryingProof() {
		return Statement{SQL: insertProofSQL, Params: proofInsertParams(p, now)}
	}
	return Statement{SQL: insertProofPreTermSQL, Params: proofInsertParamsPreTerm(p, now)}
}

// proofInsertParamsPreTerm is proofInsertParams minus the two term columns, in
// the order insertProofPreTermSQL binds them.
func proofInsertParamsPreTerm(p ActionProof, now string) []interface{} {
	return []interface{}{
		p.ID, p.Action, p.TargetKind, p.TargetName, p.DestHost, p.Coordinator,
		p.LeaseHolder, p.LeaseExpiresAt, p.QuorumLive, p.QuorumNeeded,
		p.OwnerEpoch, p.FenceEpoch, p.RelocationToken, now, now,
	}
}

func proofInsertParams(p ActionProof, now string) []interface{} {
	return []interface{}{
		p.ID, p.Action, p.TargetKind, p.TargetName, p.DestHost, p.Coordinator,
		p.LeaseHolder, p.LeaseExpiresAt, p.QuorumLive, p.QuorumNeeded,
		p.OwnerEpoch, p.FenceEpoch, p.RelocationToken, p.LeaseTerm, p.LeaseKey, now, now,
	}
}

// GetActionProof reads a proof by id. ok=false if absent.
func GetActionProof(ctx context.Context, c *Client, id string) (ProofRecord, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id, action, target_kind, target_name, dest_host, coordinator,
		        lease_holder, lease_expires_at, quorum_live, quorum_needed,
		        owner_epoch, fence_epoch, relocation_token, lease_term, lease_key,
		        status, step_state, result_code, result_detail, executor_host
		   FROM runtime_action_proofs WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return ProofRecord{}, false, err
	}
	if len(rows) == 0 {
		return ProofRecord{}, false, nil
	}
	r := rows[0]
	return ProofRecord{
		ActionProof: ActionProof{
			ID: r.String("id"), Action: r.String("action"), TargetKind: r.String("target_kind"),
			TargetName: r.String("target_name"), DestHost: r.String("dest_host"),
			Coordinator: r.String("coordinator"), LeaseHolder: r.String("lease_holder"),
			LeaseExpiresAt: r.String("lease_expires_at"), QuorumLive: r.Int("quorum_live"),
			QuorumNeeded: r.Int("quorum_needed"), OwnerEpoch: r.String("owner_epoch"),
			FenceEpoch: r.String("fence_epoch"), RelocationToken: r.String("relocation_token"),
			LeaseTerm: r.Int64("lease_term"), LeaseKey: r.String("lease_key"),
		},
		Status: r.String("status"), StepState: r.String("step_state"),
		ResultCode: r.String("result_code"), ResultDetail: r.String("result_detail"),
		ExecutorHost: r.String("executor_host"),
	}, true, nil
}

// AppendProofStep records a completed step in a proof's step_state (a space-
// separated, forward-only, idempotent set) so a crashed multi-step action (e.g.
// promote: disk_built → defined → started) resumes past steps already done
// instead of re-running them destructively. Adding a step never removes one.
func AppendProofStep(ctx context.Context, c *Client, id, step string) error {
	now := c.NowTS()
	// Guard on status: proof rows are immutable except FORWARD transitions, so never
	// mutate a terminal proof's step_state/updated_at (a late step-append must not touch
	// a completed/failed row).
	_, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET step_state = TRIM(COALESCE(step_state,'') || ' ' || ?), updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL
		    AND status NOT IN ('completed','failed')
		    AND instr(' ' || COALESCE(step_state,'') || ' ', ' ' || ? || ' ') = 0`,
		step, now, id, step)
	return err
}

// ProofStepDone reports whether step is present in a space-separated step_state.
func ProofStepDone(stepState, step string) bool {
	for _, s := range strings.Fields(stepState) {
		if s == step {
			return true
		}
	}
	return false
}

// GetActionProofByToken reads the proof bound to a relocation token (container
// relocation binds by token, not by a VM pending pointer). ok=false if absent.
//
// A relocation token is single-mint (randid.New() per relocation), so at most one live proof
// carries it — the LIMIT 1 is exact today. It is ORDER BY id'd so the pick is at least
// DETERMINISTIC if that ever failed to hold. TODO(schema): fold a partial UNIQUE index on
// relocation_token (non-empty tokens only) into the next schema migration to make the
// one-proof-per-token invariant structural rather than a mint-time convention.
func GetActionProofByToken(ctx context.Context, c *Client, token string) (ProofRecord, bool, error) {
	if token == "" {
		return ProofRecord{}, false, nil
	}
	rows, err := c.Query(ctx,
		`SELECT id FROM runtime_action_proofs WHERE relocation_token = ? AND deleted_at IS NULL ORDER BY id LIMIT 1`, token)
	if err != nil {
		return ProofRecord{}, false, err
	}
	if len(rows) == 0 {
		return ProofRecord{}, false, nil
	}
	return GetActionProof(ctx, c, rows[0].String("id"))
}

// ClaimActionProof transitions a proof to in_progress on `executor`, but only
// from a non-terminal state (prepared or in_progress — the latter makes a retry
// idempotent: the same executor re-claims and resumes). A terminal or missing
// proof returns ErrProofSpent so the caller refuses rather than re-running the
// side effect. Guarded so a completed/failed proof can never regress.
func ClaimActionProof(ctx context.Context, c *Client, id, executor string) error {
	return ClaimActionProofFenced(ctx, c, id, executor, nil)
}

// ErrTermClaimantConflict means this executor has already claimed a proof at
// this lease term, for this lease key, on behalf of a DIFFERENT coordinator. It
// is a FENCING refusal, not a lifecycle one: kept distinct from ErrProofSpent so
// the caller can report "you are a competing claimant" rather than "this proof
// is used up", which are different operator problems.
var ErrTermClaimantConflict = errors.New("lease term already claimed on this host by another coordinator")

// TermFence binds a claim to ONE claimant of one lease term, on this executor.
//
// It exists because the replicated ledger cannot carry this weight. During a
// partition neither claimant's leader_lease_terms row has propagated, so a
// holder lookup answers "not found" for both, and an executor reachable from
// both coordinators while they cannot see each other would act for both. The
// claim is the one place this host writes something durable about what it
// agreed to act on, so the claim is where the binding belongs.
type TermFence struct {
	// Key is the lease whose term this is. Part of the binding because term
	// numbers COLLIDE across keys by design — the three leases allocate
	// independently, and TestLeaseTermHolder_IsScopedToItsKey pins failover
	// term 4 and rebalancer term 4 coexisting. Fencing on the term alone would
	// refuse a legitimate rebalancer proof because an unrelated failover proof
	// at the same number had been claimed here, and report it as a split-brain
	// conflict that never happened.
	Key string
	// Term is the lease incarnation the proof was minted under.
	Term int64
	// Coordinator is the claimant this executor binds itself to for (Key, Term).
	Coordinator string
}

// ClaimActionProofFenced is ClaimActionProof plus, when fence is non-nil, a
// first-writer-wins binding of (this executor, fence.Key, fence.Term) →
// fence.Coordinator.
//
// The binding is a NOT EXISTS inside the claim's own UPDATE, deliberately, so it
// is decided in the same atomic statement that takes the claim. A read followed
// by a claim would let two proofs at one term from two coordinators both pass
// the read before either wrote — which is exactly the race the fence exists to
// stop, reintroduced one layer up. TestClaimActionProofFenced_ConcurrentClaimantsRace
// is the test that tells those two implementations apart; -race cannot, because
// there is no data race, only a lost update.
//
// A nil fence is today's unfenced claim, so the pre-latch path is byte-identical
// and there is only one copy of the claim guard.
func ClaimActionProofFenced(ctx context.Context, c *Client, id, executor string, fence *TermFence) error {
	now := c.NowTS()
	if fence == nil {
		n, err := c.ExecuteRows(ctx, claimProofSQL, executor, now, now, id, executor)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrProofSpent // terminal, missing, or held by another executor
		}
		return nil
	}
	n, err := c.ExecuteRows(ctx, claimProofFencedSQL,
		executor, now, now, id, executor,
		fence.Term, fence.Key, executor, fence.Coordinator, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	// Zero rows is ambiguous — spent, missing, held elsewhere, OR fenced — and
	// the two outcomes need different operator-facing reasons. Classify with a
	// follow-up read. The SAFETY decision was already made atomically above;
	// this read only chooses the error, so its raciness cannot admit an action.
	// Tombstones are included here for the same reason the UPDATE's subquery
	// includes them: the conflicting claim is evidence, not a consumable, and
	// spending it is what created the evidence. Filtering them here too would
	// report ErrProofSpent for a refusal that was actually a claimant conflict,
	// pointing the operator at retention instead of at a split.
	rows, rerr := c.Query(ctx,
		`SELECT coordinator FROM runtime_action_proofs
		  WHERE lease_term = ? AND lease_key = ? AND executor_host = ?
		    AND coordinator <> ? AND id <> ? LIMIT 1`,
		fence.Term, fence.Key, executor, fence.Coordinator, id)
	if rerr == nil && len(rows) > 0 {
		return ErrTermClaimantConflict
	}
	return ErrProofSpent
}

// The claim is single-holder: a fresh (prepared, executor_host=”) proof may be
// taken by anyone, but an in_progress proof may only be re-claimed by the SAME
// executor (idempotent resume). A different executor gets zero rows →
// ErrProofSpent, so a claim can't be stolen mid-flight.
const claimProofSQL = `UPDATE runtime_action_proofs
	    SET status = 'in_progress',
	        executor_host = ?,
	        started_at = CASE WHEN started_at = '' THEN ? ELSE started_at END,
	        updated_at = ?
	  WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')
	    AND (executor_host = '' OR executor_host = ?)`

// claimProofFencedSQL is claimProofSQL with the term binding as one more
// predicate, so the fence is decided by the same UPDATE that takes the claim.
//
// SCOPED BY (lease_term, lease_key), and the key half is not optional. The three
// leases allocate terms independently, so their numbers collide by design; an
// earlier draft of this predicate matched on the term alone and would have
// fenced a rebalancer proof at term 7 because a failover proof at term 7 had
// been claimed on the same executor — refusing a legitimate action and
// reporting a split-brain conflict that never happened.
//
// o.executor_host = ? keeps the binding LOCAL. Another executor's claim at this
// term says nothing about what this one may do; the guarantee is per-executor,
// and matching any host's claim would make one node's action fence the whole
// fleet.
//
// The subquery deliberately does NOT filter o.deleted_at. Everywhere else a
// tombstone means "inert", because everywhere else a proof is a CONSUMABLE and
// the tombstone is what stops it being consumed twice. Here the row is not a
// consumable but EVIDENCE — this executor already acted for that coordinator at
// that (key, term) — and spending the proof is precisely what creates the
// evidence, so excluding spent rows excluded almost all of it. ReapSpentProofs
// tombstones on AGE alone (default 24h) with no regard for whether the term is
// still current, so a leader holding its lease longer than the retention window
// — ordinary on a stable cluster — had its executors' bindings quietly erased
// underneath it, and a second coordinator at the same live term could then claim
// on a host that had already executed for the first. That is the two-claimants
// -one-tenure split this fence is the last line against.
//
// Keeping tombstoned rows cannot over-fence: terms are monotone per key, so a
// (key, term) pair never recurs once the lease moves on, and the evidence a
// tombstone carries never stops being true. It also costs nothing to retain,
// because ReapSpentProofs never hard-deletes.
const claimProofFencedSQL = `UPDATE runtime_action_proofs
	    SET status = 'in_progress',
	        executor_host = ?,
	        started_at = CASE WHEN started_at = '' THEN ? ELSE started_at END,
	        updated_at = ?
	  WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')
	    AND (executor_host = '' OR executor_host = ?)
	    AND NOT EXISTS (
	          SELECT 1 FROM runtime_action_proofs o
	           WHERE o.lease_term = ? AND o.lease_key = ? AND o.executor_host = ?
	             AND o.coordinator <> ? AND o.id <> ?)`

// CompleteVMStartProof marks a VM-start proof completed (terminal) AND clears the
// VM's pending_action_id in the SAME mutation that moves it to 'running', so a
// crash can't leave state and pointer inconsistent. Guarded: only advances from a
// non-terminal proof; a no-op (already terminal / vm gone) reports ErrNoRowsAffected.
func CompleteVMStartProof(ctx context.Context, c *Client, id, vmName, executor string) error {
	now := c.NowTS()
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		// BOTH preconditions must hold atomically, or neither update runs:
		//   (1) the proof is still non-terminal, AND
		//   (2) the VM still points at THIS proof (pending_action_id = id).
		// Otherwise a stale proof could be marked completed while the VM pointer had
		// already changed/cleared — a half-write the caller can't detect (a zero-row
		// UPDATE inside a passing guard is silently "ok").
		var status string
		err := tx.QueryRow(`SELECT status FROM runtime_action_proofs WHERE id = ? AND deleted_at IS NULL`, id).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if status != ProofPrepared && status != ProofInProgress {
			return false, nil
		}
		var n int
		if err := tx.QueryRow(
			`SELECT COUNT(1) FROM vms WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
			vmName, id).Scan(&n); err != nil {
			return false, err
		}
		return n == 1, nil
	}, []Statement{
		{SQL: `UPDATE runtime_action_proofs SET status = 'completed', executor_host = ?, completed_at = ?, updated_at = ?
		        WHERE id = ?`, Params: []interface{}{executor, now, now, id}},
		// Phase 4: completion mints the new ownership generation in the SAME
		// mutation that clears pending — the reschedule's read-old → prove →
		// move → mint-new ordering. The executor claimed the proof against the
		// old epoch; after this lands, a replay of that proof is stale by
		// construction.
		{SQL: `UPDATE vms SET state = 'running', pending_action_id = '',
		        vm_owner_epoch = vm_owner_epoch + 1, updated_at = ?
		        WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`, Params: []interface{}{now, vmName, id}},
	})
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// CompleteActionProof marks a standalone proof completed (terminal) on `executor`
// — the generic counterpart to CompleteVMStartProof for direct-RPC actions
// (promote/relocate) that manage their own workload state. Guarded so a terminal
// proof never regresses; a no-op (already terminal / missing) reports
// ErrNoRowsAffected.
func CompleteActionProof(ctx context.Context, c *Client, id, executor string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE runtime_action_proofs
		    SET status = 'completed', executor_host = ?, completed_at = ?, updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')`,
		executor, now, now, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// FailActionProof marks a proof failed (terminal, non-retryable) with a result,
// and clears any VM pending pointer. Use ONLY for a known non-retryable point or
// explicit abort — a transient error should leave the proof in_progress so a retry
// resumes. Guarded so terminal never regresses.
func FailActionProof(ctx context.Context, c *Client, id, vmName, code, detail string) error {
	now := c.NowTS()
	stmts := []Statement{
		{SQL: `UPDATE runtime_action_proofs SET status = 'failed', result_code = ?, result_detail = ?,
		        completed_at = ?, updated_at = ?
		        WHERE id = ? AND deleted_at IS NULL AND status IN ('prepared','in_progress')`,
			Params: []interface{}{code, detail, now, now, id}},
	}
	if vmName != "" {
		// Exit 'pending' AND clear the pointer together — clearing the pointer while
		// leaving state='pending' would create a MARKERLESS pending row, which
		// startPendingVM would (wrongly) treat as a legacy, ungated start. Move it to
		// 'error' so a failed proof-gated start is a dead end, not a legacy fallthrough.
		stmts = append(stmts, Statement{
			SQL: `UPDATE vms SET state = 'error', state_detail = ?, pending_action_id = '', updated_at = ?
			       WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
			Params: []interface{}{"failover proof failed: " + code, now, vmName, id},
		})
	}
	return c.ExecuteBatch(ctx, stmts)
}
