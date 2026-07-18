package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestRegistryCredentialID_Frozen pins the deterministic id derivation (a change here is a
// contract break — it would strand every existing credential from its canonical row).
func TestRegistryCredentialID_Frozen(t *testing.T) {
	cases := map[string][3]string{
		"3ccd6170-44ce-80c6-9963-991ad2891923": {"user", "alice", "ghcr.io"},
		"82f03ff9-767b-82f1-9552-d92e643b6c57": {"global", "", "docker.io"},
	}
	for want, in := range cases {
		if got := RegistryCredentialID(in[0], in[1], in[2]); got != want {
			t.Errorf("RegistryCredentialID%v = %q, want %q (frozen)", in, got, want)
		}
	}
	// Deterministic: same inputs → same id.
	if RegistryCredentialID("user", "bob", "reg:5000") != RegistryCredentialID("user", "bob", "reg:5000") {
		t.Error("id must be deterministic")
	}
	// v8 (custom) UUID shape: version nibble 8, RFC-4122 variant.
	id := RegistryCredentialID("user", "alice", "ghcr.io")
	if id[14] != '8' {
		t.Errorf("expected a version-8 UUID, got %q", id)
	}
	if v := id[19]; v != '8' && v != '9' && v != 'a' && v != 'b' {
		t.Errorf("expected RFC-4122 variant, got %q", id)
	}
}

// TestRegistryCredentialID_LengthPrefixed: field boundaries are unambiguous — ("ab","c") and
// ("a","bc") must NOT collide (a naive concatenation would).
func TestRegistryCredentialID_LengthPrefixed(t *testing.T) {
	if RegistryCredentialID("user", "ab", "c") == RegistryCredentialID("user", "a", "bc") {
		t.Error("length-prefixing must keep distinct triples distinct")
	}
}

// TestRegistryCredentialID_NoLowercasing: the id hashes the STORED registry verbatim. Since
// NormalizeRegistry preserves case (it only folds the Docker Hub aliases), the id must NOT
// re-case — else a credential stored as "GHCR.io" would split from its own pulls.
func TestRegistryCredentialID_NoLowercasing(t *testing.T) {
	if RegistryCredentialID("user", "alice", "GHCR.io") == RegistryCredentialID("user", "alice", "ghcr.io") {
		t.Error("id must not lowercase the registry (normalization is frozen upstream)")
	}
}

func liveRegistryRows(t *testing.T, c *Client, scope, owner, registry string) []Row {
	t.Helper()
	rows, err := c.Query(context.Background(),
		"SELECT id, username, secret FROM registry_credentials WHERE scope=? AND owner=? AND registry=? AND deleted_at IS NULL",
		scope, owner, registry)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return rows
}

// TestUpsertRegistryCredentialCanonical_CreateRotateRevive: create, rotate, revoke, and revive all
// funnel through the SAME deterministic-id row — one physical row throughout.
func TestUpsertRegistryCredentialCanonical_CreateRotateRevive(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	rc := RegistryCredential{Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s1"}
	wantID := RegistryCredentialID("user", "alice", "ghcr.io")

	if err := UpsertRegistryCredentialCanonical(ctx, c, rc); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows := liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(rows) != 1 || rows[0].String("id") != wantID || rows[0].String("secret") != "s1" {
		t.Fatalf("create: want one row id=%s secret=s1, got %v", wantID, rows)
	}

	// Rotate: new secret, SAME row.
	rc.Secret = "s2"
	if err := UpsertRegistryCredentialCanonical(ctx, c, rc); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rows = liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(rows) != 1 || rows[0].String("id") != wantID || rows[0].String("secret") != "s2" {
		t.Fatalf("rotate: want one row id=%s secret=s2, got %v", wantID, rows)
	}

	// Revoke by triple (id-agnostic), then revive via the canonical upsert → same id, no live row lost.
	if _, err := DeleteRegistryCredential(ctx, c, "user", "alice", "ghcr.io"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rows := liveRegistryRows(t, c, "user", "alice", "ghcr.io"); len(rows) != 0 {
		t.Fatalf("revoke: expected no live row, got %v", rows)
	}
	rc.Secret = "s3"
	if err := UpsertRegistryCredentialCanonical(ctx, c, rc); err != nil {
		t.Fatalf("revive: %v", err)
	}
	rows = liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(rows) != 1 || rows[0].String("id") != wantID || rows[0].String("secret") != "s3" {
		t.Fatalf("revive: want one row id=%s secret=s3, got %v", wantID, rows)
	}
	// And exactly ONE physical row total (deterministic id, revived in place — never a second row).
	all, _ := c.Query(ctx, "SELECT id FROM registry_credentials WHERE scope=? AND owner=? AND registry=?", "user", "alice", "ghcr.io")
	if len(all) != 1 {
		t.Fatalf("expected a single physical row across the lifecycle, got %d", len(all))
	}
}

// TestUpsertRegistryCredentialAuto_Gating: with the gate off the legacy mint-new-id writer runs
// (two logins leave a tombstone + a live row, distinct random ids); with the gate on the canonical
// writer keeps a single deterministic-id row.
func TestUpsertRegistryCredentialAuto_Gating(t *testing.T) {
	ctx := context.Background()
	rc := RegistryCredential{Scope: "user", Owner: "bob", Registry: "reg:5000", Username: "bob", Secret: "p"}

	// Gate OFF ⇒ legacy: each login mints a fresh id; the prior live row is tombstoned.
	off := mustTestClient(t)
	rc.ID = "rand-1"
	if err := UpsertRegistryCredentialAuto(ctx, off, rc); err != nil {
		t.Fatalf("legacy 1: %v", err)
	}
	rc.ID = "rand-2"
	if err := UpsertRegistryCredentialAuto(ctx, off, rc); err != nil {
		t.Fatalf("legacy 2: %v", err)
	}
	all, _ := off.Query(ctx, "SELECT id FROM registry_credentials WHERE owner='bob'")
	if len(all) != 2 {
		t.Fatalf("legacy: expected 2 physical rows (live + tombstone), got %d", len(all))
	}

	// Gate ON ⇒ canonical: one deterministic-id row regardless of how many logins.
	on := mustTestClient(t)
	on.SetCanonicalRegistry(func() bool { return true })
	rc.ID = "ignored"
	if err := UpsertRegistryCredentialAuto(ctx, on, rc); err != nil {
		t.Fatalf("canonical 1: %v", err)
	}
	if err := UpsertRegistryCredentialAuto(ctx, on, rc); err != nil {
		t.Fatalf("canonical 2: %v", err)
	}
	all, _ = on.Query(ctx, "SELECT id FROM registry_credentials WHERE owner='bob'")
	if len(all) != 1 || all[0].String("id") != RegistryCredentialID("user", "bob", "reg:5000") {
		t.Fatalf("canonical: expected a single deterministic-id row, got %v", all)
	}
}

// TestRegistryCredentialCanonical_ConcurrentConverges is the core H2 win: two nodes creating the
// SAME credential produce the SAME deterministic id, so the replicated write resolves by normal
// LWW on that PK — one row, newer wins — instead of two random ids colliding on the partial
// UNIQUE and back-pressuring (the legacy failure this replaces).
func TestRegistryCredentialCanonical_ConcurrentConverges(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })

	// This node's own login (older).
	rc := RegistryCredential{Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "local"}
	if err := UpsertRegistryCredentialCanonical(ctx, c, rc); err != nil {
		t.Fatalf("local login: %v", err)
	}
	id := RegistryCredentialID("user", "alice", "ghcr.io")

	// A peer's concurrent login for the SAME triple arrives via replication (WAL apply) — same id,
	// strictly-newer HLC. It must LWW-win on the PK, not collide.
	r := NewReplicator(c, "", RelayConfig{})
	newer := "9000000000000-0000-peer"
	s := Statement{
		SQL:    registryCanonicalUpsertSQL,
		Params: []interface{}{id, "user", "alice", "ghcr.io", "alice", "peer", "2020-01-01T00:00:00Z", newer},
	}
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if aerr := r.applyStatementLWW(ctx, tx, s, newer); aerr != nil {
		tx.Rollback()
		t.Fatalf("replicated canonical upsert must apply (not back-pressure): %v", aerr)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rows := liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(rows) != 1 || rows[0].String("id") != id || rows[0].String("secret") != "peer" {
		t.Fatalf("concurrent logins must converge to one row (newer wins), got %v", rows)
	}
}

// canonicalUpsertStmt builds the exact statement the canonical writer emits (ledger-registered).
func canonicalUpsertStmt(id, scope, owner, registry, username, secret, createdAt, updatedAt string) Statement {
	return Statement{
		SQL:    registryCanonicalUpsertSQL,
		Params: []interface{}{id, scope, owner, registry, username, secret, createdAt, updatedAt},
	}
}

// applyRegistryWAL drives one replicated statement through the WAL apply path, returning the apply
// error (nil on success). Infra failures fail the test.
func applyRegistryWAL(t *testing.T, c *Client, s Statement) error {
	t.Helper()
	r := NewReplicator(c, "", RelayConfig{})
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	aerr := r.applyStatementLWW(context.Background(), tx, s, s.Params[len(s.Params)-1].(string))
	if aerr != nil {
		tx.Rollback()
		return aerr
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return nil
}

func fullRegistryRow(t *testing.T, c *Client, id string) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		"SELECT id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at FROM registry_credentials WHERE id = ?", id)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one row for id %s, got %d", id, len(rows))
	}
	r := rows[0]
	return strings.Join([]string{
		r.String("id"), r.String("scope"), r.String("owner"), r.String("registry"),
		r.String("username"), r.String("secret"), r.String("created_at"), r.String("updated_at"), r.String("deleted_at"),
	}, "|")
}

// TestRegistryCanonical_TwoClientConverges (finding 1): two nodes independently create the same
// deterministic id with DIFFERENT created_at; after bidirectional replication both nodes hold the
// IDENTICAL full row (the newer write's, created_at included) — no permanent created_at divergence.
func TestRegistryCanonical_TwoClientConverges(t *testing.T) {
	id := RegistryCredentialID("user", "alice", "ghcr.io")
	a := mustTestClient(t)
	a.SetCanonicalRegistryLatched(func() bool { return true })
	b := mustTestClient(t)
	b.SetCanonicalRegistryLatched(func() bool { return true })

	stmtA := canonicalUpsertStmt(id, "user", "alice", "ghcr.io", "alice", "sa", "2020-01-01T00:00:00Z", "1000000000000-0000-a")
	stmtB := canonicalUpsertStmt(id, "user", "alice", "ghcr.io", "alice", "sb", "2020-06-01T00:00:00Z", "2000000000000-0000-b") // newer

	// Each node's own create, then exchange both ways.
	if err := applyRegistryWAL(t, a, stmtA); err != nil {
		t.Fatalf("a local: %v", err)
	}
	if err := applyRegistryWAL(t, b, stmtB); err != nil {
		t.Fatalf("b local: %v", err)
	}
	if err := applyRegistryWAL(t, a, stmtB); err != nil {
		t.Fatalf("a<-b: %v", err)
	}
	if err := applyRegistryWAL(t, b, stmtA); err != nil {
		t.Fatalf("b<-a: %v", err)
	}

	rowA, rowB := fullRegistryRow(t, a, id), fullRegistryRow(t, b, id)
	if rowA != rowB {
		t.Fatalf("nodes must converge to an identical full row:\n A=%q\n B=%q", rowA, rowB)
	}
	// The winner is the newer write — created_at converged to it, not each node's local value.
	if want := id + "|user|alice|ghcr.io|alice|sb|2020-06-01T00:00:00Z|2000000000000-0000-b|"; rowA != want {
		t.Fatalf("converged row = %q, want %q (newer write, created_at propagated)", rowA, want)
	}
}

// TestRegistryCanonical_RejectedBeforeActivation (finding 2): a canonical upsert applied on a
// receiver where canonical_registry_v1 is NOT active fails closed (back-pressure) — a prematurely-
// enabled peer can't inject canonical rows while legacy writers still run.
func TestRegistryCanonical_RejectedBeforeActivation(t *testing.T) {
	c := mustTestClient(t) // gate OFF
	id := RegistryCredentialID("user", "alice", "ghcr.io")
	s := canonicalUpsertStmt(id, "user", "alice", "ghcr.io", "alice", "s", "2020-01-01T00:00:00Z", "1000000000000-0000-a")
	if err := applyRegistryWAL(t, c, s); err == nil {
		t.Fatal("canonical upsert must be rejected before activation")
	}
	if rows, _ := c.Query(context.Background(), "SELECT id FROM registry_credentials"); len(rows) != 0 {
		t.Fatalf("nothing must be applied before activation, got %d rows", len(rows))
	}
}

// TestRegistryCanonical_MismatchedIDRejected (finding 3): even with the capability active, a
// canonical upsert whose id does NOT equal RegistryCredentialID(scope,owner,registry) fails closed
// — it can't insert a noncanonical row or (via ON CONFLICT) hijack an unrelated credential's row.
func TestRegistryCanonical_MismatchedIDRejected(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })
	s := canonicalUpsertStmt("00000000-0000-8000-8000-000000000000", "user", "alice", "ghcr.io", "alice", "s", "2020-01-01T00:00:00Z", "1000000000000-0000-a")
	if err := applyRegistryWAL(t, c, s); err == nil {
		t.Fatal("a canonical upsert whose id != RegistryCredentialID(triple) must be rejected")
	}
	if rows, _ := c.Query(context.Background(), "SELECT id FROM registry_credentials"); len(rows) != 0 {
		t.Fatalf("a mismatched-id upsert must apply nothing, got %d rows", len(rows))
	}
}

// TestConsolidateRegistryCredentials_MigratesLegacyLive: a legacy random-id live credential is
// rewritten to its canonical deterministic-id row (content + created_at preserved), the legacy row
// is tombstoned, and a second run is a no-op (idempotent).
func TestConsolidateRegistryCredentials_MigratesLegacyLive(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })
	ctx := context.Background()
	// Two legacy logins ⇒ a tombstone (rand-1) + a live row (rand-2).
	if err := UpsertRegistryCredential(ctx, c, RegistryCredential{ID: "rand-1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s1"}); err != nil {
		t.Fatalf("seed 1: %v", err)
	}
	if err := UpsertRegistryCredential(ctx, c, RegistryCredential{ID: "rand-2", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s2"}); err != nil {
		t.Fatalf("seed 2: %v", err)
	}
	detID := RegistryCredentialID("user", "alice", "ghcr.io")
	// capture the legacy live row's created_at to assert preservation.
	pre, _ := c.Query(ctx, "SELECT created_at FROM registry_credentials WHERE id = 'rand-2'")
	legacyCreated := pre[0].String("created_at")

	if !mustNotComplete(t, c) { // not canonical yet
		t.Fatal("precondition: should be locally incomplete before consolidation")
	}

	migrated, err := ConsolidateRegistryCredentials(ctx, c)
	if err != nil || migrated != 1 {
		t.Fatalf("consolidate: migrated=%d err=%v (want 1/nil)", migrated, err)
	}
	live := liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(live) != 1 || live[0].String("id") != detID || live[0].String("secret") != "s2" {
		t.Fatalf("want one canonical live row secret=s2, got %v", live)
	}
	// created_at preserved from the legacy live row.
	got, _ := c.Query(ctx, "SELECT created_at FROM registry_credentials WHERE id = ?", detID)
	if got[0].String("created_at") != legacyCreated {
		t.Errorf("created_at not preserved: got %q want %q", got[0].String("created_at"), legacyCreated)
	}
	// legacy live row is tombstoned.
	if gone, _ := c.Query(ctx, "SELECT id FROM registry_credentials WHERE id='rand-2' AND deleted_at IS NULL"); len(gone) != 0 {
		t.Error("legacy live row must be tombstoned")
	}
	// idempotent + now locally complete.
	if m2, _ := ConsolidateRegistryCredentials(ctx, c); m2 != 0 {
		t.Errorf("second run must be a no-op, migrated=%d", m2)
	}
	if complete, _ := RegistryWriterReady(ctx, c); !complete {
		t.Error("must be locally complete after consolidation")
	}
}

func mustNotComplete(t *testing.T, c *Client) bool {
	t.Helper()
	complete, err := RegistryWriterReady(context.Background(), c)
	if err != nil {
		t.Fatalf("completeness: %v", err)
	}
	return !complete
}

// TestRegistryCanonical_EqualTSKeepsLocal: an equal-timestamp / different-content canonical
// conflict (two nodes wrote the same triple at the same HLC) is NOT silently overwritten — the
// exact-tie apply keeps local, so the divergence is surfaced (by anti-entropy's content resolver)
// rather than one write clobbering the other. This is where the equal-ts fault the local
// consolidation cannot see is fail-closed.
func TestRegistryCanonical_EqualTSKeepsLocal(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })
	id := RegistryCredentialID("user", "alice", "ghcr.io")
	const tie = "5000000000000-0000-tie"

	if err := applyRegistryWAL(t, c, canonicalUpsertStmt(id, "user", "alice", "ghcr.io", "alice", "sa", "2020-01-01T00:00:00Z", tie)); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// A conflicting write at the SAME updated_at with different content — must keep local.
	if err := applyRegistryWAL(t, c, canonicalUpsertStmt(id, "user", "alice", "ghcr.io", "alice", "sb", "2020-01-01T00:00:00Z", tie)); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	rows := liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(rows) != 1 || rows[0].String("secret") != "sa" {
		t.Fatalf("an equal-timestamp conflict must keep local (sa), not overwrite: got %v", rows)
	}
}

// TestConsolidate_ReplicatedMigrationKeepsCanonicalLive (finding 1): when a peer's migration
// entries (a by-id tombstone of the legacy row + the canonical upsert) arrive at a node that has
// ALREADY consolidated, the canonical live row must survive — the by-id tombstone targets the
// legacy id, not the canonical id (the old by-triple tombstone would have deleted it).
func TestConsolidate_ReplicatedMigrationKeepsCanonicalLive(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })
	ctx := context.Background()
	detID := RegistryCredentialID("user", "alice", "ghcr.io")
	const legacyTS = "2000000000000-0000-legacy"
	if err := c.Execute(ctx,
		`INSERT INTO registry_credentials (id, scope, owner, registry, username, secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"rand-legacy", "user", "alice", "ghcr.io", "alice", "s1", "2020-01-01T00:00:00Z", legacyTS); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := ConsolidateRegistryCredentials(ctx, c); err != nil {
		t.Fatalf("consolidate: %v", err)
	}
	if live := liveRegistryRows(t, c, "user", "alice", "ghcr.io"); len(live) != 1 || live[0].String("id") != detID {
		t.Fatalf("precondition: expected canonical live, got %v", live)
	}
	// Peer's migration entries (it consolidated the same converged legacy row) — full-content CAS.
	if err := applyRegistryWAL(t, c, Statement{SQL: registryTombstoneByIDSQL,
		Params: []interface{}{"2020-06-01T00:00:00Z", "9000000000000-0000-peer", "rand-legacy",
			"user", "alice", "ghcr.io", "alice", "s1", "2020-01-01T00:00:00Z", legacyTS}}); err != nil {
		t.Fatalf("apply peer tombstone: %v", err)
	}
	if err := applyRegistryWAL(t, c, canonicalUpsertStmt(detID, "user", "alice", "ghcr.io", "alice", "s1", "2020-01-01T00:00:00Z", legacyTS)); err != nil {
		t.Fatalf("apply peer canonical: %v", err)
	}
	live := liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(live) != 1 || live[0].String("id") != detID {
		t.Fatalf("exchanging migration entries must retain the canonical live row, got %v", live)
	}
}

// TestRegistryContractReady_vs_WriterReady (finding 4): after consolidation the writer is ready (no
// legacy LIVE rows) but the CONTRACT is NOT — the legacy tombstone remains, and a non-partial
// UNIQUE(scope,owner,registry) would reject it. Contract readiness needs the watermark-safe GC to
// reclaim the tombstones first.
func TestRegistryContractReady_vs_WriterReady(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })
	ctx := context.Background()
	if err := UpsertRegistryCredential(ctx, c, RegistryCredential{ID: "rand-1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s1"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := ConsolidateRegistryCredentials(ctx, c); err != nil {
		t.Fatalf("consolidate: %v", err)
	}
	if wr, _ := RegistryWriterReady(ctx, c); !wr {
		t.Fatal("writer-ready must be true after consolidation (no legacy live rows)")
	}
	if cr, _ := RegistryContractReady(ctx, c); cr {
		t.Fatal("contract-ready must be FALSE while a legacy tombstone remains")
	}
	// Simulate the watermark-safe GC reclaiming the tombstone.
	if err := c.Execute(ctx, "DELETE FROM registry_credentials WHERE id = 'rand-1'"); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if cr, _ := RegistryContractReady(ctx, c); !cr {
		t.Fatal("contract-ready must be true once no non-canonical physical rows remain")
	}
}

// TestConsolidate_RequiresLatch (finding 5): consolidation refuses to run before the accept-latch,
// since its canonical writes would be rejected by peers.
func TestConsolidate_RequiresLatch(t *testing.T) {
	c := mustTestClient(t) // latch NOT set
	if _, err := ConsolidateRegistryCredentials(context.Background(), c); err == nil {
		t.Fatal("consolidation must require canonical_registry_v1 latched")
	}
}

// TestConsolidate_EqualTSDiffContentBackPressures (finding): two nodes hold the SAME legacy id and
// updated_at but DIFFERENT content. When the sender's consolidation entry (a full-content-CAS
// tombstone + the canonical upsert) is applied on the receiver, the tombstone matches ZERO rows
// (content mismatch), so the canonical insert collides with the still-live legacy row on the partial
// UNIQUE and the WHOLE mutation entry rolls back / back-pressures — the migration fails closed
// instead of silently retiring the receiver's differing credential.
func TestConsolidate_EqualTSDiffContentBackPressures(t *testing.T) {
	c := mustTestClient(t)
	c.SetCanonicalRegistryLatched(func() bool { return true })
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})
	const id, ts, created = "rand-X", "2000000000000-0000-legacy", "2020-01-01T00:00:00Z"
	detID := RegistryCredentialID("user", "alice", "ghcr.io")

	// Receiver holds the legacy row with its OWN (different) secret.
	if err := c.Execute(ctx,
		`INSERT INTO registry_credentials (id, scope, owner, registry, username, secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "user", "alice", "ghcr.io", "alice", "receiver-secret", created, ts); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Sender's consolidation entry: tombstone (sender's content) + canonical upsert (sender's content).
	stmts, _ := json.Marshal([]Statement{
		{SQL: registryTombstoneByIDSQL, Params: []interface{}{"2020-06-01T00:00:00Z", "9000000000000-0000-peer", id,
			"user", "alice", "ghcr.io", "alice", "sender-secret", created, ts}},
		{SQL: registryCanonicalUpsertSQL, Params: []interface{}{detID, "user", "alice", "ghcr.io", "alice", "sender-secret", created, ts}},
	})
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: "9000000000000-0000-peer", Origin: "sender-node", Stmts: string(stmts)}}

	if _, err := r.ApplyRemoteMutations(ctx, entries); err == nil {
		t.Fatal("equal-timestamp/different-content consolidation must back-pressure (fail closed)")
	}
	assertNotSeen(t, c, "sender-node") // watermark not advanced

	// The receiver's differing legacy credential must remain LIVE (nothing was retired).
	live := liveRegistryRows(t, c, "user", "alice", "ghcr.io")
	if len(live) != 1 || live[0].String("id") != id || live[0].String("secret") != "receiver-secret" {
		t.Fatalf("receiver's differing legacy credential must remain live, got %v", live)
	}
}

// TestRegistryLegacyInsert_GatedByPhase2 (point 7): the legacy mint-new-id INSERT is applied
// before the canonical writer is on, and REJECTED (back-pressure) once canonical_registry_active_v1
// is active on the receiver — a stray legacy INSERT after activation can't create a duplicate row.
func TestRegistryLegacyInsert_GatedByPhase2(t *testing.T) {
	legacyInsert := func(id string) Statement {
		return Statement{SQL: registryLegacyInsertSQL,
			Params: []interface{}{id, "user", "alice", "ghcr.io", "alice", "s1", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"}}
	}
	ctx := context.Background()

	// Phase 2 OFF (writer off) ⇒ accepted.
	off := mustTestClient(t)
	if err := applyRegistryWAL(t, off, legacyInsert("rand-1")); err != nil {
		t.Fatalf("legacy INSERT must apply before activation: %v", err)
	}
	if rows, _ := off.Query(ctx, "SELECT id FROM registry_credentials WHERE id='rand-1'"); len(rows) != 1 {
		t.Fatal("legacy row must exist before activation")
	}

	// Phase 2 ON (writer on) ⇒ rejected.
	on := mustTestClient(t)
	on.SetCanonicalRegistry(func() bool { return true })
	if err := applyRegistryWAL(t, on, legacyInsert("rand-2")); err == nil {
		t.Fatal("legacy INSERT must be rejected after activation")
	}
	if rows, _ := on.Query(ctx, "SELECT id FROM registry_credentials WHERE id='rand-2'"); len(rows) != 0 {
		t.Fatal("nothing must be applied after activation")
	}
}
