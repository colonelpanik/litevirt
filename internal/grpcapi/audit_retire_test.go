package grpcapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// Phase 2 of RetireAuditKey had ZERO coverage. Both previous tests exited at the
// same "no live audit signing certificate" precondition, so RecordSignedRetirement
// — the CA chain check, the CN match, and both signature checks — was never
// reached. Deleting the entire verification loop left them green.
//
// That matters more than an ordinary coverage gap: this RPC is the only way to
// close a signing contract on a host that cannot sign for itself, so a regression
// that accepted an unverified retirement would let any admin-role caller put
// every row a host ever signed past a forged boundary.

// retireFixture gives a server a host with one live, adopted signing key, plus a
// CA it can mint retirement certificates from — the state phase 2 needs.
func retireFixture(t *testing.T, host string) (*Server, string, string) {
	t.Helper()
	s := testServer(t)
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := pki.GenerateHostCert(caCert, caKey,
		filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
		host, net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}
	s.pkiDir = dir

	kr, err := corrosion.LoadAuditKeyring(dir, host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	s.db.SetAuditKeyring(kr)
	if _, err := corrosion.AdoptAuditKey(context.Background(), s.db, kr, host); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	return s, dir, kr.KeyID()
}

// mintRetirement produces what a real `lv host retire-audit-key` sends in phase 2.
func mintRetirement(t *testing.T, caDir, host string, retiredKeyID string, seq int64) (certPEM, sig, selfSig, adoptSig string) {
	t.Helper()
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, pki.AuditSigningCertName)
	keyPath := filepath.Join(tmp, pki.AuditSigningKeyName)
	if err := pki.GenerateAuditSigningCert(
		filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"),
		certPath, keyPath, host); err != nil {
		t.Fatalf("mint: %v", err)
	}
	kr, err := corrosion.LoadAuditKeyringFromPaths(caDir, certPath, keyPath, host)
	if err != nil {
		t.Fatalf("load minted: %v", err)
	}
	s1, err := kr.SignLifecycle(host, retiredKeyID, "retired", seq)
	if err != nil {
		t.Fatalf("SignLifecycle: %v", err)
	}
	s2, err := kr.SignLifecycle(host, kr.KeyID(), "retired", seq)
	if err != nil {
		t.Fatalf("SignLifecycle self: %v", err)
	}
	// The CA signature is what carries standing over the key being retired — a leaf,
	// even a CA-signed one, has authority over nobody but itself. See reduceLifecycle.
	s3, err := corrosion.SignLifecycleWithCA(caDir, host, retiredKeyID, "retired", seq)
	if err != nil {
		t.Fatalf("SignLifecycleWithCA: %v", err)
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	return string(b), s1, s2, s3
}

// TestRetireAuditKey_PhaseOneWritesNothing. Phase 1 answers what would be
// retired; if it wrote anything, a caller who never completes phase 2 would have
// closed a contract without ever proving they could.
func TestRetireAuditKey_PhaseOneWritesNothing(t *testing.T) {
	ctx := context.Background()
	s, _, keyID := retireFixture(t, "node-1")

	resp, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err != nil {
		t.Fatalf("phase 1: %v", err)
	}
	if resp.RetiredKeyId != keyID {
		t.Fatalf("phase 1 named key %q, want %q", resp.RetiredKeyId, keyID)
	}
	rows, err := s.db.Query(ctx, `SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired'`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("phase 1 recorded %d retirement(s); it must only report", len(rows))
	}
}

// TestRetireAuditKey_PhaseTwoRejectsBadSubmissions is the coverage that was
// missing. Each case must be refused AND must leave nothing behind — a failed
// phase 2 that published its certificate anyway left an orphan contract.
func TestRetireAuditKey_PhaseTwoRejectsBadSubmissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		// mutate the well-formed submission into a bad one
		breakIt func(cert, sig, selfSig string) (string, string, string)
	}{
		{"certificate does not chain to the cluster CA", func(_, sig, self string) (string, string, string) {
			other := t.TempDir()
			if err := pki.GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
				t.Fatalf("GenerateCA: %v", err)
			}
			c, _, _, _ := mintRetirement(t, other, "node-1", "x", 0)
			return c, sig, self
		}},
		{"certificate names a different host", func(_, sig, self string) (string, string, string) {
			// Minted from the RIGHT CA but for the wrong host.
			s2, dir2, k2 := retireFixture(t, "node-other")
			_ = s2
			c, _, _, _ := mintRetirement(t, dir2, "node-other", k2, 0)
			return c, sig, self
		}},
		{"retirement signature is wrong", func(cert, _, self string) (string, string, string) {
			return cert, "deadbeef", self
		}},
		{"self-retirement signature is wrong", func(cert, sig, _ string) (string, string, string) {
			return cert, sig, "deadbeef"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir, keyID := retireFixture(t, "node-1")
			plan, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
			if err != nil {
				t.Fatalf("phase 1: %v", err)
			}
			cert, sig, self, adopt := mintRetirement(t, dir, "node-1", keyID, plan.RetiredAtSeq)
			cert, sig, self = tc.breakIt(cert, sig, self)

			if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
				HostName: "node-1", CertPem: cert, Signature: sig, SelfSignature: self, CaSignature: adopt,
			}); err == nil {
				t.Fatal("phase 2 accepted a submission it should have refused")
			}
			n := countRows(t, s, `SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired'`)
			if n != 0 {
				t.Fatalf("a refused phase 2 recorded %d retirement(s)", n)
			}
			// The orphan-certificate case: publishing before verifying left a
			// certificate naming the host with no adoption and no retirement, which
			// put the host under a contract starting at row 0 forever.
			if got := countRows(t, s, `SELECT key_id FROM audit_signing_keys`); got != 1 {
				t.Fatalf("a refused phase 2 left %d certificates published, want just the "+
					"host's own; an orphan certificate is a contract nobody can close", got)
			}
		})
	}
}

// TestRetireAuditKey_PhaseTwoSucceeds is the other direction — the refusals above
// must not be a wall.
func TestRetireAuditKey_PhaseTwoSucceeds(t *testing.T) {
	s, dir, keyID := retireFixture(t, "node-1")
	plan, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err != nil {
		t.Fatalf("phase 1: %v", err)
	}
	cert, sig, self, adopt := mintRetirement(t, dir, "node-1", keyID, plan.RetiredAtSeq)

	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: cert, Signature: sig, SelfSignature: self, CaSignature: adopt,
	}); err != nil {
		t.Fatalf("phase 2 refused a well-formed submission: %v", err)
	}
	if n := countRows(t, s, `SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired'`); n != 2 {
		t.Fatalf("want the host's key AND the minted certificate retired, got %d records\n"+
			"a certificate minted to END a contract must not stand as a new one", n)
	}
	// And the contract really is closed.
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"}); err == nil {
		t.Fatal("the host still has a live contract after a successful retirement")
	}
}

func countRows(t *testing.T, s *Server, q string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), q)
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return len(rows)
}

// TestRetireAuditKey_RefusesFromALaggingReplica.
//
// Found on the lab, and it is the finding the floor was supposed to have closed.
// Retiring node-3 from a node whose copy of node-3's log ended at seq 5 — while
// node-3 had genuinely signed through 8 — recorded the boundary at 5. Anti-entropy
// then delivered rows 6, 7 and 8, and all three became permanent RetiredKeyUse
// findings on every node in the cluster.
//
// The floor cannot help: a host's heads are signed by its own keys, and retiring
// the current one excludes exactly the heads that would prove how far the chain
// has come. So the only safe move is to notice and refuse.
func TestRetireAuditKey_RefusesFromALaggingReplica(t *testing.T) {
	ctx := context.Background()
	s, dir, keyID := retireFixture(t, "node-1")
	_ = dir

	// The host's own chain head says it reached seq 9; this node holds nothing.
	kr, err := corrosion.LoadAuditKeyring(s.pkiDir, "node-1")
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	created := "2026-07-29T10:00:00Z"
	sig, err := kr.SignHead("node-1", 0, 9, "aabb", created)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-1', 0, 9, 'aabb', ?, ?, ?, ?, NULL)`,
		kr.KeyID(), sig, created, created); err != nil {
		t.Fatalf("insert head: %v", err)
	}

	_, err = s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err == nil {
		t.Fatalf("retiring succeeded from a replica that is 9 rows behind\n"+
			"the boundary would be pinned below every row key %s legitimately signed, "+
			"permanently, and anti-entropy would then report each of them", keyID)
	}
	if !strings.Contains(err.Error(), "attests to") {
		t.Errorf("the refusal does not explain that the replica is behind: %v", err)
	}
}

// TestRetireAuditKey_AtSeqOverridesAPoisonedHead.
//
// The lagging-replica refusal counts heads signed by the key being retired, which
// is deliberate — a host's heads are signed by its own keys, so excluding them is
// what let a stale replica pin a boundary below rows that were legitimately
// signed. The cost is that whoever holds the leaked key publishes ONE head at an
// absurd sequence and retirement then refuses on every node forever: heads are
// append-only, tombstones are inert, and anti-entropy refuses rewrites, so the
// claim cannot be withdrawn.
//
// Without --at-seq the leaked key disables the command that retires it.
func TestRetireAuditKey_AtSeqOverridesAPoisonedHead(t *testing.T) {
	ctx := context.Background()
	s, dir, keyID := retireFixture(t, "node-1")

	// The attacker, holding the key about to be retired, claims the chain reached a
	// sequence no replica can ever match.
	kr, err := corrosion.LoadAuditKeyring(dir, "node-1")
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	created := "2026-07-29T10:00:00Z"
	sig, err := kr.SignHead("node-1", 0, 1_000_000_000, "aabb", created)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-1', 0, 1000000000, 'aabb', ?, ?, ?, ?, NULL)`,
		kr.KeyID(), sig, created, created); err != nil {
		t.Fatalf("insert the poisoned head: %v", err)
	}

	// Without the override the command is dead.
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"}); err == nil {
		t.Fatal("a head at seq 1e9 did not block retirement; the refusal is not doing its job")
	}

	// With it, the operator names the boundary and phase 1 answers.
	plan, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", AtSeq: at(7),
	})
	if err != nil {
		t.Fatalf("--at-seq did not get past the poisoned head: %v\n"+
			"the key that leaked would then be permanently un-retirable, because the head "+
			"it published cannot be withdrawn", err)
	}
	if plan.RetiredAtSeq != 7 {
		t.Fatalf("phase 1 reports boundary %d, not the requested 7; the CLI signs over the "+
			"reported value, so a mismatch here means the signatures cannot match", plan.RetiredAtSeq)
	}

	// And phase 2 records it at exactly that sequence.
	certPEM, rsig, selfSig, adoptSig := mintRetirement(t, dir, "node-1", keyID, 7)
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: certPEM, Signature: rsig, SelfSignature: selfSig, CaSignature: adoptSig, AtSeq: at(7),
	}); err != nil {
		t.Fatalf("phase 2 with the override: %v", err)
	}
	rows, err := s.db.Query(ctx, `SELECT at_seq FROM audit_key_lifecycle
	     WHERE host_name = 'node-1' AND event = 'retired' AND key_id = ?`, keyID)
	if err != nil {
		t.Fatalf("read the recorded boundary: %v", err)
	}
	if len(rows) != 1 || rows[0].Int64("at_seq") != 7 {
		t.Fatalf("want one retirement recorded at 7, got %d row(s): %v", len(rows), rows)
	}
}

// TestRetireAuditKey_AtSeqStillVerifiesTheSignatures.
//
// The override skips the boundary derivation and the lagging-replica check. It must
// not skip anything else — it is reachable by any admin caller, and the property
// that makes it safe to expose is that completing a retirement still needs a
// certificate minted with the cluster CA private key.
func TestRetireAuditKey_AtSeqStillVerifiesTheSignatures(t *testing.T) {
	s, dir, keyID := retireFixture(t, "node-1")

	// Signatures made for sequence 7, submitted against a claimed boundary of 9.
	certPEM, sig, selfSig, adoptSig := mintRetirement(t, dir, "node-1", keyID, 7)
	_, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: certPEM, Signature: sig, SelfSignature: selfSig, CaSignature: adoptSig, AtSeq: at(9), Force: true,
	})
	if err == nil {
		t.Fatal("--at-seq accepted signatures made over a different sequence\n" +
			"the boundary would then be operator-chosen AND unauthenticated, so anyone who " +
			"could reach the RPC could retire any key at any sequence")
	}
	if n := countRows(t, s, `SELECT key_id FROM audit_key_lifecycle WHERE event = 'retired'`); n != 0 {
		t.Errorf("a rejected override still recorded %d retirement(s)", n)
	}
}

// insAudit appends one signed row to the host's chain, so the derived boundary has
// somewhere above zero to sit.
func insAudit(t *testing.T, s *Server, host string) {
	t.Helper()
	if err := corrosion.InsertAuditLog(context.Background(), s.db, corrosion.AuditRecord{
		ID: fmt.Sprintf("row-%d-%s", time.Now().UnixNano(), host), Username: "root",
		HostName: host, Action: "vm.start", Target: "vm1", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
}

// at is the presence-carrying form of an --at-seq value. A pointer rather than a
// zero sentinel because 0 is a meaningful boundary: "this key signed nothing valid".
func at(seq int64) *int64 { return &seq }

// TestRetireAuditKey_AtSeqBelowTheDerivedBoundaryNeedsForce.
//
// Raising a boundary and lowering one are not the same operation. Rows ABOVE the
// boundary are the finding, so a higher boundary forgives more and cannot condemn
// anything; a lower one is unrecoverable, because lifecycle records are append-only
// and the earliest verified retirement is the one that stands.
//
// The derived sequence is the one number that can tell the two apart, and it is
// sitting in a local variable when the override is applied. A mistyped --at-seq 42
// for 4210 otherwise reads exactly like a deliberate decision.
func TestRetireAuditKey_AtSeqBelowTheDerivedBoundaryNeedsForce(t *testing.T) {
	s, dir, keyID := retireFixture(t, "node-1")
	for i := 0; i < 6; i++ {
		insAudit(t, s, "node-1")
	}
	plan, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err != nil {
		t.Fatalf("phase 1: %v", err)
	}
	derived := plan.RetiredAtSeq
	if derived < 2 {
		t.Fatalf("need a derived boundary above 1 to have room below it, got %d", derived)
	}

	// Below the derived boundary, without --force.
	_, err = s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", AtSeq: at(1),
	})
	if err == nil {
		t.Fatalf("accepted a boundary of 1 when this node can already see the chain reaching "+
			"%d\nevery row in between becomes a permanent retired-key finding on every node, "+
			"and a typo is indistinguishable from a decision", derived)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the refusal does not say how to proceed deliberately: %v", err)
	}

	// At the derived boundary, and above it: both are the safe direction.
	for _, seq := range []int64{derived, derived + 100} {
		if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
			HostName: "node-1", AtSeq: at(seq),
		}); err != nil {
			t.Fatalf("refused a boundary of %d with the derived one at %d: %v\n"+
				"raising a boundary cannot condemn a row, and at-or-above is the legitimate "+
				"way past a chain head claiming more than the log holds", seq, derived, err)
		}
	}

	// With --force, the operator gets what they asked for.
	certPEM, sig, selfSig, adoptSig := mintRetirement(t, dir, "node-1", keyID, 1)
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: certPEM, Signature: sig, SelfSignature: selfSig, CaSignature: adoptSig,
		AtSeq: at(1), Force: true,
	}); err != nil {
		t.Fatalf("--force did not permit a deliberate lower boundary: %v", err)
	}
}

// TestRetireAuditKey_ANegativeAtSeqIsRefused.
//
// A `> 0` gate treated a negative sequence as "not supplied", so a client that
// believed it was pinning a boundary got the derived one back with a success
// response and no sign its input had been discarded.
func TestRetireAuditKey_ANegativeAtSeqIsRefused(t *testing.T) {
	s, _, _ := retireFixture(t, "node-1")
	_, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", AtSeq: at(-5),
	})
	if err == nil {
		t.Fatal("a negative at_seq was accepted; a malformed sequence must be refused, not " +
			"silently replaced by the derived boundary")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument for a malformed sequence, got %v", status.Code(err))
	}
}

// TestRetireAuditKey_TheAuditRecordNamesAnOverride.
//
// This is the audit log of the audit system. A retirement that bypassed the
// lagging-replica protection must not read the same as one that did not, or the only
// record of it is a slog line on whichever node happened to serve the RPC.
func TestRetireAuditKey_TheAuditRecordNamesAnOverride(t *testing.T) {
	ctx := context.Background()
	s, dir, keyID := retireFixture(t, "node-1")

	certPEM, sig, selfSig, adoptSig := mintRetirement(t, dir, "node-1", keyID, 9)
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: certPEM, Signature: sig, SelfSignature: selfSig, CaSignature: adoptSig,
		AtSeq: at(9),
	}); err != nil {
		t.Fatalf("retire with an override: %v", err)
	}

	rows, err := s.db.Query(ctx,
		`SELECT detail FROM audit_log WHERE action = 'audit.key.retire' ORDER BY seq DESC LIMIT 1`)
	if err != nil {
		t.Fatalf("read the audit record: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("no audit record was written for the retirement")
	}
	detail := rows[0].String("detail")
	if !strings.Contains(detail, "operator-supplied") {
		t.Errorf("the audit record does not say the boundary was supplied rather than derived: %q\n"+
			"an investigation into why a host's rows are all retired-key findings has no way to "+
			"tell that a safety check was skipped", detail)
	}
	if !strings.Contains(detail, "derived") {
		t.Errorf("the audit record does not name the sequence this node derived: %q\n"+
			"that value is the evidence the two disagreed", detail)
	}
}

// TestRetireAuditKey_KeyIDSelectsAmongSeveralLiveKeys.
//
// A host with two live keys could not be retired AT ALL. The handler refused with
// "retire them one at a time" and the RPC took only a host name, so there was no
// way to name one — and two live keys is exactly what a rotation that never
// completed leaves behind, which is the state this command exists for.
func TestRetireAuditKey_KeyIDSelectsAmongSeveralLiveKeys(t *testing.T) {
	s, dir, firstKey := retireFixture(t, "node-1")

	// A second live key for the same host: mint another signing pair, publish and
	// adopt it, without retiring the first.
	second := t.TempDir()
	if err := pki.GenerateAuditSigningCert(
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(second, pki.AuditSigningCertName),
		filepath.Join(second, pki.AuditSigningKeyName),
		"node-1"); err != nil {
		t.Fatalf("mint the second signing cert: %v", err)
	}
	if err := copyFile(filepath.Join(dir, "ca.crt"), filepath.Join(second, "ca.crt")); err != nil {
		t.Fatalf("stage the CA for the second keyring: %v", err)
	}
	kr2, err := corrosion.LoadAuditKeyring(second, "node-1")
	if err != nil {
		t.Fatalf("LoadAuditKeyring(second): %v", err)
	}
	if err := kr2.PublishSigningKey(context.Background(), s.db); err != nil {
		t.Fatalf("publish the second certificate: %v", err)
	}
	// AdoptAuditKeyContract, not AdoptAuditKey: the latter IS a rotation and would
	// retire the first key, which is the state this test needs to not be in.
	if err := corrosion.AdoptAuditKeyContract(context.Background(), s.db, kr2, "node-1", 1); err != nil {
		t.Fatalf("adopt the second key: %v", err)
	}
	if kr2.KeyID() == firstKey {
		t.Fatal("the second key has the same id as the first; the test would pass vacuously")
	}

	// Without a selector: refused, and the message has to name the flag that works.
	_, err = s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err == nil {
		t.Fatal("retired one of two live keys without being told which")
	}
	if !strings.Contains(err.Error(), "--key-id") {
		t.Errorf("the refusal does not say how to proceed: %v", err)
	}

	// With one: a plan for exactly that key.
	plan, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", KeyId: kr2.KeyID(),
	})
	if err != nil {
		t.Fatalf("RetireAuditKey with --key-id: %v", err)
	}
	if plan.RetiredKeyId != kr2.KeyID() {
		t.Fatalf("planned to retire %s, asked for %s", plan.RetiredKeyId, kr2.KeyID())
	}

	// A key that is not live is refused rather than silently retiring something else.
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", KeyId: "0000000000000000",
	}); err == nil {
		t.Error("accepted a key id the host does not have live")
	}
}
