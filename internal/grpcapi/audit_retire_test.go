package grpcapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
func mintRetirement(t *testing.T, caDir, host string, retiredKeyID string, seq int64) (certPEM, sig, selfSig string) {
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
	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	return string(b), s1, s2
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
			c, _, _ := mintRetirement(t, other, "node-1", "x", 0)
			return c, sig, self
		}},
		{"certificate names a different host", func(_, sig, self string) (string, string, string) {
			// Minted from the RIGHT CA but for the wrong host.
			s2, dir2, k2 := retireFixture(t, "node-other")
			_ = s2
			c, _, _ := mintRetirement(t, dir2, "node-other", k2, 0)
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
			cert, sig, self := mintRetirement(t, dir, "node-1", keyID, plan.RetiredAtSeq)
			cert, sig, self = tc.breakIt(cert, sig, self)

			if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
				HostName: "node-1", CertPem: cert, Signature: sig, SelfSignature: self,
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
	cert, sig, self := mintRetirement(t, dir, "node-1", keyID, plan.RetiredAtSeq)

	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: cert, Signature: sig, SelfSignature: self,
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
		HostName: "node-1", AtSeq: 7,
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
	certPEM, rsig, selfSig := mintRetirement(t, dir, "node-1", keyID, 7)
	if _, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: certPEM, Signature: rsig, SelfSignature: selfSig, AtSeq: 7,
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
	certPEM, sig, selfSig := mintRetirement(t, dir, "node-1", keyID, 7)
	_, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: certPEM, Signature: sig, SelfSignature: selfSig, AtSeq: 9,
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
