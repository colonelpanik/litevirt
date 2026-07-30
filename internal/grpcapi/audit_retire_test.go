package grpcapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
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
