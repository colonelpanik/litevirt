package grpcapi

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// mintCRL builds a CRL under a CA of the caller's choosing and returns its PEM.
func mintCRL(t *testing.T, dir string, serials ...string) string {
	t.Helper()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, err := os.Stat(caCert); err != nil {
		if err := pki.GenerateCA(caCert, caKey); err != nil {
			t.Fatalf("GenerateCA: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "minted.pem")
	if err := pki.GenerateCRL(caCert, caKey, path, serials); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read minted CRL: %v", err)
	}
	return string(pemBytes)
}

func publishedCRLCount(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := corrosion.ClusterCRLs(context.Background(), s.db)
	if err != nil {
		t.Fatalf("ClusterCRLs: %v", err)
	}
	return len(rows)
}

func TestPublishCRL_StoresACRLSignedByTheClusterCA(t *testing.T) {
	s := testServer(t)
	s.pkiDir = t.TempDir()
	crlPEM := mintCRL(t, s.pkiDir, "1a2b")

	resp, err := s.PublishCRL(adminCtx(), &pb.PublishCRLRequest{CrlPem: crlPEM})
	if err != nil {
		t.Fatalf("PublishCRL: %v", err)
	}
	if resp.Version <= 0 {
		t.Fatalf("published CRL reported version %d", resp.Version)
	}
	if n := publishedCRLCount(t, s); n != 1 {
		t.Fatalf("cluster_crl holds %d rows after one publish, want 1", n)
	}
}

// Verification has to happen BEFORE the row is written, not alongside it. The
// same ordering mistake in RecordSignedRetirement left an orphan certificate
// behind on a failed phase 2; here it would leave a CRL any caller composed
// sitting in the table every peer syncs from.
func TestPublishCRL_StoresNothingWhenTheCRLDoesNotVerify(t *testing.T) {
	s := testServer(t)
	s.pkiDir = t.TempDir()
	mintCRL(t, s.pkiDir) // give the server a CA of its own
	foreign := mintCRL(t, t.TempDir(), "1a2b")

	if _, err := s.PublishCRL(adminCtx(), &pb.PublishCRLRequest{CrlPem: foreign}); err == nil {
		t.Fatal("accepted a CRL signed by a CA that is not this cluster's")
	}
	if n := publishedCRLCount(t, s); n != 0 {
		t.Fatalf("a refused CRL was published anyway: %d rows in cluster_crl", n)
	}
}

func TestPublishCRL_RejectsAnEmptySubmission(t *testing.T) {
	s := testServer(t)
	s.pkiDir = t.TempDir()
	if _, err := s.PublishCRL(adminCtx(), &pb.PublishCRLRequest{}); err == nil {
		t.Fatal("accepted an empty CRL")
	}
	if n := publishedCRLCount(t, s); n != 0 {
		t.Fatalf("an empty submission produced %d rows in cluster_crl", n)
	}
}

func TestPublishCRL_RepairsACorruptLocalCRLFromPublishedState(t *testing.T) {
	s := testServer(t)
	s.pkiDir = t.TempDir()
	crlPEM := mintCRL(t, s.pkiDir, "1a2b")
	if err := os.WriteFile(filepath.Join(s.pkiDir, "crl.pem"), []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt local CRL: %v", err)
	}
	if _, err := s.PublishCRL(adminCtx(), &pb.PublishCRLRequest{CrlPem: crlPEM}); err != nil {
		t.Fatalf("PublishCRL recovery: %v", err)
	}
	if !pki.IsCertRevoked(s.pkiDir, big.NewInt(0x1a2b)) {
		t.Fatal("published CRL did not repair and replace corrupt local state")
	}
}
