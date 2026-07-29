package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Phase 1 answers what would be retired; it must not write anything, and it must
// refuse for a host that has no live contract — otherwise an operator would be
// told an already-closed contract had just been closed again.
func TestRetireAuditKey_RefusesAHostWithNoLiveContract(t *testing.T) {
	s := testServer(t)
	_, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err == nil {
		t.Fatal("retiring succeeded for a host that has published no signing certificate")
	}
}

// A retirement the caller did not sign must not be recorded. The daemon holds no
// CA — that lives in the operator's config directory and never has to be on a
// node — so verifying is the only thing it can do, and the only thing it should.
func TestRetireAuditKey_RefusesAnUnsignedSubmission(t *testing.T) {
	s := testServer(t)
	_, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{
		HostName: "node-1", CertPem: "not a certificate", Signature: "deadbeef",
	})
	if err == nil {
		t.Fatal("a retirement with an unusable certificate was accepted")
	}
}
