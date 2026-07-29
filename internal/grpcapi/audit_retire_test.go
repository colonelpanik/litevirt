package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Retiring a key on a host's behalf is CA authority, and the RPC has to say so
// rather than silently doing nothing useful on a node that cannot mint.
//
// The failure it guards against is quiet: a node without ca.key would mint
// nothing, and an operator who ran the command on the wrong machine would
// believe a leaked key's contract had been ended when it had not.
func TestRetireAuditKey_RequiresTheClusterCA(t *testing.T) {
	s := testServer(t) // its PKI dir holds no ca.key
	_, err := s.RetireAuditKey(adminCtx(), &pb.RetireAuditKeyRequest{HostName: "node-1"})
	if err == nil {
		t.Fatal("retiring a key succeeded on a node with no cluster CA private key; " +
			"an operator on the wrong machine would think the contract was ended")
	}
}
