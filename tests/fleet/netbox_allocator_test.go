package fleet

import (
	"testing"
)

// TestContainerAllocationUnchangedWithoutNetBox is the refactor regression
// guard for putting AllocateIPFor behind an Allocator interface
// (internal/network/allocator.go). That refactor touches the container create
// path (internal/grpcapi/container_network.go) for EVERY user, NetBox or not,
// which is why it needs a real multi-node fleet exercise rather than a
// single-package unit test: this asserts a no-NetBox cluster still allocates
// exactly as before — byte-identical to the pre-refactor builtin allocator,
// which starts at the first host address in the subnet.
func TestContainerAllocationUnchangedWithoutNetBox(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	seedContainerNetwork(t, c)

	n := c.Nodes[0]
	firstIP := createContainerOnNetwork(t, c, n, "ct-1")
	secondIP := createContainerOnNetwork(t, c, n, "ct-2")

	if firstIP != "10.77.0.2" {
		t.Fatalf("first container IP = %q, want 10.77.0.2", firstIP)
	}
	if secondIP != "10.77.0.3" {
		t.Fatalf("second container IP = %q, want 10.77.0.3", secondIP)
	}
}
