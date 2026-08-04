package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertisedCapabilities_AuditSignatureConditional: audit_signature_v1 is
// advertised only when the node is config-enforcing, so the cluster-wide latch
// requires CONFIG uniformity. A node with the flag off keeps writing unsigned
// audit rows into the same replicated table; if the latch could form anyway,
// peers would start refusing unsignable writes — and treating an unsigned row as
// evidence of tampering — while a legitimate source of unsigned rows was still
// running. The build-static tokens are unaffected.
func TestAdvertisedCapabilities_AuditSignatureConditional(t *testing.T) {
	off := testServer(t) // enfAuditSignature defaults false
	if hasCap(off.advertisedCapabilities(), capabilities.AuditSignatureV1) {
		t.Fatal("audit_signature_v1 must NOT be advertised when config-off")
	}
	if !hasCap(off.advertisedCapabilities(), capabilities.SplitBrainGateV1) {
		t.Fatal("build-static tokens must still be advertised")
	}
	if off.tokenEnabled(capabilities.AuditSignatureV1) {
		t.Fatal("tokenEnabled(audit_signature_v1) must be false when config-off (latch not driven)")
	}

	on := testServer(t)
	on.SetAuditSignatureEnforce(true)
	if !hasCap(on.advertisedCapabilities(), capabilities.AuditSignatureV1) {
		t.Fatal("audit_signature_v1 must be advertised when config-on")
	}
	// tokenEnabled is the predicate driveCapabilityActivation uses to decide which
	// tokens to latch-drive. A token missing from its switch falls to `default:
	// return false`, so the latch is never driven at all and auditSignatureActive
	// could never become true in production — silently, with every test above still
	// green.
	if !on.tokenEnabled(capabilities.AuditSignatureV1) {
		t.Fatal("tokenEnabled(audit_signature_v1) must be true when config-on (drives the latch)")
	}

	// Filtering must never mutate the shared build-static Supported() slice.
	if !hasCap(capabilities.Supported(), capabilities.AuditSignatureV1) {
		t.Fatal("advertisedCapabilities filtering corrupted the shared Supported() slice")
	}
}
