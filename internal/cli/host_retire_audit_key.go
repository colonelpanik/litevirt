package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// HostRetireAuditKey ends a host's audit signing contract on its behalf.
//
// The daemon signs its own retirement whenever an operator turns
// enforcement.audit_signature off, so an ordinary rollback needs no command.
// This is for a host that cannot sign one: key lost or unreadable, machine
// destroyed, decommission. Left alone, such a host keeps a published certificate
// declaring that its rows are signed, and every unsigned row it ever wrote is
// reported as evidence on every node with no way to close it out.
//
// The signing happens HERE, not on a node. The cluster CA private key lives in
// the operator's config directory and never has to be present on a cluster
// member — so the daemon reports what would be retired, this mints and signs,
// and the daemon verifies and records. A private key is never sent anywhere.
func HostRetireAuditKey(ctx context.Context, c pb.LiteVirtClient, hostName string) error {
	if hostName == "" {
		return fmt.Errorf("host name required")
	}
	// Phase 1: ask which key would be retired, and at what sequence. Nothing is
	// written by this call.
	plan, err := c.RetireAuditKey(ctx, &pb.RetireAuditKeyRequest{HostName: hostName})
	if err != nil {
		return err
	}

	tmpDir, certPath, keyPath, err := mintAuditSigningPair(PKIDir(), hostName)
	if err != nil {
		return err
	}
	// The retiring key signs twice and is gone. Removing it is the point, not
	// tidiness: a second live copy of a signing identity for this host is what
	// the whole feature exists to avoid.
	defer os.RemoveAll(tmpDir)

	keyring, err := corrosion.LoadAuditKeyringFromPaths(PKIDir(), certPath, keyPath, hostName)
	if err != nil {
		return fmt.Errorf("load the retirement signing key: %w", err)
	}
	sig, err := keyring.SignLifecycle(hostName, plan.RetiredKeyId, "retired", plan.RetiredAtSeq)
	if err != nil {
		return fmt.Errorf("sign the retirement: %w", err)
	}
	// The certificate minted to END a contract must not stand as a new one, so it
	// retires itself at the same boundary.
	selfSig, err := keyring.SignLifecycle(hostName, keyring.KeyID(), "retired", plan.RetiredAtSeq)
	if err != nil {
		return fmt.Errorf("sign the certificate's own retirement: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read the retirement certificate: %w", err)
	}

	// Phase 2: hand over the certificate and the signatures. The daemon checks
	// both against the cluster CA before recording anything.
	if _, err := c.RetireAuditKey(ctx, &pb.RetireAuditKeyRequest{
		HostName:      hostName,
		CertPem:       string(certPEM),
		Signature:     sig,
		SelfSignature: selfSig,
	}); err != nil {
		return err
	}

	fmt.Printf("Retired %s's audit signing key %s at sequence %d\n",
		hostName, plan.RetiredKeyId, plan.RetiredAtSeq)
	fmt.Println("  rows it signed up to there stay verifiable; the certificate is kept")
	fmt.Println("  rows above that sequence signed by that key are now reported as")
	fmt.Println("  retired-key use on every node")
	fmt.Println("  unsigned rows from this host are no longer treated as evidence")
	fmt.Println("  Confirm with: lv audit verify")
	return nil
}

// mintRetirementCertPaths names the on-disk shape mintAuditSigningPair produces,
// so the retirement and rotation paths cannot drift on where they look.
func mintRetirementCertPaths(dir string) (certPath, keyPath string) {
	return filepath.Join(dir, pki.AuditSigningCertName), filepath.Join(dir, pki.AuditSigningKeyName)
}
