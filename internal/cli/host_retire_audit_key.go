package cli

import (
	"context"
	"fmt"
	"os"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
//
// --at-seq names the boundary instead of letting the daemon derive it, and is the
// escape hatch for a poisoned chain head. The daemon refuses to retire from a
// replica a signed head says is behind, and it counts heads signed by the key being
// retired on purpose — excluding them is what let a stale replica pin a boundary
// below rows that were legitimately signed. The cost is that whoever holds a leaked
// key can publish one head at any sequence and make retirement refuse everywhere,
// permanently: heads are append-only, tombstones are inert, and anti-entropy
// refuses rewrites, so the claim cannot be withdrawn. That would leave the leaked
// key blocking the command that retires it.
//
// The flag is safe to expose because it grants nothing new. Completing a retirement
// already requires minting a certificate with the cluster CA private key, so the
// only party who can pass --at-seq is the only party who could retire the key at
// all, and both signatures cover the value — a substituted one cannot be replayed.
// It is still the sharpest tool here: set it below what the host really signed and
// those rows are reported as retired-key use on every node, permanently.
// atSeq overrides the boundary the daemon derives, and is nil when --at-seq was not
// given — a pointer rather than a zero sentinel because 0 is a meaningful boundary.
// force permits an atSeq below the boundary the daemon derives, which is the
// unrecoverable direction. See the --at-seq guidance in the doc comment above.
func HostRetireAuditKey(ctx context.Context, c pb.LiteVirtClient, hostName, keyID string, atSeq *int64, force bool) error {
	if hostName == "" {
		return fmt.Errorf("host name required")
	}
	if atSeq != nil && *atSeq < 0 {
		return fmt.Errorf("--at-seq must be a sequence number, not %d", *atSeq)
	}
	if force && atSeq == nil {
		return fmt.Errorf("--force only means anything with --at-seq: it permits a boundary " +
			"below the one the cluster derives, and there is no boundary to permit without one")
	}
	// Phase 1: ask which key would be retired, and at what sequence. Nothing is
	// written by this call.
	//
	// atSeq goes in here too. Phase 1 is where the daemon decides the boundary and
	// where it refuses a lagging replica, so an override that only appeared in phase
	// 2 would be signed over a sequence phase 1 never agreed to — and phase 1 would
	// still refuse before the operator ever got the chance to override it.
	plan, err := c.RetireAuditKey(ctx, &pb.RetireAuditKeyRequest{
		HostName: hostName,
		KeyId:    keyID,
		AtSeq:    atSeq,
		Force:    force,
	})
	if err != nil {
		return err
	}
	if atSeq != nil && plan.RetiredAtSeq != *atSeq {
		return fmt.Errorf("asked to retire at sequence %d but the daemon reports %d; "+
			"the signatures below would not match the boundary it records", *atSeq, plan.RetiredAtSeq)
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
	// The retirement that actually carries standing, signed with the cluster CA key.
	// A lifecycle record is honoured only from the key itself or from the CA, because
	// a signer speaking about someone else's key is how a leaked, already-retired key
	// could retire its own successor and switch a host's tamper-evidence off.
	caSig, err := corrosion.SignLifecycleWithCA(PKIDir(), hostName, plan.RetiredKeyId,
		"retired", plan.RetiredAtSeq)
	if err != nil {
		return fmt.Errorf("sign the retirement with the cluster CA: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read the retirement certificate: %w", err)
	}

	// Phase 2: hand over the certificate and the signatures. The daemon checks
	// both against the cluster CA before recording anything.
	if _, err := c.RetireAuditKey(ctx, &pb.RetireAuditKeyRequest{
		HostName: hostName,
		// Phase 2 re-enters the same handler, so it re-runs the live-key selection
		// and would hit the same "more than one live key" refusal without this.
		// plan.RetiredKeyId, not the caller's flag: phase 1 is what decided, and
		// the signatures below are over that decision.
		KeyId:         plan.RetiredKeyId,
		CertPem:       string(certPEM),
		Signature:     sig,
		SelfSignature: selfSig,
		CaSignature:   caSig,
		AtSeq:         atSeq,
		Force:         force,
	}); err != nil {
		return err
	}

	fmt.Printf("Retired %s's audit signing key %s at sequence %d\n",
		hostName, plan.RetiredKeyId, plan.RetiredAtSeq)
	fmt.Println("  rows it signed up to there stay verifiable; the certificate is kept")
	fmt.Println("  rows above that sequence signed by that key are now reported as")
	fmt.Println("  retired-key use on every node")
	fmt.Println("  unsigned rows from this host are no longer treated as evidence")
	if atSeq != nil {
		fmt.Println("  the boundary was supplied with --at-seq, so neither the sequence the")
		fmt.Println("  cluster derives nor its lagging-replica check applied — if it was set too")
		fmt.Println("  low, the rows above it are reported as retired-key use permanently")
		fmt.Println("  the audit record says so, naming this and the sequence the cluster derived")
	}
	fmt.Println("  Confirm with: lv audit verify")
	return nil
}
