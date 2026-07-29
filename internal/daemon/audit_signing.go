package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

// auditHeadInterval is how often this node republishes its signed chain head.
//
// A head is what makes a truncated tail detectable, so the interval bounds how
// many rows an attacker could remove without leaving a head that contradicts
// them. Five minutes keeps that window small while adding one tiny replicated
// row per node per interval — cheap next to the audit rows themselves.
const auditHeadInterval = 5 * time.Minute

// setupAuditSigning loads this host's signing identity, publishes its
// verification certificate, and starts signing.
//
// Publishing the certificate is not optional bookkeeping: peers hold the
// cluster CA but do not store each other's leaf certificates, so without a
// published copy no other node could check this host's chain — and a host
// checking only its own log is exactly the arrangement a compromised host
// defeats.
func (d *Daemon) setupAuditSigning(ctx context.Context) error {
	keyring, err := corrosion.LoadAuditKeyring(d.cfg.PKIDir, d.cfg.HostName)
	if err != nil {
		// The private key is unreadable, but the CERTIFICATE is public and this
		// host is configured to sign — so publish the certificate anyway. That
		// row is the signing contract, and every unsigned row this host now
		// writes is reported as evidence on every node that reads the log.
		//
		// Publishing nothing is what used to happen, and it is the worst of the
		// three outcomes: the host looks like one that was never meant to sign,
		// so its entire audit log reads as ordinary pre-enforcement history —
		// unsigned, freely rewritable, and clean on every peer. "The key is
		// unreadable" is precisely the state an attacker arranges, so it must not
		// be the state that goes unnoticed.
		if id, perr := corrosion.PublishSigningCertOnly(ctx, d.db, d.cfg.PKIDir, d.cfg.HostName); perr != nil {
			slog.Error("audit signing key could not be loaded AND its certificate could not be "+
				"published; this host's unsigned rows will look like ordinary pre-enforcement "+
				"history to every peer", "error", err, "publish_error", perr)
		} else {
			slog.Error("audit signing key could not be loaded; the certificate is published so "+
				"every row this host writes unsigned is reported as evidence cluster-wide. "+
				"Fix the key, or retire it deliberately with `lv host retire-audit-key`",
				"error", err, "key_id", id)
		}
		if verifier, verr := corrosion.LoadAuditVerifier(d.cfg.PKIDir); verr == nil {
			d.db.SetAuditKeyring(verifier) // can still check everyone else's chain
		}
		return err
	}
	d.db.SetAuditKeyring(keyring)
	adoptAuditKey(ctx, d, keyring)
	slog.Info("audit signing enabled", "host", d.cfg.HostName, "key_id", keyring.KeyID(),
		"dedicated_key", corrosion.UsesDedicatedAuditKey(d.cfg.PKIDir))
	return nil
}

// retireOwnAuditKeyOnRollback records a SIGNED retirement when this host is no
// longer configured to sign but still has a live signing contract.
//
// Turning enforcement.audit_signature off is a supported operator action — the
// docs call the flag a reversible kill switch — but the published certificate is
// a cluster-wide declaration that this host's rows are signed, and a config edit
// on one machine cannot silently revoke it. Left standing, every row the host
// writes afterwards is reported as evidence on every node, permanently, for what
// was a legitimate rollback.
//
// So the rollback signs for itself. That is the whole distinction the verifier
// needs: a host that STOPPED deliberately still holds its key and can say so; a
// host whose key was taken away cannot. Both stop signing, and only one leaves a
// signature explaining it — which is also why an attacker cannot use this to go
// quiet, since producing the retirement means holding the key and publishing a
// permanent, replicated statement of when they stopped.
func (d *Daemon) retireOwnAuditKeyOnRollback(ctx context.Context) {
	keyring, err := corrosion.LoadAuditKeyring(d.cfg.PKIDir, d.cfg.HostName)
	if err != nil {
		// Cannot sign a retirement without the key. That is the case the contract
		// is FOR, so it stays in force and the unsigned rows are reported.
		slog.Warn("enforcement.audit_signature is off but this host's signing key cannot be "+
			"loaded, so its retirement cannot be signed. Its published certificate stays "+
			"live and its unsigned rows are reported as evidence — retire it from the CA "+
			"node with `lv host retire-audit-key`", "host", d.cfg.HostName, "error", err)
		return
	}
	active, ok, err := corrosion.ActiveAuditKeyID(ctx, d.db, keyring, d.cfg.HostName)
	if err != nil {
		slog.Warn("could not check this host's signing contract", "error", err)
		return
	}
	if !ok || active != keyring.KeyID() {
		return // no live contract for the key we hold; nothing to retire
	}
	seq, err := corrosion.HostTailSeq(ctx, d.db, d.cfg.HostName)
	if err != nil {
		slog.Warn("could not read this host's audit tail", "error", err)
		return
	}
	if err := corrosion.RetireAuditKey(ctx, d.db, keyring, d.cfg.HostName, keyring.KeyID(), seq); err != nil {
		slog.Error("could not record this host's audit signing rollback; its unsigned rows "+
			"will be reported as evidence until it is retired", "error", err)
		return
	}
	slog.Warn("enforcement.audit_signature is off: this host's signing key has been RETIRED at "+
		"the sequence its chain had reached. Rows it wrote up to there stay verifiable; rows "+
		"from here on are unsigned and are no longer treated as evidence",
		"host", d.cfg.HostName, "key_id", keyring.KeyID(), "retired_at_seq", seq)
}

// shouldCompleteAuditKeyRotation reports whether a starting daemon must adopt a
// dedicated audit signing pair even though it is not configured to sign.
//
// The pair only gets onto a host one way — `lv host rotate-audit-key` — and that
// command is only run for one reason: a signing key that may be in someone
// else's hands. Gating the adoption on enforcement.audit_signature meant that on
// a default-configured host the rotation did nothing at all while reporting
// success, so the leaked key stayed the only published signing identity.
func shouldCompleteAuditKeyRotation(cfg *Config) bool {
	return !cfg.Enforcement.AuditSignature && corrosion.UsesDedicatedAuditKey(cfg.PKIDir)
}

// completeAuditKeyRotation adopts a dedicated audit signing pair on a host that
// is NOT configured to sign.
//
// `lv host rotate-audit-key` exists to answer a key that may have leaked, and it
// told the operator their old key had been retired and the history it wrote
// sealed. On a host with enforcement.audit_signature off — the default, and the
// state of any cluster that has not opted in — none of that happened: the whole
// adoption path hung off the flag, so the restart published nothing, retired
// nothing and sealed nothing, and the command still exited 0 with the success
// text. An operator rotating because the key was world-readable closed the
// incident on a promise that was not kept.
//
// Adoption is therefore unconditional once the pair is on disk: installing it is
// an explicit operator act, and sealing the superseded key's history is exactly
// what the rotation was for. The flag keeps its meaning — this host still does
// not sign new rows — so the keyring wired onto the client is VERIFY-ONLY.
//
// That also gives a non-enforcing node a working `lv audit verify`, which the
// rotation command tells the operator to run. A node with no keyring at all
// reports every signed row as unverifiable, which is not a confirmation of
// anything.
func (d *Daemon) completeAuditKeyRotation(ctx context.Context) error {
	keyring, err := corrosion.LoadAuditKeyring(d.cfg.PKIDir, d.cfg.HostName)
	if err != nil {
		return err
	}
	verifier, err := corrosion.LoadAuditVerifier(d.cfg.PKIDir)
	if err != nil {
		return err
	}
	d.db.SetAuditKeyring(verifier)
	adoptAuditKey(ctx, d, keyring)
	slog.Warn("adopted a dedicated audit signing key, but enforcement.audit_signature is off: "+
		"the previous key is retired and its history sealed, and NEW rows are still written "+
		"unsigned. Turn the flag on fleet-wide to make them tamper-evident",
		"host", d.cfg.HostName, "key_id", keyring.KeyID())
	return nil
}

// adoptAuditKey publishes the certificate AND completes a rotation if this host
// is now holding a different key than the one it last published.
//
// Doing it in the daemon rather than in a rotate RPC is deliberate: a host is
// the only party that can know which key it actually holds, and the only one
// that can sign the chain head that seals what the superseded key wrote. So
// rotation is "replace the files, restart" with no coordination at all.
func adoptAuditKey(ctx context.Context, d *Daemon, keyring *corrosion.AuditKeyring) {
	if _, err := corrosion.AdoptAuditKey(ctx, d.db, keyring, d.cfg.HostName); err != nil {
		// Signing still works; peers just cannot verify until this lands. Worth
		// an error rather than a warning, because a chain nobody else can check
		// is the failure mode this whole design exists to avoid.
		slog.Error("audit signing key could not be published; peers cannot verify this "+
			"host's chain until it is", "error", err)
	}
}

// runAuditChainHeads periodically publishes this host's signed chain head.
//
// It also publishes once on the way out. A clean shutdown is the moment the
// head is most valuable and most likely to be missed: the daemon has just
// written its last rows, and without a final head those rows sit outside every
// signed assertion until the node comes back.
func (d *Daemon) runAuditChainHeads(ctx context.Context) {
	if !d.cfg.Enforcement.AuditSignature {
		return
	}
	publish := func(reason string) {
		// Detached: the shutdown call runs when ctx is already cancelled, and a
		// head that only gets written while the daemon is still healthy is not
		// much of a shutdown record.
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := corrosion.PublishAuditChainHead(pctx, d.db, d.cfg.HostName); err != nil {
			slog.Warn("could not publish audit chain head", "reason", reason, "error", err)
			return
		}
		metrics.AuditChainHeadPublished()
	}

	// Publish once immediately. Waiting for the first tick leaves every row
	// written since the last head outside any signed assertion, and a node that
	// restarts more often than the interval would never publish at all — the
	// shutdown publish cannot be relied on to win the race against process
	// exit, which is exactly what the lab showed (heads_published_total stayed
	// at 0 across four restarts).
	publish("startup")

	t := time.NewTicker(auditHeadInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			publish("interval")
		case <-ctx.Done():
			publish("shutdown")
			return
		}
	}
}

// auditVerifyInterval is how often the daemon checks its own chain.
//
// Verification has to happen without anyone asking. Tamper-evidence that only
// runs when an operator types `lv audit verify` detects an intrusion whenever
// someone next thinks to look, which in practice is after the incident that
// prompted them — and `litevirt_audit_chain_last_verified_ok` cannot be alerted
// on if nothing sets it.
const auditVerifyInterval = time.Hour

// runAuditChainVerify verifies the audit chain periodically and publishes the
// result as metrics.
//
// It runs whether or not signing is enabled: on an unsigned cluster it still
// catches hash-chain corruption, and it reports how much of the log predates
// tamper-evidence, which is what tells an operator the feature is worth turning
// on.
func (d *Daemon) runAuditChainVerify(ctx context.Context) {
	check := func() {
		vctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		res, err := corrosion.VerifyAuditChain(vctx, d.db)
		if err != nil {
			slog.Warn("audit chain verification failed to run", "error", err)
			return
		}
		metrics.AuditChainVerified(d.cfg.HostName, !res.Tampered(), map[string]int{
			"broken_hash":   boolCount(res.BrokenAt != ""),
			"bad_signature": len(res.BadSignature),
			"unknown_key":   len(res.UnknownKeyID),
			"seq_gap":       len(res.SeqGaps),
			"laundered":     len(res.Laundered),
			"truncated":     len(res.TruncatedHosts),
			"retired_key":   len(res.RetiredKeyUse),
			"head_mismatch": len(res.HeadMismatch),
			"unsigned":      res.Unsigned,
			// Distinct from "unsigned", which is ordinary pre-enforcement
			// history and must stay alertable-on separately: this one is a
			// tamper finding, and it is what a node writing rows it cannot sign
			// leaves behind.
			"unsigned_after_signed": len(res.UnsignedAfterSigned),
		})
		if res.Tampered() {
			// Error, not warn: this is the one finding in the daemon that means
			// someone has altered the record of what happened on this cluster.
			slog.Error("audit chain verification found evidence of tampering",
				"rows", res.RowsChecked, "broken_at", res.BrokenAt,
				"bad_signature", len(res.BadSignature), "unknown_key", len(res.UnknownKeyID),
				"seq_gaps", len(res.SeqGaps), "laundered", len(res.Laundered),
				"retired_key_use", res.RetiredKeyUse, "head_mismatch", res.HeadMismatch,
				"truncated_hosts", res.TruncatedHosts)
		}
	}

	check() // once at startup, so a node that never runs an hour still reports
	t := time.NewTicker(auditVerifyInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			check()
		case <-ctx.Done():
			return
		}
	}
}

func boolCount(b bool) int {
	if b {
		return 1
	}
	return 0
}
