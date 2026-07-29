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
		return err
	}
	d.db.SetAuditKeyring(keyring)
	if err := keyring.PublishSigningKey(ctx, d.db); err != nil {
		// Signing still works; peers just cannot verify until this lands. Worth
		// an error rather than a warning, because a chain nobody else can check
		// is the failure mode this whole design exists to avoid.
		slog.Error("audit signing key could not be published; peers cannot verify this "+
			"host's chain until it is", "error", err)
	}
	slog.Info("audit signing enabled", "host", d.cfg.HostName, "key_id", keyring.KeyID())
	return nil
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
			"unsigned":      res.Unsigned,
		})
		if res.Tampered() {
			// Error, not warn: this is the one finding in the daemon that means
			// someone has altered the record of what happened on this cluster.
			slog.Error("audit chain verification found evidence of tampering",
				"rows", res.RowsChecked, "broken_at", res.BrokenAt,
				"bad_signature", len(res.BadSignature), "unknown_key", len(res.UnknownKeyID),
				"seq_gaps", len(res.SeqGaps), "laundered", len(res.Laundered),
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
