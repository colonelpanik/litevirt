package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/pki"
)

// PublishCRL records a CA-signed certificate revocation list so it reaches every
// node the way every other cluster fact does.
//
// The row is keyed by the CRL's own bytes and never updated, so publishing the
// same CRL twice really is a no-op — INSERT OR IGNORE, matching every other
// append-only table here, because a lost response or a copy that replicated in
// from a peer first must not turn a successful publication into an error the
// operator is told to recover from.
//
// Nothing here decides which CRL a node should enforce. That is SyncClusterCRL
// plus pki.InstallCRL, which verify the CA signature before letting any of it
// near the file the mTLS handshake reads.
func PublishCRL(ctx context.Context, c *Client, crlPEM string) error {
	if crlPEM == "" {
		return fmt.Errorf("refusing to publish an empty CRL")
	}
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO cluster_crl (id, crl_pem, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, NULL)`,
		crlRowID(crlPEM), crlPEM, c.NowWall(), c.NowTS())
}

// crlRowID is the primary key: the hash of the CRL itself.
//
// Content-addressed so the key is not a value any writer chooses. A peer can add
// rows, but it cannot occupy the row a future genuine CRL will land in without
// producing that CRL's exact bytes — which needs the cluster CA's private key.
func crlRowID(crlPEM string) string {
	sum := sha256.Sum256([]byte(crlPEM))
	return hex.EncodeToString(sum[:])
}

// SyncClusterCRL installs the newest published CRL this node can verify.
//
// It reads EVERY row and takes the highest number it can verify, rather than
// ordering by anything the table says about itself. Two earlier versions of this
// were wrong in ways worth keeping written down, because both looked safe:
//
//   - Ordering by a `version` column and stopping at the first row that verified.
//     The column is peer-supplied and covered by no signature, so a host about to
//     be removed could re-insert an OLD genuine CRL — one that verifies perfectly
//     — under a huge version, and every node would stop there forever. The
//     operator sees "published CRL N"; no node ever installs N.
//   - Returning as soon as a verifying row turned out not to be newer. That is the
//     same bug in miniature: "already current" is a fact about ONE row, and it was
//     being used to conclude something about all the rows underneath it.
//
// Filtering tombstones was wrong for the same family of reasons and is also gone:
// a peer that sets deleted_at on the row carrying a revocation would hide it from
// any node that had not already installed it. A row here is worth exactly what its
// signature is worth, so deleted_at is ignored — the same rule the audit evidence
// tables use, and the reason their merge floor can be shared with this one.
//
// Returns the version installed, or 0 when this node was already current.
func SyncClusterCRL(ctx context.Context, c *Client, pkiDir string) (int64, error) {
	published, err := ClusterCRLs(ctx, c)
	if err != nil {
		return 0, fmt.Errorf("read the cluster CRL: %w", err)
	}
	var best []byte
	var bestNum int64
	refused := 0
	for _, crl := range published {
		num, vErr := pki.VerifiedCRLNumber(pkiDir, []byte(crl.PEM))
		if vErr != nil {
			// Not fatal and not skipped in silence. Someone published a CRL this node
			// will not accept, which is either a peer that does not hold our CA or an
			// attempt to replace the revocation list with a friendlier one.
			refused++
			slog.Error("refusing a published CRL that does not verify against the cluster CA",
				"row", crl.ID, "error", vErr)
			continue
		}
		if best == nil || num > bestNum {
			best, bestNum = []byte(crl.PEM), num
		}
	}
	if refused > 0 {
		slog.Warn("published CRLs were refused; revocation is decided by the ones that verified",
			"refused", refused, "considered", len(published))
	}
	if best == nil {
		return 0, nil
	}
	version, installed, err := pki.InstallCRL(pkiDir, best)
	if err != nil {
		return 0, fmt.Errorf("install the newest verified CRL: %w", err)
	}
	if !installed {
		return 0, nil
	}
	slog.Warn("installed a newer cluster CRL", "version", version)
	return version, nil
}

// ClusterCRL is one published revocation list.
type ClusterCRL struct {
	ID  string
	PEM string
}

// ClusterCRLs returns every published CRL, tombstoned rows included — see
// SyncClusterCRL for why a tombstone must not be able to hide one.
func ClusterCRLs(ctx context.Context, c *Client) ([]ClusterCRL, error) {
	rows, err := c.Query(ctx, `SELECT id, crl_pem FROM cluster_crl`)
	if err != nil {
		return nil, err
	}
	out := make([]ClusterCRL, 0, len(rows))
	for _, r := range rows {
		out = append(out, ClusterCRL{ID: r.String("id"), PEM: r.String("crl_pem")})
	}
	return out, nil
}
