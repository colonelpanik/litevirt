package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/pki"
)

const (
	maxClusterCRLBytes = 1 << 20
	clusterCRLPageSize = 128
)

// PublishCRL records a CA-signed certificate revocation list so it reaches every
// node the way every other cluster fact does.
//
// The row is keyed by the CRL's hash AND bytes and never updated, so publishing the
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
	if len(crlPEM) > maxClusterCRLBytes {
		return fmt.Errorf("refusing to publish a CRL larger than %d bytes", maxClusterCRLBytes)
	}
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO cluster_crl (id, crl_pem, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, NULL)`,
		crlRowID(crlPEM), crlPEM, c.NowWall(), c.NowTS())
}

// crlRowID is the compact half of the composite primary key.
//
// crl_pem is the other half. The hash alone is not a safe slot: after a CRL has
// been published, its hash is public and a peer can race a garbage row carrying
// that id to a partitioned node. Including the bytes means that row and the
// genuine signed row are distinct facts, so INSERT OR IGNORE cannot turn the
// race winner into a permanent veto.
func crlRowID(crlPEM string) string {
	sum := sha256.Sum256([]byte(crlPEM))
	return hex.EncodeToString(sum[:])
}

// SyncClusterCRL installs the union of every published CRL this node can verify.
//
// It pages through EVERY row and verifies the signed content rather than
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
// Distinct CA-signed CRLs may have equal numbers or incomparable revoked sets.
// Picking one "best" row loses a revocation in both cases. pki.InstallCRLs writes
// one atomic PEM bundle and the mTLS checker enforces the union.
//
// Returns the highest version in a newly installed bundle, or 0 when this node
// was already enforcing the same bundle.
func SyncClusterCRL(ctx context.Context, c *Client, pkiDir string) (int64, error) {
	if err := c.execLocal(ctx, `CREATE TABLE IF NOT EXISTS local_invalid_crls (
		id TEXT PRIMARY KEY
	)`); err != nil {
		return 0, fmt.Errorf("initialize the local CRL verification cache: %w", err)
	}
	var verified [][]byte
	refused := 0
	considered := 0
	err := forEachClusterCRL(ctx, c, func(crl ClusterCRL) error {
		considered++
		if len(crl.PEM) > maxClusterCRLBytes || crl.ID != crlRowID(crl.PEM) {
			refused++
			slog.Error("refusing a published CRL whose row key does not bind its bounded content",
				"row", crl.ID, "bytes", len(crl.PEM))
			return nil
		}
		if crl.KnownInvalid {
			refused++
			return nil
		}
		_, vErr := pki.VerifiedCRLNumber(pkiDir, []byte(crl.PEM))
		if vErr != nil {
			_ = c.execLocal(ctx,
				`INSERT OR IGNORE INTO local_invalid_crls (id) VALUES (?)`, crl.ID)
			// Not fatal and not skipped in silence. Someone published a CRL this node
			// will not accept, which is either a peer that does not hold our CA or an
			// attempt to replace the revocation list with a friendlier one.
			refused++
			slog.Error("refusing a published CRL that does not verify against the cluster CA",
				"row", crl.ID, "error", vErr)
			return nil
		}
		verified = append(verified, []byte(crl.PEM))
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("read the cluster CRL: %w", err)
	}
	if refused > 0 {
		slog.Warn("published CRLs were refused; revocation is decided by the ones that verified",
			"refused", refused, "considered", considered)
	}
	if len(verified) == 0 {
		return 0, nil
	}
	version, installed, err := pki.InstallCRLs(pkiDir, verified)
	if err != nil {
		return 0, fmt.Errorf("install the verified cluster CRLs: %w", err)
	}
	if !installed {
		return 0, nil
	}
	slog.Warn("installed the cluster CRL union", "version", version, "members", len(verified))
	return version, nil
}

// ClusterCRL is one published revocation list.
type ClusterCRL struct {
	ID           string
	PEM          string
	KnownInvalid bool
}

// ClusterCRLs returns published CRLs for diagnostics and tests. Synchronization
// uses forEachClusterCRL so an attacker-writable table is never materialized
// unboundedly in memory.
func ClusterCRLs(ctx context.Context, c *Client) ([]ClusterCRL, error) {
	rows, err := c.Query(ctx,
		`SELECT id, crl_pem FROM cluster_crl
		 WHERE length(crl_pem) <= ?
		 ORDER BY id, crl_pem LIMIT ?`,
		maxClusterCRLBytes, clusterCRLPageSize)
	if err != nil {
		return nil, err
	}
	out := make([]ClusterCRL, 0, len(rows))
	for _, r := range rows {
		out = append(out, ClusterCRL{ID: r.String("id"), PEM: r.String("crl_pem")})
	}
	return out, nil
}

func forEachClusterCRL(ctx context.Context, c *Client, visit func(ClusterCRL) error) error {
	var afterID, afterPEM string
	for {
		rows, err := c.Query(ctx,
			`SELECT c.id, c.crl_pem, CASE WHEN v.id IS NULL THEN 0 ELSE 1 END AS known_invalid
			 FROM cluster_crl c
			 LEFT JOIN local_invalid_crls v ON v.id = c.id
			 WHERE length(crl_pem) <= ?
			   AND (c.id > ? OR (c.id = ? AND c.crl_pem > ?))
			 ORDER BY c.id, c.crl_pem LIMIT ?`,
			maxClusterCRLBytes, afterID, afterID, afterPEM, clusterCRLPageSize)
		if err != nil {
			return err
		}
		for _, r := range rows {
			item := ClusterCRL{
				ID: r.String("id"), PEM: r.String("crl_pem"), KnownInvalid: r.Int("known_invalid") == 1,
			}
			if err := visit(item); err != nil {
				return err
			}
			afterID, afterPEM = item.ID, item.PEM
		}
		if len(rows) < clusterCRLPageSize {
			return nil
		}
	}
}
