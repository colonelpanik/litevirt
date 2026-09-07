package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// fingerprintLen is how many hex characters of the digest identify a cluster.
// 16 hex chars is 64 bits — far more than enough to separate the handful of
// clusters that could ever share one NetBox, and short enough to read in a
// NetBox custom field.
const fingerprintLen = 16

// ClusterFingerprint returns this installation's stable, unique identity.
//
// It is DERIVED from the replicated cluster CA certificate, not generated. That
// matters in a masterless cluster: every node computes the identical value
// independently with no coordination, so there is no minting race. A generated
// UUID would have one — two nodes minting concurrently, LWW picking a winner,
// and every object written under the loser's value stranded.
//
// It is deliberately NOT cluster.id, which is declared DEFAULT 'default' and is
// therefore the same string in every installation, and NOT the cluster name,
// which an operator chooses and which is not unique.
func ClusterFingerprint(ctx context.Context, c *Client) (string, error) {
	rows, err := c.Query(ctx, `SELECT ca_cert FROM cluster LIMIT 1`)
	if err != nil {
		return "", fmt.Errorf("read cluster ca_cert: %w", err)
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("cluster row not found — cannot derive a cluster fingerprint")
	}
	return fingerprintFromCert(rows[0].String("ca_cert"))
}

// ClusterName returns the operator-chosen cluster name, or "" when the row
// carries none.
//
// It is what an operator RECOGNISES, which is why the NetBox mirror names its
// cluster object after it rather than after the fingerprint: a fingerprint that
// moved would point the mirror at a second, empty NetBox cluster and orphan the
// first. (See EnsureClusterRecord — the fingerprint is minted once and does not
// track `ca.crt`, so replacing the CA is not what moves it.)
//
// It is deliberately NOT an identity. Two installations can share a name, so
// nothing may be SCOPED by it — object identity stays the fingerprint's job.
func ClusterName(ctx context.Context, c *Client) (string, error) {
	rows, err := c.Query(ctx, `SELECT name FROM cluster LIMIT 1`)
	if err != nil {
		return "", fmt.Errorf("read cluster name: %w", err)
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("cluster row not found — cannot read a cluster name")
	}
	return strings.TrimSpace(rows[0].String("name")), nil
}

// fingerprintFromCert is the pure half, so the digest is testable without a DB.
func fingerprintFromCert(caCert string) (string, error) {
	if strings.TrimSpace(caCert) == "" {
		return "", fmt.Errorf("cluster ca_cert is empty — cannot derive a cluster fingerprint")
	}
	sum := sha256.Sum256([]byte(caCert))
	return hex.EncodeToString(sum[:])[:fingerprintLen], nil
}
