package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// HostRemove takes a host out of the cluster and revokes the certificate it holds.
//
// Removal used to be a tombstone and nothing else. The row is soft-deleted, the
// certificate serial is logged, and the certificate itself keeps chaining to the
// cluster CA — so whether a decommissioned node can still act as a peer depends
// entirely on that tombstone reaching every other node. One node that never
// receives it goes on accepting the removed host, and nothing reports the fact.
//
// That was survivable while peer trust required a live host row, because an
// unreplicated row meant "not a peer" anyway. It is not survivable now that trust
// falls back to the certificate for a host with no row — the fallback that lets a
// fresh cluster form. The two changes have to land together: absent means trust the
// certificate, so the certificate has to stop being trustworthy.
//
// The CRL is that second mechanism and every piece of it already existed —
// pki.AppendToCRL, a crl.pem each daemon re-reads when its mtime changes, and a
// health check that publishes every node's CRL version and warns on a mismatch.
// Nothing called them, and nothing carried the CRL between nodes.
//
// It is carried by replication now, like every other cluster fact. Minting it
// still happens here because it has to: revoking a certificate means signing with
// the cluster CA's private key, which lives with the operator and never on a
// daemon. So this command produces the CRL and PublishCRL hands it to the cluster.
func HostRemove(ctx context.Context, c pb.LiteVirtClient, hostName string, force bool) error {
	// Read and revoke BEFORE the tombstone. Once RemoveHost succeeds, ListHosts
	// deliberately hides the row and there is no supported way to recover its
	// certificate serial. A mint or publish failure must therefore leave the row
	// intact so the operator can repair the cause and retry this command.
	serial, err := hostCertSerial(ctx, c, hostName)
	if err != nil {
		return fmt.Errorf("read %s's certificate serial before removal: %w", hostName, err)
	}

	if err := revokeHostCert(PKIDir(), hostName, serial); err != nil {
		return fmt.Errorf("refusing to remove %s before its certificate is revoked: %w", hostName, err)
	}

	version, err := publishClusterCRL(ctx, c, PKIDir())
	if err != nil {
		return fmt.Errorf("refusing to remove %s before its certificate revocation is published: %w",
			hostName, err)
	}

	if _, err := c.RemoveHost(ctx, &pb.RemoveHostRequest{Name: hostName, Force: force}); err != nil {
		return fmt.Errorf("remove host after publishing its certificate revocation: %w", err)
	}
	fmt.Printf("Host %s removed from cluster.\n", hostName)
	fmt.Printf("  revoked certificate %s in CRL %d before removing the host\n", serial, version)
	fmt.Println("  `lv health` warns for as long as any peer's CRL version is behind another's")
	return nil
}

// PublishClusterCRL hands this machine's CRL to the cluster, for `lv host
// publish-crl` — the recovery path when the publish inside `lv host rm` failed.
func PublishClusterCRL(ctx context.Context, c pb.LiteVirtClient) error {
	version, err := publishClusterCRL(ctx, c, PKIDir())
	if err != nil {
		return fmt.Errorf("publish %s to the cluster: %w", filepath.Join(PKIDir(), "crl.pem"), err)
	}
	fmt.Printf("Published CRL %d to the cluster; each daemon installs it within a minute.\n", version)
	fmt.Println("`lv health` warns for as long as any peer's CRL version is behind another's")
	return nil
}

// publishClusterCRL hands the freshly-minted CRL to the cluster to replicate.
func publishClusterCRL(ctx context.Context, c pb.LiteVirtClient, pkiDir string) (int64, error) {
	crlPEM, err := os.ReadFile(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		return 0, fmt.Errorf("read the CRL just written: %w", err)
	}
	resp, err := c.PublishCRL(ctx, &pb.PublishCRLRequest{CrlPem: string(crlPEM)})
	if err != nil {
		return 0, err
	}
	return resp.Version, nil
}

// hostCertSerial reads a host's certificate serial, best-effort: a removal must not
// be blocked by a lookup, and a missing serial only costs the revocation.
func hostCertSerial(ctx context.Context, c pb.LiteVirtClient, hostName string) (string, error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return "", err
	}
	for _, h := range resp.Hosts {
		if h.Name == hostName {
			if h.CertSerial == "" || strings.EqualFold(h.CertSerial, "unknown") {
				return "", fmt.Errorf("host has no recorded certificate serial")
			}
			return h.CertSerial, nil
		}
	}
	return "", fmt.Errorf("host is not present")
}

// revokeHostCert appends a removed host's certificate serial to the cluster CRL.
func revokeHostCert(pkiDir, hostName, serial string) error {
	if serial == "" || strings.EqualFold(serial, "unknown") {
		return fmt.Errorf("host %s has no recorded certificate serial", hostName)
	}
	caCert := filepath.Join(pkiDir, "ca.crt")
	caKey := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caKey); err != nil {
		return fmt.Errorf("no cluster CA private key at %s: revoking a certificate has to be "+
			"signed by the CA, which lives on the machine that ran `lv host init`", caKey)
	}
	if err := pki.AppendToCRL(caCert, caKey, filepath.Join(pkiDir, "crl.pem"), serial); err != nil {
		return fmt.Errorf("append %s to the CRL: %w", serial, err)
	}
	return nil
}
