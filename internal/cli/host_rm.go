package cli

import (
	"context"
	"fmt"
	"log/slog"
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
// Nothing called them.
func HostRemove(ctx context.Context, c pb.LiteVirtClient, hostName string, force bool) error {
	// Read the serial BEFORE the removal: afterwards the row is tombstoned and
	// ListHosts no longer returns it.
	serial := hostCertSerial(ctx, c, hostName)

	if _, err := c.RemoveHost(ctx, &pb.RemoveHostRequest{Name: hostName, Force: force}); err != nil {
		return fmt.Errorf("remove host: %w", err)
	}
	fmt.Printf("Host %s removed from cluster.\n", hostName)

	// Revocation is reported, never silently skipped. It needs the CA private key,
	// which lives in the operator's config directory — so running `lv host rm` from
	// a node that does not hold it leaves the tombstone as the only mechanism, and
	// the operator has to know that.
	if err := revokeHostCert(PKIDir(), hostName, serial); err != nil {
		fmt.Printf("  WARNING: %s's certificate was NOT revoked: %v\n", hostName, err)
		fmt.Println("  its certificate still chains to the cluster CA, so removal now rests")
		fmt.Println("  entirely on the tombstone reaching every node. Re-run this from the")
		fmt.Println("  machine holding ca.key, or distribute an updated crl.pem by hand")
		return nil
	}
	if serial == "" || serial == "unknown" {
		return nil
	}
	fmt.Printf("  revoked certificate %s in %s\n", serial, filepath.Join(PKIDir(), "crl.pem"))
	fmt.Println("  copy that crl.pem to /etc/litevirt/pki/crl.pem on the remaining hosts —")
	fmt.Println("  each daemon reloads it when the file changes, and the health check warns")
	fmt.Println("  for as long as any peer's CRL version is behind another's")
	return nil
}

// hostCertSerial reads a host's certificate serial, best-effort: a removal must not
// be blocked by a lookup, and a missing serial only costs the revocation.
func hostCertSerial(ctx context.Context, c pb.LiteVirtClient, hostName string) string {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		slog.Warn("could not read the host's certificate serial; it cannot be revoked",
			"host", hostName, "error", err)
		return ""
	}
	for _, h := range resp.Hosts {
		if h.Name == hostName {
			return h.CertSerial
		}
	}
	return ""
}

// revokeHostCert appends a removed host's certificate serial to the cluster CRL.
//
// An empty or "unknown" serial is skipped rather than treated as an error — a host
// record written before certificate serials were recorded carries "unknown", and
// that must not turn a successful removal into a failure.
func revokeHostCert(pkiDir, hostName, serial string) error {
	if serial == "" || strings.EqualFold(serial, "unknown") {
		slog.Warn("host has no recorded certificate serial; nothing to revoke", "host", hostName)
		return nil
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
