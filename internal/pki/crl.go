package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"crypto/rand"
)

// GenerateCRL creates or updates a CRL file, revoking the given serial numbers.
// The CRL is signed by the CA at caCertPath/caKeyPath.
func GenerateCRL(caCertPath, caKeyPath, crlPath string, revokedSerials []string) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA for CRL: %w", err)
	}

	var revoked []pkix.RevokedCertificate
	for _, s := range revokedSerials {
		serial := new(big.Int)
		serial.SetString(s, 16)
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		})
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: toRevocationEntries(revoked),
		Number:                    big.NewInt(nextCRLNumber(crlPath)),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(365 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}

	return writePEM(crlPath, "X509 CRL", crlDER)
}

// AppendToCRL adds a serial number to an existing CRL, or creates a new one.
func AppendToCRL(caCertPath, caKeyPath, crlPath, serial string) error {
	var existing []string

	// An ABSENT CRL is the first revocation and starts an empty list. An
	// unreadable or corrupt one is not the same thing and must not be treated as
	// empty: the result would be a CRL numbered now — higher than the cluster's —
	// that revokes only this serial, and once that replicates, every host revoked
	// before it is accepted again on every node. InstallCRL refuses such a CRL on
	// the receiving side; refusing to MINT it is the half that keeps the operator
	// from being told the revocation succeeded.
	entries, err := LoadCRL(crlPath)
	switch {
	case err == nil:
		existing = entries
	case errors.Is(err, os.ErrNotExist):
		// no CRL yet — this is the first revocation
	default:
		return fmt.Errorf("refusing to rebuild the CRL from an unreadable %s (%w): a CRL minted "+
			"without the serials already in it would un-revoke every host revoked so far. Restore "+
			"that file, or delete it deliberately if this cluster has never revoked anything",
			crlPath, err)
	}

	// Check for duplicates.
	for _, s := range existing {
		if s == serial {
			return nil // already revoked
		}
	}

	existing = append(existing, serial)
	return GenerateCRL(caCertPath, caKeyPath, crlPath, existing)
}

// LoadCRL reads a CRL file and returns the revoked serial numbers as hex strings.
func LoadCRL(crlPath string) ([]string, error) {
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in CRL")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	var serials []string
	for _, entry := range crl.RevokedCertificateEntries {
		serials = append(serials, entry.SerialNumber.Text(16))
	}
	return serials, nil
}

// IsCertRevoked checks if a certificate serial is in the CRL.
func IsCertRevoked(pkiDir string, serial *big.Int) bool {
	crlPath := filepath.Join(pkiDir, "crl.pem")
	serials, err := LoadCRL(crlPath)
	if err != nil {
		return false // no CRL or unreadable — not revoked
	}
	target := serial.Text(16)
	for _, s := range serials {
		if s == target {
			return true
		}
	}
	return false
}

// nextCRLNumber picks a CRL number strictly greater than the one already in the
// file. The number is a wall-clock second, which is fine for a human revoking a
// host and wrong for anything faster: two revocations inside the same second
// produce the same number, and every reader of a replicated CRL decides whether
// to install by comparing numbers. Two removals in quick succession would leave
// half the cluster enforcing the first CRL and calling the second a duplicate.
func nextCRLNumber(crlPath string) int64 {
	n := time.Now().Unix()
	if prev := CRLVersion(crlPath); prev >= n {
		n = prev + 1
	}
	return n
}

// verifyCRL parses a CRL and checks it against the cluster CA in pkiDir.
//
// Nothing downstream may look at a CRL's contents before this returns, and that
// includes its number: the number is the value every reader orders by, so taking
// it from an unverified parse is how an attacker gets to choose the ordering.
func verifyCRL(pkiDir string, crlPEM []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in CRL")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	caCert, err := loadCert(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("load cluster CA to verify the CRL: %w", err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("CRL does not verify against the cluster CA: %w", err)
	}
	if crl.Number == nil {
		return nil, fmt.Errorf("CRL carries no number, so it cannot be ordered against the local one")
	}
	return crl, nil
}

// VerifiedCRLNumber returns a CRL's number, but only once its signature has been
// checked against the cluster CA. Callers ordering several candidate CRLs use this
// rather than parsing the number themselves, so an unsigned blob can never take
// part in the ordering.
func VerifiedCRLNumber(pkiDir string, crlPEM []byte) (int64, error) {
	crl, err := verifyCRL(pkiDir, crlPEM)
	if err != nil {
		return 0, err
	}
	return crl.Number.Int64(), nil
}

// InstallCRL verifies a CA-signed CRL and writes it into pkiDir, but only if it
// revokes more recently than the CRL already there AND revokes everything that
// one did.
//
// This is the receiving half of cluster CRL distribution. It is deliberately
// paranoid about what it accepts and deliberately relaxed about what it does
// with it: the CRL arrives over replication, so any peer can put bytes in front
// of it, and only the cluster CA's signature makes them mean anything. A CRL
// that does not verify is refused outright rather than installed and ignored
// later — the file on disk is what the mTLS checker enforces, and overwriting a
// good CRL with a forged one is how an attacker would UN-revoke themselves.
//
// The superset rule is the second half of that, and it does not need an attacker
// at all. A CRL is minted by appending one serial to whatever crl.pem the CA
// machine happens to hold, and AppendToCRL treats an unreadable file as an empty
// one — so a CA host whose crl.pem was deleted, restored from an old backup, or
// never copied alongside ca.key mints a CRL containing ONE serial, numbered now
// and therefore higher than the cluster's. Without this check every node installs
// it and every previously revoked certificate starts working again, cluster-wide,
// while the command reports success. A newer CRL that revokes LESS is refused as
// the mistake it almost always is.
//
// Returns the incoming CRL's number — verified, so it can be trusted to order
// this CRL against any other — and whether this call wrote it.
func InstallCRL(pkiDir string, crlPEM []byte) (int64, bool, error) {
	crl, err := verifyCRL(pkiDir, crlPEM)
	if err != nil {
		return 0, false, err
	}

	crlPath := filepath.Join(pkiDir, "crl.pem")
	incoming := crl.Number.Int64()
	if local := CRLVersion(crlPath); local >= incoming {
		return incoming, false, nil
	}
	if missing := serialsMissingFrom(crl, crlPath); len(missing) > 0 {
		return incoming, false, fmt.Errorf(
			"refusing CRL %d: it is newer than the local CRL but does not revoke %d serial(s) the "+
				"local one does (%v). Installing it would un-revoke them on this node and, once it "+
				"replicates, on every other. This is what minting a CRL from a lost or stale crl.pem "+
				"looks like — re-mint from a crl.pem that has the cluster's full history",
			incoming, len(missing), missing)
	}

	// Write through a temporary file: the mTLS checker reloads on mtime change and
	// must never observe a half-written CRL, which it would read as "unparseable →
	// enforce nothing" and cache until the next write.
	//
	// A UNIQUE temporary name, because two goroutines install concurrently — the
	// PublishCRL RPC and the periodic cluster sync. On one fixed name they can
	// interleave so that one renames the file the other is still writing, and the
	// truncated result is exactly the "enforce nothing" state above.
	tmp, err := os.CreateTemp(pkiDir, "crl-*.pem.tmp")
	if err != nil {
		return 0, false, fmt.Errorf("create a temporary file for the CRL: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(crlPEM); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("write CRL: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("write CRL: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("set CRL permissions: %w", err)
	}
	if err := os.Rename(tmpName, crlPath); err != nil {
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("install CRL: %w", err)
	}
	return incoming, true, nil
}

// serialsMissingFrom returns the serials the local CRL revokes that the incoming
// one does not. An unreadable or absent local CRL revokes nothing, so nothing can
// be missing from its successor — the first CRL a node ever installs is not
// obstructed by this.
func serialsMissingFrom(incoming *x509.RevocationList, localPath string) []string {
	local, err := LoadCRL(localPath)
	if err != nil {
		return nil
	}
	have := make(map[string]bool, len(incoming.RevokedCertificateEntries))
	for _, e := range incoming.RevokedCertificateEntries {
		have[e.SerialNumber.Text(16)] = true
	}
	var missing []string
	for _, s := range local {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	return missing
}

// CRLVersion returns the CRL number (version) from a CRL file, or 0 if not found.
// Used to detect CRL version mismatches between hosts for gossip-based distribution (#49).
func CRLVersion(crlPath string) int64 {
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return 0
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return 0
	}
	if crl.Number != nil {
		return crl.Number.Int64()
	}
	return 0
}

func toRevocationEntries(revoked []pkix.RevokedCertificate) []x509.RevocationListEntry {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   r.SerialNumber,
			RevocationTime: r.RevocationTime,
		}
	}
	return entries
}
