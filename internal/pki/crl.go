package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
		Number:                    big.NewInt(time.Now().Unix()),
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

	// Load existing revoked serials if CRL exists.
	if entries, err := LoadCRL(crlPath); err == nil {
		existing = entries
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
