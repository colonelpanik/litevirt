package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// TestHostInitLocal_CertCoversTheAddressPeersDial.
//
// `lv host init --local` minted a certificate whose only IP SAN was 127.0.0.1, so
// no peer could ever complete a TLS handshake with the first node — it is the one
// address that is guaranteed to mean a different machine to whoever dials it.
//
// That made the documented multi-node path circular. The advice is "use the remote
// form, `lv host init root@<ip>`", but a node cannot init ITSELF remotely (the
// binary push is a same-file copy and fails), so the first host has to be done
// locally, and doing it locally produced a certificate no peer could verify. The
// only way through was to copy the CA to a second node and re-issue node-1's
// certificate from there, which is what the lab needed and what nobody would guess.
func TestHostInitLocal_CertCoversTheAddressPeersDial(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LITEVIRT_PKI_DIR", dir)
	mustCA(t, dir)

	if err := mintLocalHostCert(dir, "node-1", "10.77.0.11"); err != nil {
		t.Fatalf("mintLocalHostCert: %v", err)
	}

	pemBytes, err := os.ReadFile(filepath.Join(dir, "node-1.crt"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("no PEM block in the generated certificate")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var haveCluster, haveLoopback bool
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("10.77.0.11")) {
			haveCluster = true
		}
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			haveLoopback = true
		}
	}
	if !haveCluster {
		t.Fatalf("the certificate's IP SANs are %v, missing the address peers dial\n"+
			"every peer handshake fails with \"certificate is valid for 127.0.0.1, not "+
			"10.77.0.11\", and the first node can never join anything", cert.IPAddresses)
	}
	if !haveLoopback {
		t.Errorf("127.0.0.1 was dropped from the SANs (%v); the on-node CLI dials loopback",
			cert.IPAddresses)
	}
}

// TestHostInitLocal_FallsBackWhenNoAddressGiven — an operator who names no address
// still gets a usable certificate rather than an error.
func TestHostInitLocal_FallsBackWhenNoAddressGiven(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LITEVIRT_PKI_DIR", dir)
	mustCA(t, dir)
	if err := mintLocalHostCert(dir, "node-1", ""); err != nil {
		t.Fatalf("an empty address should fall back to auto-detection, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node-1.crt")); err != nil {
		t.Fatalf("no certificate was written: %v", err)
	}
}

// mustCA gives the temp PKI dir a cluster CA to sign with.
func mustCA(t *testing.T, dir string) {
	t.Helper()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
}

var _ = context.Background
