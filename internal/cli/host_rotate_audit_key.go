package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// HostRotateAuditKey installs a fresh audit signing pair on one host and
// restarts its daemon.
//
// There is no rotate RPC and none is needed. A host is the only party that
// holds its new private key, so it is the only one that can sign the chain head
// that seals what the old key wrote; the daemon does that itself on the next
// start (corrosion.AdoptAuditKey). This command's whole job is to put
// audit-signing.crt/.key in place and bounce the unit.
//
// It deliberately does NOT touch host.crt/host.key, even though those are what
// an un-rotated host signs with. Three things read the TLS identity and none of
// them would notice a swap: the daemon builds its gRPC serving TLS config once
// at boot (internal/daemon/daemon.go), the health checker caches the client
// config it dials peers with (internal/health/checker.go), and
// internal/pki/libvirt.go symlinks /etc/pki/libvirt/{server,client}{cert,key}.pem
// at those files, which qemu+tls:// follows mid-migration. Replacing the TLS
// identity of a running node is a much larger operation — an operator restoring
// audit integrity must not be gambling with quorum or a live migration.
func HostRotateAuditKey(ctx context.Context, hostName, sshTarget string) error {
	if hostName == "" {
		return fmt.Errorf("host name required")
	}
	if sshTarget == "" {
		// The cert's CN must be the litevirt host name, and in the common case
		// that name is also how you reach the box. --ssh covers the rest.
		sshTarget = "root@" + hostName
	}

	tmpDir, certPath, keyPath, err := mintAuditSigningPair(PKIDir(), hostName)
	if err != nil {
		return err
	}
	// The point of rotation is to reduce the number of copies of the private
	// key, so the CA node keeps none: unlike host_init, nothing is written into
	// PKIDir and the temp dir goes away on return.
	defer os.RemoveAll(tmpDir)

	parsedHost, _, err := parseSSHTarget(sshTarget)
	if err != nil {
		return err
	}
	hostAddr, err := resolveHost(parsedHost)
	if err != nil {
		return err
	}

	slog.Info("pushing audit signing key", "host", hostName, "address", hostAddr)
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	remotePKIDir := "/etc/litevirt/pki"
	if err := sc.Run(fmt.Sprintf("mkdir -p %s", remotePKIDir)); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}

	// 0600 on the KEY, via CopyFileMode. CopyFile defaults to 0644, and that
	// default is exactly how host.key shipped world-readable — a signing key any
	// local user can read makes the tamper-evidence this command exists to
	// restore forgeable again on the spot.
	for _, f := range []struct {
		local, remote string
		mode          os.FileMode
	}{
		{certPath, filepath.Join(remotePKIDir, pki.AuditSigningCertName), 0644},
		{keyPath, filepath.Join(remotePKIDir, pki.AuditSigningKeyName), 0600},
	} {
		if err := sc.CopyFileMode(f.local, f.remote, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(f.remote), err)
		}
	}

	// The keyring is loaded once at boot, so until the daemon restarts the host
	// keeps signing with the key that was just replaced.
	slog.Info("restarting litevirt to adopt the new audit key", "host", hostName)
	if err := sc.Run("systemctl restart litevirt.service"); err != nil {
		return fmt.Errorf("restart litevirt on %s: %w", hostName, err)
	}
	// Type=simple: a successful `restart` only means systemd forked the process.
	// A daemon that dies loading the new keyring — key unreadable, CN not this
	// host — would otherwise read as a clean rotation, with the host silently
	// out of the cluster.
	if err := sc.Run("sleep 3; systemctl is-active --quiet litevirt.service"); err != nil {
		return fmt.Errorf("litevirt is not running on %s after installing the new audit key "+
			"— check `journalctl -u litevirt -n 50` on that host: %w", hostName, err)
	}

	fmt.Printf("Audit signing key rotated for %s (%s)\n", hostName, hostAddr)
	fmt.Printf("  installed %s/%s (0644) and %s (0600)\n",
		remotePKIDir, pki.AuditSigningCertName, pki.AuditSigningKeyName)
	fmt.Println("  host.crt / host.key are unchanged — peer mTLS and qemu+tls:// migration are untouched")
	fmt.Println("  on restart the daemon published the new certificate, retired the previous key at")
	fmt.Println("  the sequence its chain had reached, and signed a chain head with the new key that")
	fmt.Println("  seals every row the old key wrote — altering one now contradicts a head the holder")
	fmt.Println("  of the old key cannot forge")
	fmt.Println("  the retired certificate is kept, so rows it signed stay verifiable")
	fmt.Println("  Confirm with: lv audit verify")
	return nil
}

// mintAuditSigningPair generates a new audit signing pair for hostName into a
// fresh 0700 temp dir, returning the dir so the caller can delete it.
//
// Split out from HostRotateAuditKey so the CA precondition and the shape of the
// minted certificate are testable without an SSH server.
func mintAuditSigningPair(pkiDir, hostName string) (tmpDir, certPath, keyPath string, err error) {
	caCertPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	// Signing a certificate needs the CA PRIVATE key, and there is no CSR flow:
	// a node that does not hold ca.key cannot have anything signed for it, by
	// itself or by anyone else. Fail here rather than after the SSH connect, so
	// the operator learns which machine to run this from before anything on the
	// target has been touched.
	if _, statErr := os.Stat(caKeyPath); statErr != nil {
		return "", "", "", fmt.Errorf("no cluster CA private key at %s: rotation must be run from the "+
			"node that ran `lv host init`, because minting a new signing certificate requires the CA "+
			"private key and litevirt has no CSR flow", caKeyPath)
	}

	tmpDir, err = os.MkdirTemp("", "litevirt-audit-key-")
	if err != nil {
		return "", "", "", fmt.Errorf("create temp dir: %w", err)
	}
	if err := os.Chmod(tmpDir, 0700); err != nil {
		os.RemoveAll(tmpDir)
		return "", "", "", fmt.Errorf("tighten temp dir: %w", err)
	}

	certPath = filepath.Join(tmpDir, pki.AuditSigningCertName)
	keyPath = filepath.Join(tmpDir, pki.AuditSigningKeyName)
	// CN is the litevirt host name because the daemon refuses a keyring whose CN
	// is not its own host name, and the verifier rejects a signature whose
	// certificate names a different host.
	if err := pki.GenerateAuditSigningCert(caCertPath, caKeyPath, certPath, keyPath, hostName); err != nil {
		os.RemoveAll(tmpDir)
		return "", "", "", fmt.Errorf("generate audit signing cert: %w", err)
	}
	return tmpDir, certPath, keyPath, nil
}
