package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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

// auditRotationSettleHint is how long the target's daemon waits for replication
// before recording the rotation. Kept in step with daemon.auditLifecycleSettle by
// TestRotationSettleHintMatchesTheDaemon.
const auditRotationSettleHint = "a minute"

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
	// Future tense, and the delay named. The daemon deliberately waits for
	// replication before recording any of this: adoption and retirement are
	// permanent sequence boundaries, and one taken from a local tail that is
	// behind the cluster condemns rows that were legitimately signed. Claiming it
	// in the past tense — which this command did, twice — sends an operator to
	// `lv audit verify` a second later to find nothing there.
	fmt.Printf("  within about %s the daemon will publish the new certificate, retire the\n",
		auditRotationSettleHint)
	fmt.Println("  previous key at the sequence its chain has reached, and sign a chain head with")
	fmt.Println("  the new key sealing every row the old key wrote — after which altering one")
	fmt.Println("  contradicts a head the holder of the old key cannot forge")
	fmt.Println("  it waits that long on purpose: those are permanent sequence boundaries, and")
	fmt.Println("  taking one before replication has caught up would condemn rows the old key")
	fmt.Println("  legitimately signed, with no way to raise it again")
	fmt.Println("  the retired certificate is kept, so rows it signed stay verifiable")

	// Whether the host will SIGN with the new key is a separate question from
	// whether the rotation completes, and an operator who rotates because a key
	// leaked needs to know the replacement is not yet protecting anything. Read it
	// from the target rather than guessing.
	reportRemoteSigningState(sc, hostName)

	fmt.Printf("  Confirm with: lv audit verify (after ~%s)\n", auditRotationSettleHint)
	return nil
}

// reportRemoteSigningState says whether the rotated host will actually SIGN with
// the new key, read from its own config rather than assumed.
//
// Best-effort: an unreadable config is reported as unknown, never as either
// answer. Claiming "signing is on" when it is off is how the previous version of
// this command closed an incident that was still open.
func reportRemoteSigningState(sc *ssh.Client, hostName string) {
	// No `|| true`. It made the command exit 0 whatever happened, and RunOutput
	// only errors on a non-zero exit and returns stdout alone — so a missing or
	// unreadable config produced err == nil and empty output, which fell through
	// to the "signing is on" branch. An operator closing a key-compromise
	// incident was told the replacement key was protecting rows that were in fact
	// being written unsigned.
	//
	// grep exits 0 when it matches, 1 when it does not, and 2 on an error it
	// could not read past. Only the first two are answers.
	out, err := sc.RunOutput(
		`grep -qE '^[[:space:]]+audit_signature:[[:space:]]*true' /etc/litevirt/config.yaml; echo $?`)
	switch code := strings.TrimSpace(string(out)); {
	case err != nil:
		fmt.Printf("  could not read enforcement.audit_signature on %s (%v); check by hand "+
			"whether rows written there are being signed\n", hostName, err)
	case code == "0":
		fmt.Println("  enforcement.audit_signature is on, so rows written from here are signed with")
		fmt.Println("  the new key")
	case code == "1":
		fmt.Println("  NOTE: enforcement.audit_signature is OFF on this host, so new rows are still")
		fmt.Println("  written UNSIGNED. The rotation sealed what the old key wrote, but the new key")
		fmt.Println("  is not protecting anything yet — enable the flag fleet-wide to change that")
	default:
		fmt.Printf("  could not read enforcement.audit_signature on %s (grep exit %q); check by "+
			"hand whether rows written there are being signed\n", hostName, code)
	}
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
