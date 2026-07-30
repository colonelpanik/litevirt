package cli

import (
	"context"
	"fmt"
	"github.com/litevirt/litevirt/internal/netutil"
	"log/slog"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
	"github.com/litevirt/litevirt/internal/systemdunit"
)

var (
	lookupUserByName = osuser.Lookup
	chownPath        = os.Chown
)

// HostInit bootstraps the first host in the cluster.
// 1. Generate CA (if not exists)
// 2. Generate host certificate
// 3. Push CA + host cert + litevirtd binary + setup script via SSH
// 4. Run setup script to install deps and start litevirtd
func HostInit(ctx context.Context, sshTarget string, hostName string) error {
	pkiDir := PKIDir()
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return fmt.Errorf("create PKI dir: %w", err)
	}

	// Parse SSH target to get IP for cert SAN
	parsedHost, _, err := parseSSHTarget(sshTarget)
	if err != nil {
		return err
	}
	hostAddr, err := resolveHost(parsedHost)
	if err != nil {
		return err
	}

	// 1. Generate CA if it doesn't exist
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		slog.Info("generating cluster CA")
		if err := pki.GenerateCA(caPath, caKeyPath); err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
	}

	// 2. Generate CLI client certificate if it doesn't exist
	clientCertPath := filepath.Join(pkiDir, "client.crt")
	clientKeyPath := filepath.Join(pkiDir, "client.key")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("generating CLI client certificate")
		if err := pki.GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}

	// 3. Generate host certificate
	slog.Info("generating host certificate", "host", hostName, "address", hostAddr)
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")

	ip := net.ParseIP(hostAddr)
	if err := pki.GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, hostName, ip); err != nil {
		return fmt.Errorf("generate host cert: %w", err)
	}

	// 4. Push files to host
	slog.Info("pushing files to host", "target", sshTarget)
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	remotePKIDir := "/etc/litevirt/pki"
	if err := sc.Run(fmt.Sprintf("mkdir -p %s", remotePKIDir)); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}

	// The host KEY is 0600. It is the node's entire cluster identity: peer mTLS
	// authenticates with it and audit rows are signed with it, so a local user
	// who can read it can both impersonate the host to every peer and forge its
	// audit history. It shipped 0644 because CopyFile's default mode was
	// invisible at the call site.
	for _, f := range []struct {
		local, remote string
		mode          os.FileMode
	}{
		{caPath, filepath.Join(remotePKIDir, "ca.crt"), 0644},
		{hostCertPath, filepath.Join(remotePKIDir, "host.crt"), 0644},
		{hostKeyPath, filepath.Join(remotePKIDir, "host.key"), 0600},
	} {
		if err := sc.CopyFileMode(f.local, f.remote, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(f.local), err)
		}
	}

	// Push litevirtd binary
	binPath, err := findDaemonBinary()
	if err != nil {
		return fmt.Errorf("find litevirtd binary: %w", err)
	}
	slog.Info("pushing litevirt binary", "path", binPath)
	if err := sc.CopyFile(binPath, "/usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("push litevirt binary: %w", err)
	}
	if err := sc.Run("chmod 755 /usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("chmod litevirt: %w", err)
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := sc.Run("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv"); err != nil {
		return fmt.Errorf("symlink lv: %w", err)
	}

	// 4. Push and run setup script
	slog.Info("running host setup")
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}

	if err := sc.WriteFile("/tmp/litevirt-setup.sh", []byte(setupScript), 0755); err != nil {
		return fmt.Errorf("push setup script: %w", err)
	}

	if err := sc.Run(fmt.Sprintf("HOST_NAME=%s bash /tmp/litevirt-setup.sh", hostName)); err != nil {
		return fmt.Errorf("run setup script: %w", err)
	}

	fmt.Printf("Host %s initialized successfully at %s\n", hostName, hostAddr)
	fmt.Printf("  gRPC endpoint: %s:7443 (mTLS)\n", hostAddr)
	return nil
}

// HostAdd adds a new host to an existing cluster.
func HostAdd(ctx context.Context, sshTarget string, hostName string, joinPeers []string) error {
	// Before anything is generated or pushed, because a failure here must leave the
	// target untouched.
	//
	// The peer list is gathered best-effort by the caller: it asks the local daemon
	// for the current hosts and carries on if that fails. Carrying on means writing
	// `join_peers: []` onto the new node — certificates, binary and a running daemon,
	// and no way to find the cluster — and then reporting success. `add` always has
	// at least one host to join by definition; if it did not, this would be `init`.
	if len(joinPeers) == 0 {
		return fmt.Errorf("no gossip peers to join: could not read the existing cluster's "+
			"hosts, so %s would be provisioned with an empty join_peers and never reach the "+
			"cluster. Check that a daemon is reachable from here (lv host ls), or that this "+
			"is not the first host — the first one is `lv host init`", hostName)
	}
	pkiDir := PKIDir()

	// Verify CA exists
	caPath := filepath.Join(pkiDir, "ca.crt")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		return fmt.Errorf("no cluster CA found — run 'lv host init' first")
	}

	parsedHost, _, err := parseSSHTarget(sshTarget)
	if err != nil {
		return err
	}
	hostAddr, err := resolveHost(parsedHost)
	if err != nil {
		return err
	}

	// Generate CLI client certificate if it doesn't exist
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	clientCertPath := filepath.Join(pkiDir, "client.crt")
	clientKeyPath := filepath.Join(pkiDir, "client.key")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("generating CLI client certificate")
		if err := pki.GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}

	// Generate host certificate
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")

	ip := net.ParseIP(hostAddr)
	if err := pki.GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, hostName, ip); err != nil {
		return fmt.Errorf("generate host cert: %w", err)
	}

	// Push to host
	sc, err := ssh.NewClient(sshTarget)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer sc.Close()

	remotePKIDir := "/etc/litevirt/pki"
	if err := sc.Run(fmt.Sprintf("mkdir -p %s", remotePKIDir)); err != nil {
		return fmt.Errorf("create remote PKI dir: %w", err)
	}

	// The host KEY is 0600. It is the node's entire cluster identity: peer mTLS
	// authenticates with it and audit rows are signed with it, so a local user
	// who can read it can both impersonate the host to every peer and forge its
	// audit history. It shipped 0644 because CopyFile's default mode was
	// invisible at the call site.
	for _, f := range []struct {
		local, remote string
		mode          os.FileMode
	}{
		{caPath, filepath.Join(remotePKIDir, "ca.crt"), 0644},
		{hostCertPath, filepath.Join(remotePKIDir, "host.crt"), 0644},
		{hostKeyPath, filepath.Join(remotePKIDir, "host.key"), 0600},
	} {
		if err := sc.CopyFileMode(f.local, f.remote, f.mode); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(f.local), err)
		}
	}

	// Push litevirtd binary
	binPath, err := findDaemonBinary()
	if err != nil {
		return fmt.Errorf("find litevirtd binary: %w", err)
	}
	slog.Info("pushing litevirt binary", "path", binPath)
	if err := sc.CopyFile(binPath, "/usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("push litevirt binary: %w", err)
	}
	if err := sc.Run("chmod 755 /usr/local/bin/litevirt"); err != nil {
		return fmt.Errorf("chmod litevirt: %w", err)
	}
	// `lv` stays available as a convenience symlink to the combined binary.
	if err := sc.Run("ln -sf /usr/local/bin/litevirt /usr/local/bin/lv"); err != nil {
		return fmt.Errorf("symlink lv: %w", err)
	}

	// Run setup
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}
	if err := sc.WriteFile("/tmp/litevirt-setup.sh", []byte(setupScript), 0755); err != nil {
		return fmt.Errorf("push setup script: %w", err)
	}
	// Format join_peers as YAML array, e.g. ["10.0.50.10:7946","10.0.50.11:7946"]
	peersYAML := "[]"
	if len(joinPeers) > 0 {
		peersYAML = "["
		for i, p := range joinPeers {
			if i > 0 {
				peersYAML += ","
			}
			peersYAML += fmt.Sprintf("%q", p)
		}
		peersYAML += "]"
	}

	// hostAddr is the address this command just put in the certificate SAN and the
	// address peers were told to dial, so it is also the address the node must
	// advertise. Leaving the daemon to auto-detect meant it registered with its
	// default-route source IP — a different interface on a multi-homed host — and
	// that value was then copied into the join_peers of every host added after it.
	if err := sc.Run(fmt.Sprintf("%s bash /tmp/litevirt-setup.sh",
		strings.Join(setupScriptEnv(hostName, hostAddr, peersYAML), " "))); err != nil {
		return fmt.Errorf("run setup script: %w", err)
	}

	// Ensure the new host is listed as a gossip peer in the local daemon config.
	// This is a best-effort update — the daemon needs a restart to pick it up,
	// but memberlist may also discover the peer via existing gossip members.
	if err := ensureLocalPeer(hostAddr, 7946); err != nil {
		slog.Warn("could not update local config with new peer", "error", err)
	}

	fmt.Printf("Host %s added to cluster at %s\n", hostName, hostAddr)
	return nil
}

// ensureLocalPeer adds a gossip peer address to the local daemon config if not already present.
func ensureLocalPeer(addr string, gossipPort int) error {
	cfgPath := "/etc/litevirt/config.yaml"
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	peerAddr := fmt.Sprintf("%s:%d", addr, gossipPort)

	// Get existing peers.
	var peers []string
	if raw, ok := cfg["join_peers"]; ok && raw != nil {
		if list, ok := raw.([]interface{}); ok {
			for _, p := range list {
				if s, ok := p.(string); ok {
					if s == peerAddr {
						return nil // already present
					}
					peers = append(peers, s)
				}
			}
		}
	}

	peers = append(peers, peerAddr)
	cfg["join_peers"] = peers

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, out, 0644)
}

// findDaemonBinary locates the litevirt binary to distribute. Since the CLI
// and daemon are now one binary, the running executable is itself a valid
// candidate — but prefer a sibling/installed `litevirt` so a freshly-built
// bin/litevirt is picked up during dev.
func findDaemonBinary() (string, error) {
	self, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(self), "litevirt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Check common install paths.
	for _, p := range []string{"/usr/local/bin/litevirt", "/usr/bin/litevirt"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// The running binary is itself the combined litevirt binary.
	if self != "" {
		return self, nil
	}
	return "", fmt.Errorf("litevirt binary not found — build it first or place it next to the running binary")
}

// HostInitLocal bootstraps litevirt on the local machine (no SSH).
// Intended for single-node standalone setups.
// mintLocalHostCert issues the first host's certificate, covering the address
// PEERS will dial as well as loopback.
//
// It used to pass 127.0.0.1 alone, which is the one address guaranteed to mean a
// different machine to whoever dials it — so no peer could ever complete a
// handshake with the first node, and the documented advice ("use the remote form")
// is circular, because a node cannot init itself remotely. The only way through
// was copying the CA to a second node and re-issuing the first node's certificate
// from there.
//
// addr empty falls back to the default-route source IP. That is the wrong answer
// on a multi-homed host, which is exactly why --address exists: on a box whose
// cluster network is not the default route, the operator has to say so, and the
// same value belongs in advertise_address.
func mintLocalHostCert(pkiDir, hostName, addr string) error {
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if addr == "" {
		addr = netutil.OutboundIP()
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		// Not an IP (a name, or nothing detectable). GenerateHostCert always adds
		// loopback and the DNS name, so this stays usable for a single-node install
		// while still being honest in the log about what peers will and will not
		// be able to verify.
		slog.Warn("no usable IP address for this host's certificate; peers dialling it by "+
			"address will fail TLS verification. Pass --address <ip>", "host", hostName, "addr", addr)
	}
	slog.Info("generating host certificate", "host", hostName, "address", addr)
	return pki.GenerateHostCert(caPath, caKeyPath,
		filepath.Join(pkiDir, hostName+".crt"), filepath.Join(pkiDir, hostName+".key"),
		hostName, ip)
}

func HostInitLocal(ctx context.Context, hostName, advertiseAddr string) error {
	pkiDir := PKIDir()
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return fmt.Errorf("create PKI dir: %w", err)
	}

	// 1. Generate CA if it doesn't exist
	caPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		slog.Info("generating cluster CA")
		if err := pki.GenerateCA(caPath, caKeyPath); err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
	}

	// 2. Generate CLI client certificate if it doesn't exist.
	clientCertPath := filepath.Join(pkiDir, "client.crt")
	clientKeyPath := filepath.Join(pkiDir, "client.key")
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		slog.Info("generating CLI client certificate")
		if err := pki.GenerateClientCert(caPath, caKeyPath, clientCertPath, clientKeyPath, "lv-cli"); err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}

	// 3. Generate the host certificate.
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")
	if err := mintLocalHostCert(pkiDir, hostName, advertiseAddr); err != nil {
		return err
	}

	// 4. Copy daemon certs to system PKI dir. The daemon host key stays
	// root-owned; the user CLI gets a separate client certificate below.
	remotePKIDir := "/etc/litevirt/pki"
	if err := os.MkdirAll(remotePKIDir, 0700); err != nil {
		return fmt.Errorf("create system PKI dir: %w", err)
	}
	for src, dst := range map[string]string{
		caPath:       filepath.Join(remotePKIDir, "ca.crt"),
		hostCertPath: filepath.Join(remotePKIDir, "host.crt"),
		hostKeyPath:  filepath.Join(remotePKIDir, "host.key"),
	} {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", filepath.Base(src), err)
		}
		if err := os.WriteFile(dst, data, 0600); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(dst), err)
		}
		// WriteFile only applies its mode when it CREATES the file, so a
		// re-init over an existing loose-permissioned key would silently keep
		// the old mode.
		if err := os.Chmod(dst, 0600); err != nil {
			return fmt.Errorf("chmod %s: %w", filepath.Base(dst), err)
		}
	}

	if err := installLocalCLIClientBundle(pkiDir); err != nil {
		return err
	}

	// 5. Run setup script locally
	slog.Info("running local host setup")
	setupScript, err := getSetupScript()
	if err != nil {
		return fmt.Errorf("read setup script: %w", err)
	}

	scriptPath := "/tmp/litevirt-setup.sh"
	if err := os.WriteFile(scriptPath, []byte(setupScript), 0755); err != nil {
		return fmt.Errorf("write setup script: %w", err)
	}

	cmd := execCommand("bash", scriptPath)
	cmd.Env = append(os.Environ(), setupScriptEnv(hostName, advertiseAddr, "[]")...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setup script failed: %w", err)
	}

	fmt.Printf("Host %s initialized locally\n", hostName)
	fmt.Println("  Start the daemon: systemctl enable --now litevirt.service")
	fmt.Println("  Or run directly:  litevirt daemon")
	return nil
}

type cliPKITarget struct {
	dir   string
	uid   int
	gid   int
	chown bool
}

func installLocalCLIClientBundle(srcPKIDir string) error {
	targets, err := localCLIClientPKITargets()
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := installCLIClientBundle(srcPKIDir, target); err != nil {
			return err
		}
	}
	return nil
}

func localCLIClientPKITargets() ([]cliPKITarget, error) {
	targets := []cliPKITarget{{dir: PKIDir()}}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" || sudoUser == "root" {
		return targets, nil
	}

	u, err := lookupUserByName(sudoUser)
	if err != nil {
		return nil, fmt.Errorf("resolve sudo user %q for CLI cert install: %w", sudoUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("parse uid for sudo user %q: %w", sudoUser, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("parse gid for sudo user %q: %w", sudoUser, err)
	}

	sudoTarget := cliPKITarget{
		dir:   filepath.Join(u.HomeDir, ".config", "litevirt", "pki"),
		uid:   uid,
		gid:   gid,
		chown: true,
	}

	if os.Getenv("LV_CONFIG_DIR") != "" {
		targets[0].uid = uid
		targets[0].gid = gid
		targets[0].chown = true
	}
	if filepath.Clean(sudoTarget.dir) != filepath.Clean(targets[0].dir) {
		targets = append(targets, sudoTarget)
	}

	return targets, nil
}

func installCLIClientBundle(srcPKIDir string, target cliPKITarget) error {
	if err := os.MkdirAll(target.dir, 0700); err != nil {
		return fmt.Errorf("create CLI PKI dir %s: %w", target.dir, err)
	}
	files := []struct {
		name string
		mode os.FileMode
	}{
		{name: "ca.crt", mode: 0644},
		{name: "client.crt", mode: 0644},
		{name: "client.key", mode: 0600},
	}
	for _, file := range files {
		src := filepath.Join(srcPKIDir, file.name)
		dst := filepath.Join(target.dir, file.name)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read CLI %s: %w", file.name, err)
		}
		if err := os.WriteFile(dst, data, file.mode); err != nil {
			return fmt.Errorf("write CLI %s: %w", file.name, err)
		}
		if target.chown {
			if err := chownPath(dst, target.uid, target.gid); err != nil {
				return fmt.Errorf("chown CLI %s: %w", file.name, err)
			}
		}
	}
	if target.chown {
		if err := chownPath(target.dir, target.uid, target.gid); err != nil {
			return fmt.Errorf("chown CLI PKI dir %s: %w", target.dir, err)
		}
	}
	return nil
}

// execCommand wraps exec.Command for testability.
var execCommand = execCommandImpl

func execCommandImpl(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

func parseSSHTarget(target string) (host string, user string, err error) {
	// Parse "user@host" or "user@host:port"
	user = "root"
	host = target
	for i, c := range target {
		if c == '@' {
			user = target[:i]
			host = target[i+1:]
			break
		}
	}
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid SSH target: %s", target)
	}
	return host, user, nil
}

// resolveHost resolves a hostname to an IP address for use in cert SANs.
func resolveHost(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("resolve host %q: %v", host, err)
	}
	return addrs[0], nil
}

// setupScriptEnv is the environment the setup script reads to write the daemon
// config. One place, so the local and remote paths cannot disagree about it —
// they already had, which is how the local path shipped with no advertise_address.
func setupScriptEnv(hostName, advertiseAddr, joinPeers string) []string {
	return []string{
		"HOST_NAME=" + hostName,
		// The address that just went into the certificate SAN. Without it the daemon
		// auto-detects, registers with its default-route source IP — the wrong
		// interface on a multi-homed host — and the operator has to notice and
		// correct it, which needed a genuine RESTART, because init leaves the daemon
		// running and `systemctl start` is then a no-op.
		"ADVERTISE_ADDRESS=" + advertiseAddr,
		"JOIN_PEERS=" + joinPeers,
		"PCI_RESCAN_INTERVAL=0",
		"PCI_UDEV_HOOK=false",
		"SRIOV_MANAGED=false",
		"SRIOV_MAX_VFS=8",
	}
}

func getSetupScript() (string, error) {
	// Try to read from embedded or local path
	// For now, return the script inline
	return setupScriptContent, nil
}

const setupScriptContent = `#!/bin/bash
set -euo pipefail

echo "=== litevirt host setup ==="

# Install dependencies (skip apt-get update to avoid unrelated repo errors).
if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq qemu-system-x86 qemu-utils libvirt-daemon-system \
        genisoimage bridge-utils haproxy keepalived 2>/dev/null || {
        echo "Some packages may be missing. Trying apt-get update first..."
        apt-get update -qq -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=/dev/null 2>/dev/null || true
        apt-get install -y -qq qemu-system-x86 libvirt-daemon-system \
            genisoimage bridge-utils haproxy keepalived
    }
elif command -v dnf &>/dev/null; then
    dnf install -y qemu-kvm-core libvirt-daemon-kvm \
        genisoimage bridge-utils haproxy keepalived
fi

# Enable libvirtd with TLS for migration (port 16514).
# Uses systemd socket activation — enable libvirtd-tls.socket alongside
# the default sockets. Cert symlinks are created by litevirtd on startup
# (pki.SetupLibvirtTLS), but we also create them here for first boot.
sed -i 's/^#\?listen_tls.*/listen_tls = 1/' /etc/libvirt/libvirtd.conf
mkdir -p /etc/pki/CA /etc/pki/libvirt/private
ln -sf /etc/litevirt/pki/ca.crt /etc/pki/CA/cacert.pem
ln -sf /etc/litevirt/pki/host.crt /etc/pki/libvirt/servercert.pem
ln -sf /etc/litevirt/pki/host.key /etc/pki/libvirt/private/serverkey.pem
ln -sf /etc/litevirt/pki/host.crt /etc/pki/libvirt/clientcert.pem
ln -sf /etc/litevirt/pki/host.key /etc/pki/libvirt/private/clientkey.pem
systemctl enable libvirtd-tls.socket
# Full restart: stop everything, start sockets (including TLS), let service auto-start.
systemctl stop libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket 2>/dev/null
systemctl reset-failed libvirtd 2>/dev/null
sleep 1
systemctl start libvirtd-tls.socket libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket
echo "Enabled libvirtd TLS (port 16514)"

# Create litevirt directories
mkdir -p /var/lib/litevirt/{images,disks,cloudinit}
mkdir -p /etc/litevirt

# Libvirt storage pools are auto-created by litevirtd on startup
# (from storage_pools config or a default local pool).

# Configure AppArmor to allow QEMU access to litevirt paths (Ubuntu/Debian).
if [ -d /etc/apparmor.d ] && command -v apparmor_parser &>/dev/null; then
    mkdir -p /etc/apparmor.d/local/abstractions
    if [ ! -f /etc/apparmor.d/local/abstractions/libvirt-qemu ] || \
       ! grep -q '/var/lib/litevirt' /etc/apparmor.d/local/abstractions/libvirt-qemu; then
        echo '/var/lib/litevirt/** rwk,' >> /etc/apparmor.d/local/abstractions/libvirt-qemu
        echo "AppArmor: added litevirt path to libvirt-qemu profile"
        systemctl reload apparmor 2>/dev/null || apparmor_parser -r /etc/apparmor.d/libvirt/TEMPLATE.qemu 2>/dev/null || true
    fi
fi

# Write litevirtd config
cat > /etc/litevirt/config.yaml << CONF
host_name: "${HOST_NAME}"
grpc_port: 7443
metrics_port: 7444
gossip_port: 7946
pki_dir: /etc/litevirt/pki
data_dir: /var/lib/litevirt
${ADVERTISE_ADDRESS:+advertise_address: "${ADVERTISE_ADDRESS}"}
join_peers: ${JOIN_PEERS:-[]}
pci:
  rescan_interval: "${PCI_RESCAN_INTERVAL:-0}"
  udev_hook: ${PCI_UDEV_HOOK:-false}
  sriov:
    managed: ${SRIOV_MANAGED:-false}
    max_vfs_per_pf: ${SRIOV_MAX_VFS:-8}
CONF

# pci.udev_hook is deprecated: real-time PCI events are covered by
# pci.rescan_interval, and the old curl-to-REST udev rule was unreliable. This
# installer no longer writes a udev rule; the daemon warns if the flag is set.

# Load vfio-pci kernel module (needed for PCI passthrough).
modprobe vfio-pci 2>/dev/null || true

# Install the systemd units. The text comes from internal/systemdunit so this
# script and the upgrade path cannot disagree; they previously drifted, leaving
# this copy with a tight start limit and a rollback with NO sentinel gate.
cat > ` + systemdunit.MainPath + ` << 'UNIT'
` + systemdunit.Main + `UNIT

cat > ` + systemdunit.RollbackPath + ` << 'UNIT'
` + systemdunit.Rollback + `UNIT

mkdir -p "$(dirname ` + systemdunit.NeedrestartPath + `)"
cat > ` + systemdunit.NeedrestartPath + ` << 'DROPIN'
` + systemdunit.Needrestart + `DROPIN
systemctl daemon-reload
systemctl enable litevirt.service
systemctl restart litevirt.service

echo "=== litevirt setup complete ==="
`
