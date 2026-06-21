package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
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

	filesToPush := map[string]string{
		caPath:       filepath.Join(remotePKIDir, "ca.crt"),
		hostCertPath: filepath.Join(remotePKIDir, "host.crt"),
		hostKeyPath:  filepath.Join(remotePKIDir, "host.key"),
	}
	for local, remote := range filesToPush {
		if err := sc.CopyFile(local, remote); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(local), err)
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

	filesToPush := map[string]string{
		caPath:       filepath.Join(remotePKIDir, "ca.crt"),
		hostCertPath: filepath.Join(remotePKIDir, "host.crt"),
		hostKeyPath:  filepath.Join(remotePKIDir, "host.key"),
	}
	for local, remote := range filesToPush {
		if err := sc.CopyFile(local, remote); err != nil {
			return fmt.Errorf("push %s: %w", filepath.Base(local), err)
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

	if err := sc.Run(fmt.Sprintf("HOST_NAME=%s JOIN_PEERS='%s' bash /tmp/litevirt-setup.sh", hostName, peersYAML)); err != nil {
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
func HostInitLocal(ctx context.Context, hostName string) error {
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

	// 2. Generate host certificate with 127.0.0.1 + outbound IP as SANs
	slog.Info("generating host certificate", "host", hostName)
	hostCertPath := filepath.Join(pkiDir, hostName+".crt")
	hostKeyPath := filepath.Join(pkiDir, hostName+".key")

	if err := pki.GenerateHostCert(caPath, caKeyPath, hostCertPath, hostKeyPath, hostName, net.ParseIP("127.0.0.1")); err != nil {
		return fmt.Errorf("generate host cert: %w", err)
	}

	// 3. Copy certs to system PKI dir
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
	}

	// 4. Run setup script locally
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
	cmd.Env = append(os.Environ(),
		"HOST_NAME="+hostName,
		"JOIN_PEERS=[]",
		"PCI_RESCAN_INTERVAL=0",
		"PCI_UDEV_HOOK=false",
		"SRIOV_MANAGED=false",
		"SRIOV_MAX_VFS=8",
	)
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
join_peers: ${JOIN_PEERS:-[]}
pci:
  rescan_interval: "${PCI_RESCAN_INTERVAL:-0}"
  udev_hook: ${PCI_UDEV_HOOK:-false}
  sriov:
    managed: ${SRIOV_MANAGED:-false}
    max_vfs_per_pf: ${SRIOV_MAX_VFS:-8}
CONF

# Install udev rule for PCI hot-plug events (if enabled).
if [ "${PCI_UDEV_HOOK:-false}" = "true" ]; then
    echo "Installing litevirt PCI udev rule"
    cat > /etc/udev/rules.d/99-litevirt-pci.rules << 'UDEV'
# litevirt: notify daemon on PCI device add/remove events.
# This triggers a rescan so the device inventory stays current.
ACTION=="add", SUBSYSTEM=="pci", RUN+="/usr/bin/curl -s -X POST http://127.0.0.1:7446/api/v1/hosts/rescan || true"
ACTION=="remove", SUBSYSTEM=="pci", RUN+="/usr/bin/curl -s -X POST http://127.0.0.1:7446/api/v1/hosts/rescan || true"
UDEV
    udevadm control --reload-rules
    echo "udev rule installed at /etc/udev/rules.d/99-litevirt-pci.rules"
fi

# Load vfio-pci kernel module (needed for PCI passthrough).
modprobe vfio-pci 2>/dev/null || true

# Install systemd unit file for litevirtd.
# Mirror of internal/grpcapi/upgrade.go's litevirtdUnit + rollback unit —
# both should drift together.
cat > /etc/systemd/system/litevirt.service << 'UNIT'
[Unit]
Description=litevirt daemon
After=network-online.target libvirtd.service
Wants=network-online.target
Wants=libvirtd.service
StartLimitBurst=3
StartLimitIntervalSec=600
OnFailure=litevirt-rollback.service

[Service]
Type=simple
ExecStart=/usr/local/bin/litevirt daemon
KillMode=process
Delegate=no
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

# Rollback companion: fires when litevirtd hits StartLimitBurst (a bad
# upgrade panicking on every start). Restores .old binary and restarts.
cat > /etc/systemd/system/litevirt-rollback.service << 'UNIT'
[Unit]
Description=litevirt daemon rollback (auto-restore previous binary on failed upgrade)

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'if [ -f /usr/local/bin/litevirt.old ]; then logger -t litevirt-rollback "RESTORING previous litevirtd binary after failed upgrade"; mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt; systemctl reset-failed litevirt.service; systemctl start litevirt.service; else logger -t litevirt-rollback "no .old binary to roll back to; leaving litevirtd in failed state"; exit 1; fi'
UNIT
systemctl daemon-reload
systemctl enable litevirt.service
systemctl restart litevirt.service

echo "=== litevirt setup complete ==="
`
