// Command mkpki mints a litevirt CA + per-host certs into a directory, for
// local/ephemeral test clusters (the production path, host init, also installs
// systemd + packages, which a throwaway test cluster doesn't want).
//
//	mkpki <pki-root> <san-ip> <host1> [host2 ...]
//
// Layout written:
//
//	<pki-root>/ca.crt, ca.key
//	<pki-root>/<host>/pki/ca.crt, host.crt, host.key   (one dir per host)
//
// The per-host certs live under a "pki" subdir so the same parent works as both
// the daemon's pki_dir (<host>/pki) and the CLI's LV_CONFIG_DIR (<host>, which
// appends /pki).
//
// Each host cert carries <san-ip> + 127.0.0.1 as SANs. Pass the box's LAN IP
// as <san-ip> so a multi-node cluster (which dials peers by their self-
// registered outbound address) verifies; 127.0.0.1 is always added too.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/pki"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: mkpki <pki-root> <san-ip> <host1> [host2 ...]")
		os.Exit(2)
	}
	root, sanIP := os.Args[1], net.ParseIP(os.Args[2])
	if sanIP == nil {
		fatal(fmt.Errorf("invalid san-ip %q", os.Args[2]))
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		fatal(err)
	}
	caCert := filepath.Join(root, "ca.crt")
	caKey := filepath.Join(root, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		fatal(fmt.Errorf("generate CA: %w", err))
	}
	for _, host := range os.Args[3:] {
		dir := filepath.Join(root, host, "pki")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fatal(err)
		}
		if err := pki.GenerateHostCert(caCert, caKey,
			filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
			host, sanIP); err != nil {
			fatal(fmt.Errorf("host cert %s: %w", host, err))
		}
		if data, err := os.ReadFile(caCert); err == nil {
			_ = os.WriteFile(filepath.Join(dir, "ca.crt"), data, 0o600)
		}
	}
	fmt.Printf("minted CA + %d host cert(s) under %s (SAN %s + 127.0.0.1)\n", len(os.Args)-3, root, sanIP)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mkpki:", err)
	os.Exit(1)
}
