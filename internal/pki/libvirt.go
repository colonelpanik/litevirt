package pki

import (
	"fmt"
	"os"
	"path/filepath"
)

// libvirt TLS default cert paths.
const (
	libvirtCADir         = "/etc/pki/CA"
	libvirtCertDir       = "/etc/pki/libvirt"
	libvirtPrivateKeyDir = "/etc/pki/libvirt/private"
)

// SetupLibvirtTLS creates symlinks from libvirt's expected TLS cert paths
// to our existing PKI certs. This allows libvirt migration to use qemu+tls://
// without maintaining a separate PKI.
//
// Libvirt expects:
//
//	/etc/pki/CA/cacert.pem              → pkiDir/ca.crt
//	/etc/pki/libvirt/servercert.pem     → pkiDir/host.crt
//	/etc/pki/libvirt/private/serverkey.pem → pkiDir/host.key
//	/etc/pki/libvirt/clientcert.pem     → pkiDir/host.crt  (same cert for client auth)
//	/etc/pki/libvirt/private/clientkey.pem → pkiDir/host.key
func SetupLibvirtTLS(pkiDir string) error {
	// Verify our certs exist first.
	for _, f := range []string{"ca.crt", "host.crt", "host.key"} {
		if _, err := os.Stat(filepath.Join(pkiDir, f)); err != nil {
			return fmt.Errorf("PKI file %s not found in %s: %w", f, pkiDir, err)
		}
	}

	// Create target directories.
	for _, dir := range []string{libvirtCADir, libvirtCertDir, libvirtPrivateKeyDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	links := []struct {
		target string // our cert
		link   string // libvirt's expected path
	}{
		{filepath.Join(pkiDir, "ca.crt"), filepath.Join(libvirtCADir, "cacert.pem")},
		{filepath.Join(pkiDir, "host.crt"), filepath.Join(libvirtCertDir, "servercert.pem")},
		{filepath.Join(pkiDir, "host.key"), filepath.Join(libvirtPrivateKeyDir, "serverkey.pem")},
		{filepath.Join(pkiDir, "host.crt"), filepath.Join(libvirtCertDir, "clientcert.pem")},
		{filepath.Join(pkiDir, "host.key"), filepath.Join(libvirtPrivateKeyDir, "clientkey.pem")},
	}

	for _, l := range links {
		// Remove existing file/symlink if present.
		if existing, err := os.Lstat(l.link); err == nil {
			if existing.Mode()&os.ModeSymlink != 0 {
				// Already a symlink — check if it points to the right place.
				dst, _ := os.Readlink(l.link)
				if dst == l.target {
					continue // already correct
				}
			}
			os.Remove(l.link)
		}
		if err := os.Symlink(l.target, l.link); err != nil {
			return fmt.Errorf("symlink %s → %s: %w", l.link, l.target, err)
		}
	}

	return nil
}
