package libvirt

import "os"

// FirmwarePaths holds the host's resolved OVMF firmware files. It is resolved
// once at daemon startup (paths vary by distro) and injected into every
// component that builds a domain (gRPC server, health reconciler), so the
// rendered XML and the advertised host capability always agree on the same
// files. Empty SecbootCode/MsVars means the host can't do Secure Boot.
type FirmwarePaths struct {
	Code        string // non-secure OVMF code (pflash)
	Vars        string // non-secure OVMF vars template
	SecbootCode string // Secure Boot OVMF code (with SMM)
	MsVars      string // vars template with Microsoft keys enrolled (Windows-ready)
}

// firmwareCandidates lists per-distro paths, most-specific first.
var (
	codeCandidates = []string{
		"/usr/share/OVMF/OVMF_CODE_4M.fd",
		"/usr/share/OVMF/OVMF_CODE.fd",
		"/usr/share/edk2/ovmf/OVMF_CODE.fd",
		"/usr/share/edk2/x64/OVMF_CODE.4m.fd",
		"/usr/share/qemu/ovmf-x86_64-code.bin",
	}
	varsCandidates = []string{
		"/usr/share/OVMF/OVMF_VARS_4M.fd",
		"/usr/share/OVMF/OVMF_VARS.fd",
		"/usr/share/edk2/ovmf/OVMF_VARS.fd",
		"/usr/share/edk2/x64/OVMF_VARS.4m.fd",
	}
	secbootCodeCandidates = []string{
		"/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
		"/usr/share/OVMF/OVMF_CODE.secboot.fd",
		"/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
		"/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
	}
	// Only templates KNOWN to ship with Microsoft keys enrolled — the
	// litevirt.secureboot label means "Windows Secure Boot ready". A generic empty
	// VARS template (e.g. OVMF_VARS_4M.fd) must NOT satisfy it, or a guest that
	// trusts the MS UEFI CA won't boot. (Fedora/RHEL enrolled-keys templates can be
	// added once verified to boot Windows SB.)
	msVarsCandidates = []string{
		"/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
		"/usr/share/OVMF/OVMF_VARS.ms.fd",
	}
)

func firstExisting(candidates []string) string {
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// ResolveFirmwarePaths probes the host for OVMF firmware files.
func ResolveFirmwarePaths() FirmwarePaths {
	return FirmwarePaths{
		Code:        firstExisting(codeCandidates),
		Vars:        firstExisting(varsCandidates),
		SecbootCode: firstExisting(secbootCodeCandidates),
		MsVars:      firstExisting(msVarsCandidates),
	}
}

// SecureBootAvailable reports whether the host has the Secure Boot OVMF pair.
func (fp FirmwarePaths) SecureBootAvailable() bool {
	return fp.SecbootCode != "" && fp.MsVars != ""
}

// ApplyTo sets the firmware/Secure-Boot/vTPM fields on a VMConfig using the
// resolved OVMF paths and dataDir-pinned per-VM state paths. It sets fields only;
// callers enforce existence policy (create refuses pre-existing state; the
// reconciler requires it) and create/move the state files. Shared by CreateVM,
// the reconciler, restore, etc. so they all render the same firmware.
func (fp FirmwarePaths) ApplyTo(cfg *VMConfig, dataDir, vmName string, secureBoot, tpm bool) {
	isUEFI := cfg.Firmware == "uefi" || cfg.Firmware == ""
	cfg.SecureBoot = secureBoot
	cfg.TPM = tpm
	switch {
	case secureBoot:
		cfg.LoaderPath = fp.SecbootCode
		cfg.NvramTemplate = fp.MsVars
	case isUEFI:
		cfg.LoaderPath = fp.Code
		cfg.NvramTemplate = fp.Vars
	}
	if isUEFI && (secureBoot || tpm) {
		cfg.NvramPath = NvramPath(dataDir, vmName)
	}
	// Deliberately NO TPMStateDir/<source>: libvirt manages swtpm state at the
	// AppArmor-permitted /var/lib/libvirt/swtpm/<uuid>/, made deterministic by the
	// stable cfg.UUID. State-travel addresses it via LibvirtSwtpmDir(uuid)
	// (vtpmstate.go).
}

// HasNvram reports whether the per-VM (name-keyed) UEFI vars file exists.
// (LibvirtSwtpmDir/HasTPMState live in vtpmstate.go alongside the bundle ops.)
func HasNvram(dataDir, vmName string) bool {
	fi, err := os.Stat(NvramPath(dataDir, vmName))
	return err == nil && fi.Size() > 0
}
