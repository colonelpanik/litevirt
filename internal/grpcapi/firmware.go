package grpcapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/placement"
)

// firmwareLayoutFingerprint hashes the host paths that an exported domain XML
// embeds for firmware — dataDir (→ NVRAM path) + the resolved OVMF loader/VARS
// templates. A verbatim domain XML is only portable to a host whose fingerprint
// matches, so a cold firmware migration carries this and the target refuses a
// mismatch rather than defining a domain pointing at the source's paths (G1).
func (s *Server) firmwareLayoutFingerprint() string {
	fp := s.firmware
	h := sha256.Sum256([]byte(strings.Join([]string{
		s.dataDir, fp.Code, fp.Vars, fp.SecbootCode, fp.MsVars,
	}, "\x00")))
	return hex.EncodeToString(h[:])
}

// domainIdentity extracts the <name> and <uuid> from a domain XML, for
// validating a pushed migration definition against the request.
func domainIdentity(domXML string) (name, uuid string) {
	var d struct {
		Name string `xml:"name"`
		UUID string `xml:"uuid"`
	}
	_ = xml.Unmarshal([]byte(domXML), &d)
	return d.Name, d.UUID
}

// firmwareSpec is the minimal slice of a stored VMSpec needed to reason about a
// VM's firmware state without a full unmarshal.
type firmwareSpec struct {
	SecureBoot bool   `json:"secure_boot"`
	Tpm        bool   `json:"tpm"`
	UUID       string `json:"uuid"`
	Firmware   string `json:"firmware"`
}

// hasNvram reports whether this VM has a name-keyed UEFI vars file — i.e. it's
// UEFI (BIOS VMs have none, even with a vTPM). Empty firmware defaults to UEFI.
func (fs firmwareSpec) hasNvram() bool {
	return fs.Firmware == "uefi" || fs.Firmware == ""
}

func parseFirmwareSpec(specJSON string) firmwareSpec {
	var fs firmwareSpec
	_ = json.Unmarshal([]byte(specJSON), &fs)
	return fs
}

// usesFirmwareState reports whether a stored spec uses Secure Boot or vTPM (i.e.
// has lifecycle-sensitive firmware state).
func usesFirmwareState(specJSON string) bool {
	fs := parseFirmwareSpec(specJSON)
	return fs.SecureBoot || fs.Tpm
}

// applyFirmwareConfig sets the Secure Boot + vTPM fields on a VMConfig (G1) from
// the spec, using the host's resolved OVMF paths. NVRAM is name-pinned under
// dataDir; vTPM state uses libvirt's default UUID-keyed path (AppArmor-permitted),
// made deterministic by the stable spec.Uuid. Refuses to adopt name-keyed NVRAM
// left by a prior `delete --keep-disks` (vTPM can't be inherited — fresh create
// mints a new UUID). No-op when neither flag is set and firmware is bios.
func (s *Server) applyFirmwareConfig(cfg *lv.VMConfig, spec *pb.VMSpec) error {
	if spec.SecureBoot && !s.firmware.SecureBootAvailable() {
		return status.Errorf(codes.FailedPrecondition,
			"host %s has no Secure Boot OVMF firmware; cannot create a Secure Boot VM here", s.hostName)
	}
	// Local TPM preflight (defends against a stale/bypassed placement label →
	// a late, opaque libvirt swtpm_setup failure at start).
	if spec.Tpm {
		if err := s.checkTPMHostSupport(); err != nil {
			return err
		}
	}
	s.firmware.ApplyTo(cfg, s.dataDir, spec.Name, spec.SecureBoot, spec.Tpm)
	if !spec.SecureBoot && !spec.Tpm {
		return nil
	}
	// NVRAM is name-keyed: refuse to adopt vars left by a prior `delete
	// --keep-disks` (SB key inheritance). vTPM state is UUID-keyed and the VM gets
	// a fresh UUID at create, so it can never inherit an old TPM secret — no guard
	// needed there (any retained swtpm state is orphaned, only restorable explicitly).
	if cfg.NvramPath != "" {
		if lv.HasNvram(s.dataDir, spec.Name) {
			return status.Errorf(codes.FailedPrecondition,
				"UEFI vars already exist for %q (left by a prior `delete --keep-disks`); restore the VM instead of recreating it", spec.Name)
		}
		// 0755 so the dropped-privilege qemu user can traverse to the vars file
		// (the file itself is dynamic-owned by libvirt); matches the disks dir.
		if err := os.MkdirAll(filepath.Dir(cfg.NvramPath), 0o755); err != nil {
			return status.Errorf(codes.Internal, "create nvram dir: %v", err)
		}
	}
	return nil
}

// firmwarePresent verifies every firmware component the spec declares is present
// on this host — NVRAM for a UEFI VM, swtpm for a vTPM VM. WriteFirmwareBundle
// reports success for a PARTIAL bundle (either component), so callers that
// capture for backup/migration must gate on this first or they'd ship a
// half-bundle that restores a VM with a fresh TPM and breaks BitLocker (G1).
func (s *Server) firmwarePresent(vmName string, fs firmwareSpec) error {
	if fs.hasNvram() && !lv.HasNvram(s.dataDir, vmName) {
		return status.Errorf(codes.FailedPrecondition,
			"UEFI NVRAM for %q is not present on this host; cannot carry its firmware consistently", vmName)
	}
	if fs.Tpm && !lv.HasTPMState(fs.UUID) {
		return status.Errorf(codes.FailedPrecondition,
			"swtpm state for %q is not present on this host; cannot carry its firmware consistently", vmName)
	}
	return nil
}

// checkTPMHostSupport verifies the host has the full swtpm stack needed to START
// a vTPM VM — BOTH swtpm and swtpm_setup (libvirt runs swtpm_setup to initialize
// state; the first G1 drill failed there with swtpm alone). Used by both CreateVM
// (applyFirmwareConfig) and UpdateVM so enabling --tpm can't persist on a host
// that would only fail later at define/start.
func (s *Server) checkTPMHostSupport() error {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return status.Errorf(codes.FailedPrecondition, "host %s has no swtpm; cannot run a vTPM VM here", s.hostName)
	}
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		return status.Errorf(codes.FailedPrecondition, "host %s has swtpm but not swtpm_setup; cannot initialize a vTPM here", s.hostName)
	}
	return nil
}

// addCapabilityLabels appends the host-capability label requirements a VM spec
// needs (G1) to a placement request, so a vTPM and/or Secure Boot VM only lands
// on a host that advertises the matching capability. Call from every placement-
// request builder (CreateVM, migrate target preflight, failover, rebalancer,
// host, compose planner).
func addCapabilityLabels(req *placement.Request, spec *pb.VMSpec) {
	if spec == nil || (!spec.SecureBoot && !spec.Tpm) {
		return
	}
	if req.RequireLabels == nil {
		req.RequireLabels = map[string]string{}
	}
	if spec.Tpm {
		req.RequireLabels[corrosion.LabelTPMCapable] = "true"
	}
	if spec.SecureBoot {
		req.RequireLabels[corrosion.LabelSecureBootCapable] = "true"
	}
}
