package libvirt

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// DefineDomain creates a persistent domain from XML.
func (c *Client) DefineDomain(xmlConfig string) error {
	_, err := c.virt.DomainDefineXML(xmlConfig)
	if err != nil {
		return fmt.Errorf("define domain: %w", err)
	}
	return nil
}

// StartDomain boots a defined domain.
func (c *Client) StartDomain(name string) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := c.virt.DomainCreate(dom); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	return nil
}

// ShutdownDomain sends an ACPI poweroff to a running domain.
func (c *Client) ShutdownDomain(name string) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := c.virt.DomainShutdown(dom); err != nil {
		return fmt.Errorf("shutdown domain %s: %w", name, err)
	}
	return nil
}

// DestroyDomain force-stops a domain (like pulling the power cord).
func (c *Client) DestroyDomain(name string) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := c.virt.DomainDestroy(dom); err != nil {
		return fmt.Errorf("destroy domain %s: %w", name, err)
	}
	return nil
}

// UndefineDomain removes a domain definition. If removeStorage is true,
// also removes associated storage.
func (c *Client) UndefineDomain(name string, removeStorage bool) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}

	// Always include NVRAM flag — UEFI domains cannot be undefined without it.
	flags := golibvirt.DomainUndefineNvram
	if removeStorage {
		flags |= golibvirt.DomainUndefineManagedSave |
			golibvirt.DomainUndefineSnapshotsMetadata |
			golibvirt.DomainUndefineCheckpointsMetadata
	}
	if err := c.virt.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(flags)); err != nil {
		return fmt.Errorf("undefine domain %s: %w", name, err)
	}
	return nil
}

// UndefineDomainPreservingState undefines a domain WITHOUT deleting its NVRAM or
// vTPM state (G1). Use for redefine-class operations that tear the domain down
// only to immediately redefine the SAME VM (snapshot revert, UpdateVM redefine,
// cutover rename) — the default UndefineDomain passes DomainUndefineNvram, which
// would delete the per-VM UEFI vars and break a Secure-Boot/vTPM guest on the
// next start. (libvirt requires either Nvram or KeepNvram to undefine a UEFI
// domain; KeepTpm is belt-and-suspenders — swtpm state is never touched unless
// DomainUndefineTpm is set.)
func (c *Client) UndefineDomainPreservingState(name string) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	flags := golibvirt.DomainUndefineKeepNvram | golibvirt.DomainUndefineKeepTpm
	if err := c.virt.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(flags)); err != nil {
		return fmt.Errorf("undefine (keep state) domain %s: %w", name, err)
	}
	return nil
}

// DomainState returns the current coarse lifecycle state of a domain
// (running | stopping | stopped | error | unknown). Paused, shut-off and
// pm-suspended all collapse to "stopped" here — callers that need to tell those
// apart (e.g. the restart engine) use DomainStateReason instead.
func (c *Client) DomainState(name string) (string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "unknown", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	state, _, err := c.virt.DomainGetState(dom, 0)
	if err != nil {
		return "unknown", fmt.Errorf("get domain state %s: %w", name, err)
	}
	return coarseDomainState(golibvirt.DomainState(state)), nil
}

// DomainStatus is the coarse lifecycle State plus the normalized Reason — why
// the domain is in that state. The Reason is what lets the restart engine tell a
// clean guest shutdown from a crash, a fence-destroy, a suspend-to-disk (saved),
// or a migration; DomainState's coarse string collapses all of those to
// "stopped".
type DomainStatus struct {
	// State uses the same vocabulary as DomainState.
	State string
	// Reason: guest-shutdown | crashed | failed | destroyed | saved | migrated |
	// from-snapshot | daemon | paused | pmsuspended | running | shutting-down | unknown
	Reason string
}

// DomainStateReason returns the domain's coarse State together with the
// normalized Reason from libvirt's virDomainGetState — the reason int that
// DomainState discards.
func (c *Client) DomainStateReason(name string) (DomainStatus, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return DomainStatus{State: "unknown", Reason: "unknown"}, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	state, reason, err := c.virt.DomainGetState(dom, 0)
	if err != nil {
		return DomainStatus{State: "unknown", Reason: "unknown"}, fmt.Errorf("get domain state %s: %w", name, err)
	}
	s := golibvirt.DomainState(state)
	return DomainStatus{State: coarseDomainState(s), Reason: normalizeDomainReason(s, reason)}, nil
}

// HasManagedSaveImage reports whether a (shut-off) domain has a managed-save /
// suspend-to-disk image. The restart engine must never cold-boot such a domain —
// a fresh start would discard its saved RAM.
func (c *Client) HasManagedSaveImage(name string) (bool, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return false, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	r, err := c.virt.DomainHasManagedSaveImage(dom, 0)
	if err != nil {
		return false, fmt.Errorf("has managed save %s: %w", name, err)
	}
	return r != 0, nil
}

// coarseDomainState maps a libvirt DomainState to litevirt's coarse vocabulary.
// Kept identical to the original DomainState switch (13 callers depend on it).
func coarseDomainState(s golibvirt.DomainState) string {
	switch s {
	case golibvirt.DomainRunning, golibvirt.DomainBlocked:
		return "running"
	case golibvirt.DomainShutdown:
		return "stopping"
	case golibvirt.DomainPaused, golibvirt.DomainShutoff, golibvirt.DomainPmsuspended:
		return "stopped"
	case golibvirt.DomainCrashed:
		return "error"
	default:
		return "unknown"
	}
}

// normalizeDomainReason maps libvirt's per-state reason int to a stable string.
func normalizeDomainReason(s golibvirt.DomainState, reason int32) string {
	switch s {
	case golibvirt.DomainRunning, golibvirt.DomainBlocked:
		return "running"
	case golibvirt.DomainPaused:
		return "paused"
	case golibvirt.DomainPmsuspended:
		return "pmsuspended"
	case golibvirt.DomainShutdown:
		return "shutting-down"
	case golibvirt.DomainCrashed:
		return "crashed"
	case golibvirt.DomainShutoff:
		switch golibvirt.DomainShutoffReason(reason) {
		case golibvirt.DomainShutoffShutdown:
			return "guest-shutdown"
		case golibvirt.DomainShutoffDestroyed:
			return "destroyed"
		case golibvirt.DomainShutoffCrashed:
			return "crashed"
		case golibvirt.DomainShutoffMigrated:
			return "migrated"
		case golibvirt.DomainShutoffSaved:
			return "saved"
		case golibvirt.DomainShutoffFailed:
			return "failed"
		case golibvirt.DomainShutoffFromSnapshot:
			return "from-snapshot"
		case golibvirt.DomainShutoffDaemon:
			return "daemon"
		default:
			return "unknown"
		}
	default:
		return "unknown"
	}
}

// WaitForShutdown polls the domain state until it is shutoff or the timeout expires.
// Returns true if the domain shut down within the timeout, false otherwise.
func (c *Client) WaitForShutdown(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := c.DomainState(name)
		if err != nil || state == "stopped" {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// ConsolePTYPath returns the PTY device path for a running domain's serial console.
// Libvirt populates <console><source path='...'></console> in the live XML.
func (c *Client) ConsolePTYPath(name string) (string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	xmlStr, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return "", fmt.Errorf("get XML for %s: %w", name, err)
	}
	return parseConsolePTYPath(xmlStr, name)
}

// parseConsolePTYPath extracts the PTY device path from domain XML.
func parseConsolePTYPath(xmlStr, name string) (string, error) {
	var doc struct {
		Devices struct {
			Consoles []struct {
				Type   string `xml:"type,attr"`
				Source struct {
					Path string `xml:"path,attr"`
				} `xml:"source"`
			} `xml:"console"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlStr), &doc); err != nil {
		return "", fmt.Errorf("parse domain XML: %w", err)
	}

	for _, c := range doc.Devices.Consoles {
		if c.Type == "pty" && c.Source.Path != "" {
			return c.Source.Path, nil
		}
	}
	return "", fmt.Errorf("no PTY console found for domain %s", name)
}

// DomainExists checks if a domain is defined.
// DumpXML returns the full XML description of a domain.
func (c *Client) DumpXML(name string) (string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	xml, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return "", fmt.Errorf("get XML for %s: %w", name, err)
	}
	return xml, nil
}

func (c *Client) DomainExists(name string) bool {
	_, err := c.virt.DomainLookupByName(name)
	return err == nil
}

// ListDomains returns the names of all defined domains.
func (c *Client) ListDomains() ([]string, error) {
	flags := golibvirt.ConnectListDomainsActive | golibvirt.ConnectListDomainsInactive
	domains, _, err := c.virt.ConnectListAllDomains(1, flags)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}

	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Name
	}
	return names, nil
}

// GetVMVNCPort returns the VNC port assigned to a running domain.
// libvirt auto-assigns ports starting at 5900; returns -1 if VNC is not active.
func (c *Client) GetVMVNCPort(name string) (int, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return -1, fmt.Errorf("lookup domain %s: %w", name, err)
	}

	xmlDesc, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return -1, fmt.Errorf("get domain XML %s: %w", name, err)
	}

	// Parse just enough of the domain XML to find the VNC port.
	var doc struct {
		Devices struct {
			Graphics []struct {
				Type string `xml:"type,attr"`
				Port int    `xml:"port,attr"`
			} `xml:"graphics"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlDesc), &doc); err != nil {
		return -1, fmt.Errorf("parse domain XML: %w", err)
	}

	for _, g := range doc.Devices.Graphics {
		if strings.EqualFold(g.Type, "vnc") {
			return g.Port, nil
		}
	}
	return -1, fmt.Errorf("no VNC graphics device found for %s", name)
}

// GetVMSpicePort returns the SPICE port assigned to a running domain.
// Returns -1 if SPICE is not configured on this VM.
func (c *Client) GetVMSpicePort(name string) (int, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return -1, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	xmlDesc, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return -1, fmt.Errorf("get domain XML %s: %w", name, err)
	}
	var doc struct {
		Devices struct {
			Graphics []struct {
				Type string `xml:"type,attr"`
				Port int    `xml:"port,attr"`
			} `xml:"graphics"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlDesc), &doc); err != nil {
		return -1, fmt.Errorf("parse domain XML: %w", err)
	}
	for _, g := range doc.Devices.Graphics {
		if strings.EqualFold(g.Type, "spice") {
			return g.Port, nil
		}
	}
	return -1, fmt.Errorf("no SPICE graphics device found for %s", name)
}

// GetVMMACs returns the MAC addresses of all interfaces of a domain.
func (c *Client) GetVMMACs(name string) ([]string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", name, err)
	}

	xmlDesc, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return nil, fmt.Errorf("get domain XML %s: %w", name, err)
	}

	var doc struct {
		Devices struct {
			Interfaces []struct {
				MAC struct {
					Address string `xml:"address,attr"`
				} `xml:"mac"`
			} `xml:"interface"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlDesc), &doc); err != nil {
		return nil, fmt.Errorf("parse domain XML: %w", err)
	}

	macs := make([]string, 0, len(doc.Devices.Interfaces))
	for _, iface := range doc.Devices.Interfaces {
		if iface.MAC.Address != "" {
			macs = append(macs, strings.ToLower(iface.MAC.Address))
		}
	}
	return macs, nil
}

// ExecInGuest runs a command inside the VM via the QEMU guest agent.
// Returns stdout of the command.
func (c *Client) ExecInGuest(name, command string, args []string) (string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}

	// Build guest-exec JSON payload.
	argsJSON := "[]"
	if len(args) > 0 {
		parts := make([]string, len(args))
		for i, a := range args {
			parts[i] = fmt.Sprintf("%q", a)
		}
		argsJSON = "[" + strings.Join(parts, ",") + "]"
	}
	execReq := fmt.Sprintf(`{"execute":"guest-exec","arguments":{"path":%q,"arg":%s,"capture-output":true}}`, command, argsJSON)

	// Use a 30-second timeout for guest agent commands to prevent goroutine
	// leaks when the guest agent is hung (#24). -1 means "wait forever".
	const guestAgentTimeoutSec = 30

	resp, err := c.virt.QEMUDomainAgentCommand(dom, execReq, guestAgentTimeoutSec, 0)
	if err != nil {
		return "", fmt.Errorf("guest-exec %s: %w", name, err)
	}

	var execRes struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}
	if len(resp) == 0 || json.Unmarshal([]byte(resp[0]), &execRes) != nil || execRes.Return.PID == 0 {
		return "", fmt.Errorf("parse guest-exec response: %q", strings.Join(resp, ""))
	}

	// Poll guest-exec-status until the command has exited — guest-exec is
	// asynchronous, so a single status check races a command that hasn't
	// finished (the old code returned the raw, often not-yet-exited envelope).
	statusReq := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, execRes.Return.PID)
	var st struct {
		Return struct {
			Exited   bool   `json:"exited"`
			ExitCode int    `json:"exitcode"`
			OutData  string `json:"out-data"`
			ErrData  string `json:"err-data"`
		} `json:"return"`
	}
	exited := false
	for attempt := 0; attempt < 60; attempt++ { // ~30s ceiling
		statusResp, serr := c.virt.QEMUDomainAgentCommand(dom, statusReq, guestAgentTimeoutSec, 0)
		if serr != nil {
			return "", fmt.Errorf("guest-exec-status: %w", serr)
		}
		if len(statusResp) == 0 {
			return "", nil
		}
		if err := json.Unmarshal([]byte(statusResp[0]), &st); err != nil {
			return "", fmt.Errorf("parse guest-exec-status: %w", err)
		}
		if st.Return.Exited {
			exited = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !exited {
		return "", fmt.Errorf("guest command on %s did not exit within ~30s", name)
	}

	// Decode the base64 stdout/stderr the agent captured and return the real
	// output (not the raw QGA JSON envelope, which was unusable). stderr is
	// appended so callers see failure detail; a non-zero exit is surfaced as an
	// error while still returning whatever output was produced.
	out, _ := base64.StdEncoding.DecodeString(st.Return.OutData)
	errOut, _ := base64.StdEncoding.DecodeString(st.Return.ErrData)
	combined := string(out) + string(errOut)
	if st.Return.ExitCode != 0 {
		return combined, fmt.Errorf("guest command exited %d: %s", st.Return.ExitCode, strings.TrimSpace(string(errOut)))
	}
	return combined, nil
}

// SetBootOrder changes the boot device order for a domain by fetching its XML,
// patching the <boot dev='...'> element in the <os> section, and redefining it.
// bootOrder is one of: disk, cdrom, network.
func (c *Client) SetBootOrder(domainName, bootOrder string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}

	xmlDesc, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return fmt.Errorf("get domain XML %s: %w", domainName, err)
	}

	updated := patchBootDev(xmlDesc, bootOrder)

	if _, err := c.virt.DomainDefineXML(updated); err != nil {
		return fmt.Errorf("redefine domain %s: %w", domainName, err)
	}
	return nil
}

// patchBootDev replaces the boot dev attribute value inside the <os> section.
func patchBootDev(xmlDesc, bootDev string) string {
	osStart := strings.Index(xmlDesc, "<os>")
	osEnd := strings.Index(xmlDesc, "</os>")
	if osStart == -1 || osEnd == -1 {
		return xmlDesc
	}
	osSection := xmlDesc[osStart : osEnd+5]
	patched := replaceBootDev(osSection, bootDev)
	return xmlDesc[:osStart] + patched + xmlDesc[osEnd+5:]
}

// replaceBootDev finds <boot dev='...'> or <boot dev="..."> within s and
// replaces the value with bootDev.
func replaceBootDev(s, bootDev string) string {
	for _, q := range []string{"'", "\""} {
		token := "<boot dev=" + q
		if idx := strings.Index(s, token); idx != -1 {
			end := strings.Index(s[idx+len(token):], q)
			if end != -1 {
				before := s[:idx+len(token)]
				after := s[idx+len(token)+end:]
				return before + bootDev + after
			}
		}
	}
	return s
}
