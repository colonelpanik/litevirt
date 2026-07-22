// Package libvirtfake is an in-memory implementation of
// grpcapi.LibvirtBackend for tests and harnesses. It tracks domain
// state in maps, no qemu processes are launched, no XML is parsed
// beyond minimal name extraction.
//
// Scenarios that need to assert on domain lifecycle (e.g. "VM was
// started after CreateVM" or "ShutdownDomain happened during drain")
// inspect Fake.State / Fake.Events / Fake.SnapshotsOf directly.
//
// The fake is deliberately permissive: any method that doesn't have
// an explicit override returns nil. If a scenario needs to observe
// failure-injection, set the corresponding Fail* field. The harness
// stays small by leaning on this default-success-with-overrides
// pattern.
package libvirtfake

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// State describes a single domain's lifecycle. Mirrors what
// libvirt.Client.DomainState would return.
type State string

const (
	StateDefined  State = "shutoff" // defined but not started
	StateRunning  State = "running"
	StateShutdown State = "shutoff"
	StateNoDomain State = "no-domain"
)

// Event captures an interesting transition for scenario asserts.
// Recorded in Fake.Events in the order operations arrived.
type Event struct {
	Op     string // "define" | "start" | "shutdown" | "destroy" | "undefine" | "snapshot" | ...
	Domain string
	Note   string // free-form ("xml=...", "snapshot=foo")
	When   time.Time
}

// Fake satisfies grpcapi.LibvirtBackend.
type Fake struct {
	mu          sync.Mutex
	domains     map[string]State
	xml         map[string]string
	activeXML   map[string]string              // domain → live-view override (see DumpXML)
	snapshots   map[string]map[string]struct{} // domain → snapshot names
	diskSources map[string]map[string]string   // domain → target-dev → source file
	stats       map[string]*libvirt.DomainStats
	reasons     map[string]string // domain → injected DomainStateReason.Reason
	events      []Event

	// Optional time source for events. Defaults to time.Now.
	Now func() time.Time

	// attachDiskN / detachDiskN count disk hot-plug primitive calls so at-most-once
	// tests can assert exactly one libvirt attach/detach happened for one operation.
	attachDiskN int
	detachDiskN int
	// attachNICN / detachNICN are the NIC-hotplug equivalent.
	attachNICN int
	detachNICN int
	// attachHostdevN / detachHostdevN count PCI passthrough hot-plug primitive calls
	// (both the plain and alias-carrying attach) so at-most-once tests can assert
	// exactly one libvirt hostdev attach/detach happened per member per operation.
	attachHostdevN int
	detachHostdevN int
	// detachHostdevConfigN counts CONFIG-only hostdev detaches (DetachHostdevConfig) so a
	// test can prove the shut-off reclaim took the config path, NOT the live one.
	detachHostdevConfigN int

	// Fail* hooks let scenarios inject failures into specific methods.
	// Nil = default success.
	FailDefineDomain func(xml string) error
	FailStartDomain  func(name string) error
	// FailAttachDisk / FailDetachDisk inject a live disk hot-plug primitive failure so
	// scenarios can exercise attach-rollback / detach-forward compensation.
	FailAttachDisk func(domain, path, targetDev, bus string) error
	FailDetachDisk func(domain, targetDev string) error
	// FailAttachNIC / FailDetachNIC are the NIC-hotplug equivalent.
	FailAttachNIC func(domain, bridge, model, mac string) error
	FailDetachNIC func(domain, mac string) error
	// SkipConfigOnDiskMutation, when true, makes AttachDisk/DetachDisk update ONLY the
	// live view (diskSources) and NOT the persistent (inactive) config — modeling a
	// libvirt DomainDeviceModifyLive-succeeded-but-Config-not-applied divergence so a
	// both-state (live+persistent) verification can be exercised.
	SkipConfigOnDiskMutation bool
	// SkipConfigOnNICMutation is the NIC-hotplug equivalent: AttachNIC/DetachNIC
	// update ONLY the live view (activeXML) and NOT the persistent (inactive) xml.
	SkipConfigOnNICMutation bool
	// SkipConfigOnHostdevMutation is the PCI-hostdev equivalent: AttachHostdev*/
	// DetachHostdev update ONLY the live view (activeXML) and NOT the persistent
	// (inactive) xml — modeling a live-succeeded-but-config-not-applied divergence
	// so a both-state (live+persistent) hostdev verification can be exercised.
	SkipConfigOnHostdevMutation bool
	// FailAttachHostdev / FailDetachHostdev inject a live hostdev hot-plug primitive
	// failure so scenarios can exercise attach-rollback / detach-forward compensation.
	FailAttachHostdev func(domain, pciAddress, alias string) error
	FailDetachHostdev func(domain, pciAddress string) error
	// FailDetachHostdevConfig injects a CONFIG-only hostdev detach failure (the
	// shut-off reclaim path), symmetric with FailDetachHostdev for the live path.
	FailDetachHostdevConfig func(domain, pciAddress string) error
	FailShutdownDomain      func(name string) error
	FailUndefineDomain      func(name string, removeStorage bool) error
	FailUndefinePreserv     func(name string) error
	// FailDumpXML injects a live-domain read failure so a scenario can exercise a
	// fail-closed path that must NOT proceed when the live membership is unreadable
	// (e.g. PCI detach recovery refusing to release without confirming the hostdev
	// left the live domain).
	FailDumpXML func(name string) error
	// FailCreateLiveSnapshot fires AFTER the disk overlay has cut over, modeling a
	// RAM-save/capture failure that leaves the VM on an overlay.
	FailCreateLiveSnapshot func(domain, snap string) error
	FailDomainState        func(name string) error
	FailDomainStateReason  func(name string) error
	// FailSetVCPUs / FailSetMemory inject a resize primitive failure so scenarios
	// can exercise partial-apply recovery (e.g. cpu ok, mem fails).
	FailSetVCPUs        func(name string, count int) error
	FailSetMemory       func(name string, memMiB int) error
	FailMigrateToTarget func(name, dconnuri string) error
	FailBlockPull       func(domain, disk string) error
	FailPoolDestroy     func(name string) error
	// BlockJobStatusFn lets a scenario script block-job progress. Nil =
	// "no job in progress" (Found=false), i.e. the pull is already done —
	// the simplest happy path for the live-restore blockpull poll.
	BlockJobStatusFn func(domain, disk string) (libvirt.BlockJobStatus, error)
}

// New returns a Fake ready to use. Safe for concurrent use.
func New() *Fake {
	return &Fake{
		domains:     make(map[string]State),
		xml:         make(map[string]string),
		activeXML:   make(map[string]string),
		snapshots:   make(map[string]map[string]struct{}),
		diskSources: make(map[string]map[string]string),
		stats:       make(map[string]*libvirt.DomainStats),
		reasons:     make(map[string]string),
		Now:         time.Now,
	}
}

// Events returns a copy of the event log (safe to read while
// scenario test code continues to drive the fake).
func (f *Fake) EventLog() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, len(f.events))
	copy(out, f.events)
	return out
}

// SetState forces a domain into a particular state. Scenarios use
// this to simulate "the VM is already running" without rolling
// through DefineDomain + StartDomain.
func (f *Fake) SetState(name string, s State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[name] = s
}

// SetStats sets the GetDomainStats / GetAllDomainStats response for
// a domain. Scenarios use this to feed deterministic stats into
// metrics + monitoring paths.
func (f *Fake) SetStats(name string, s *libvirt.DomainStats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats[name] = s
}

func (f *Fake) record(op, domain, note string) {
	f.events = append(f.events, Event{Op: op, Domain: domain, Note: note, When: f.Now()})
}

// ── grpcapi.LibvirtBackend implementation ───────────────────────────────

func (f *Fake) DefineDomain(xmlConfig string) error {
	if f.FailDefineDomain != nil {
		if err := f.FailDefineDomain(xmlConfig); err != nil {
			return err
		}
	}
	name := domainNameFromXML(xmlConfig)
	if name == "" {
		return errors.New("libvirtfake: no <name> in domain XML")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[name] = StateDefined
	f.xml[name] = xmlConfig
	f.record("define", name, "")
	return nil
}

func (f *Fake) StartDomain(name string) error {
	if f.FailStartDomain != nil {
		if err := f.FailStartDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	f.domains[name] = StateRunning
	f.record("start", name, "")
	return nil
}

func (f *Fake) BlockPull(domain, disk string) error {
	if f.FailBlockPull != nil {
		if err := f.FailBlockPull(domain, disk); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("blockpull", domain, disk)
	return nil
}

func (f *Fake) BlockJobStatus(domain, disk string) (libvirt.BlockJobStatus, error) {
	if f.BlockJobStatusFn != nil {
		return f.BlockJobStatusFn(domain, disk)
	}
	return libvirt.BlockJobStatus{Found: false}, nil
}

func (f *Fake) ShutdownDomain(name string) error {
	if f.FailShutdownDomain != nil {
		if err := f.FailShutdownDomain(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	f.domains[name] = StateShutdown
	f.record("shutdown", name, "")
	return nil
}

func (f *Fake) DestroyDomain(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domains[name]; !ok {
		return fmt.Errorf("libvirtfake: domain %q not defined", name)
	}
	f.domains[name] = StateShutdown
	f.record("destroy", name, "")
	return nil
}

func (f *Fake) UndefineDomain(name string, removeStorage bool) error {
	if f.FailUndefineDomain != nil {
		if err := f.FailUndefineDomain(name, removeStorage); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.domains, name)
	delete(f.xml, name)
	delete(f.activeXML, name)
	delete(f.snapshots, name)
	delete(f.stats, name)
	f.record("undefine", name, fmt.Sprintf("remove_storage=%v", removeStorage))
	return nil
}

// UndefineDomainPreservingState mirrors UndefineDomain for the fake but records
// that NVRAM/vTPM state is kept (the fake has no real firmware state).
func (f *Fake) UndefineDomainPreservingState(name string) error {
	if f.FailUndefinePreserv != nil {
		if err := f.FailUndefinePreserv(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.domains, name)
	delete(f.xml, name)
	delete(f.activeXML, name)
	delete(f.snapshots, name)
	delete(f.stats, name)
	f.record("undefine", name, "keep_state=true")
	return nil
}

func (f *Fake) DomainState(name string) (string, error) {
	if f.FailDomainState != nil {
		if err := f.FailDomainState(name); err != nil {
			return "", err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.domains[name]
	if !ok {
		return string(StateNoDomain), nil
	}
	return string(s), nil
}

func (f *Fake) DomainExists(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.domains[name]
	return ok
}

// SetStateReason injects the Reason returned by DomainStateReason for a domain
// (e.g. "crashed" to drive an on-failure restart decision). Scenario helper.
func (f *Fake) SetStateReason(name, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reasons[name] = reason
}

// DomainStateReason returns the coarse state + a reason, satisfying
// health.LibvirtBackend (the restart-policy path). The coarse vocabulary matches
// libvirt.coarseDomainState: shutoff→"stopped", running→"running", else
// "unknown". Reason defaults to "running" for a running domain (or an injected
// value via SetStateReason), else "unknown".
func (f *Fake) DomainStateReason(name string) (libvirt.DomainStatus, error) {
	if f.FailDomainStateReason != nil {
		if err := f.FailDomainStateReason(name); err != nil {
			return libvirt.DomainStatus{State: "unknown", Reason: "unknown"}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.domains[name]
	if !ok {
		return libvirt.DomainStatus{State: "unknown", Reason: "unknown"}, nil
	}
	coarse := "unknown"
	switch s {
	case StateRunning:
		coarse = "running"
	case StateShutdown: // == StateDefined == "shutoff"
		coarse = "stopped"
	}
	reason := f.reasons[name]
	if reason == "" {
		if s == StateRunning {
			reason = "running"
		} else {
			reason = "unknown"
		}
	}
	return libvirt.DomainStatus{State: coarse, Reason: reason}, nil
}

func (f *Fake) ListDomains() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.domains))
	for n := range f.domains {
		out = append(out, n)
	}
	return out, nil
}

// DumpXML returns the domain's LIVE view: activeXML's override when NIC hotplug (or
// SetActiveXML) has diverged it, else the persistent xml — the fake's historical
// "single XML per domain" default (active mirrors persistent until something
// diverges them). Disk hotplug's live view is tracked separately (diskSources) and
// never touches activeXML, so this default is unaffected by disk attach/detach.
func (f *Fake) DumpXML(name string) (string, error) {
	if f.FailDumpXML != nil {
		if err := f.FailDumpXML(name); err != nil {
			return "", err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.activeXML[name]; ok {
		return x, nil
	}
	if x, ok := f.xml[name]; ok {
		return x, nil
	}
	return "", fmt.Errorf("libvirtfake: no XML for %q", name)
}

// DumpXMLInactive returns the domain's PERSISTENT (inactive) view — what a cold boot
// loads. Tests that need to model a post-pivot live/persistent divergence set them
// explicitly via SetInactiveXML/SetActiveXML.
func (f *Fake) DumpXMLInactive(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.xml[name]; ok {
		return x, nil
	}
	return "", fmt.Errorf("libvirtfake: no XML for %q", name)
}

// activeBaseline returns the current live-view baseline for domain: the tracked
// override if one exists, else the persistent config. Caller holds f.mu.
func (f *Fake) activeBaseline(domain string) string {
	if x, ok := f.activeXML[domain]; ok {
		return x
	}
	return f.xml[domain]
}

// SetActiveXML sets a domain's LIVE (active) XML directly, independent of its
// persistent config — the NIC-hotplug divergence-modeling counterpart to
// SetInactiveXML. A real running domain's live view always exists; this lets a
// scenario seed it explicitly before exercising a live/persistent divergence.
func (f *Fake) SetActiveXML(name, xml string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[name] = xml
}

// DefinedXML returns the last XML DefineDomain captured for name, or "" if the
// domain was never defined. A test accessor (no error) so assertions can inspect
// the domain a reconcile/redefine produced without the DumpXML not-found error.
func (f *Fake) DefinedXML(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.xml[name]
}

// SetInactiveXML sets a domain's persistent (inactive) XML directly, without altering
// its lifecycle state. Scenarios use it to model a RUNNING domain that already has a
// persistent definition (which a real running domain always does) so a live-vs-config
// divergence can be exercised. Mirrors SetDiskSource/SetState.
func (f *Fake) SetInactiveXML(name, xml string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.xml[name] = xml
}

func (f *Fake) WaitForShutdown(name string, timeout time.Duration) bool {
	// The fake transitions synchronously; the wait always succeeds.
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.domains[name]; ok && s == StateShutdown {
		return true
	}
	return true
}

// VNC / SPICE / console — return deterministic placeholders.

func (f *Fake) GetVMVNCPort(name string) (int, error) {
	return 5901, nil
}
func (f *Fake) GetVMSpicePort(name string) (int, error) {
	return 5930, nil
}
func (f *Fake) ConsolePTYPath(name string) (string, error) {
	return "/dev/pts/fake", nil
}

// Hot-plug — record and succeed.

func (f *Fake) AttachDisk(domainName, path, targetDev, bus string) error {
	if f.FailAttachDisk != nil {
		if err := f.FailAttachDisk(domainName, path, targetDev, bus); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Track the live disk source so DomainDiskSources reflects the attach (the
	// authoritative check a running-attach verification uses).
	if f.diskSources[domainName] == nil {
		f.diskSources[domainName] = map[string]string{}
	}
	f.diskSources[domainName][targetDev] = path
	// The real AttachDisk applies DomainDeviceModifyLive|Config, so the disk lands in
	// the persistent (inactive) definition too. Reflect that in f.xml (what
	// DumpXMLInactive reads) unless a scenario is modeling a live-only divergence.
	if !f.SkipConfigOnDiskMutation {
		f.xml[domainName] = insertDiskIntoDomainXML(f.xml[domainName], domainName, path, targetDev, bus)
	}
	f.attachDiskN++
	f.record("attach-disk", domainName, fmt.Sprintf("path=%s target=%s bus=%s", path, targetDev, bus))
	return nil
}
func (f *Fake) DetachDisk(domainName, targetDev string) error {
	if f.FailDetachDisk != nil {
		if err := f.FailDetachDisk(domainName, targetDev); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.diskSources[domainName] != nil {
		delete(f.diskSources[domainName], targetDev)
	}
	// The real DetachDisk applies DomainDeviceModifyLive|Config, so the disk leaves the
	// persistent (inactive) definition too — unless a scenario models a live-only
	// divergence, in which case the config keeps the disk.
	if !f.SkipConfigOnDiskMutation {
		f.xml[domainName] = removeDiskFromDomainXML(f.xml[domainName], targetDev)
	}
	f.detachDiskN++
	f.record("detach-disk", domainName, "target="+targetDev)
	return nil
}

// diskDevInDomainXML reports whether a domain XML carries a <target dev='X'.../>
// (either quote style). Mirrors grpcapi.diskDevInXML — the substring the
// running-path membership verification keys off.
func diskDevInDomainXML(domainXML, targetDev string) bool {
	if domainXML == "" || targetDev == "" {
		return false
	}
	return strings.Contains(domainXML, "dev='"+targetDev+"'") || strings.Contains(domainXML, `dev="`+targetDev+`"`)
}

// insertDiskIntoDomainXML adds a <disk> element carrying <target dev='X'.../> to a
// domain's persistent XML, synthesizing a minimal skeleton when the domain has no
// stored XML yet (a running fake VM seeded without DefineDomain). Idempotent: an
// already-present target dev is left untouched.
func insertDiskIntoDomainXML(domainXML, domainName, path, targetDev, bus string) string {
	if domainXML == "" {
		domainXML = "<domain type='kvm'><name>" + domainName + "</name><devices></devices></domain>"
	}
	if diskDevInDomainXML(domainXML, targetDev) {
		return domainXML
	}
	disk := "<disk type='file' device='disk'><source file='" + path + "'/><target dev='" + targetDev + "' bus='" + bus + "'/></disk>"
	if strings.Contains(domainXML, "</devices>") {
		return strings.Replace(domainXML, "</devices>", disk+"</devices>", 1)
	}
	return domainXML + disk
}

// removeDiskFromDomainXML removes the <disk>…</disk> element whose <target dev>
// matches targetDev from a domain's persistent XML, leaving any other disks intact.
func removeDiskFromDomainXML(domainXML, targetDev string) string {
	if domainXML == "" {
		return domainXML
	}
	needleA := "dev='" + targetDev + "'"
	needleB := `dev="` + targetDev + `"`
	from := 0
	for {
		rel := strings.Index(domainXML[from:], "<disk")
		if rel < 0 {
			return domainXML
		}
		start := from + rel
		endRel := strings.Index(domainXML[start:], "</disk>")
		if endRel < 0 {
			return domainXML
		}
		end := start + endRel + len("</disk>")
		if block := domainXML[start:end]; strings.Contains(block, needleA) || strings.Contains(block, needleB) {
			return domainXML[:start] + domainXML[end:]
		}
		from = end
	}
}

// AttachDiskCount / DetachDiskCount return how many times the disk hot-plug
// primitives have been invoked — test accessors for at-most-once assertions.
func (f *Fake) AttachDiskCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachDiskN
}
func (f *Fake) DetachDiskCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachDiskN
}

// AttachNIC hot-attaches a NIC to domainName, tracking both the live view
// (activeXML — ALWAYS updated, mirroring a real live attach landing immediately)
// and, unless SkipConfigOnNICMutation models a live-succeeded-but-config-not-
// applied divergence, the persistent view (xml) too — the real AttachNIC applies
// DomainDeviceModifyLive|Config.
func (f *Fake) AttachNIC(domainName, bridge, model, mac string) error {
	if f.FailAttachNIC != nil {
		if err := f.FailAttachNIC(domainName, bridge, model, mac); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[domainName] = insertNICIntoDomainXML(f.activeBaseline(domainName), domainName, bridge, model, mac)
	if !f.SkipConfigOnNICMutation {
		f.xml[domainName] = insertNICIntoDomainXML(f.xml[domainName], domainName, bridge, model, mac)
	}
	f.attachNICN++
	f.record("attach-nic", domainName, fmt.Sprintf("bridge=%s mac=%s", bridge, mac))
	return nil
}

// DetachNIC hot-detaches a NIC from domainName by MAC, mirroring AttachNIC's
// live/persistent tracking split.
func (f *Fake) DetachNIC(domainName, mac string) error {
	if f.FailDetachNIC != nil {
		if err := f.FailDetachNIC(domainName, mac); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[domainName] = removeNICFromDomainXML(f.activeBaseline(domainName), mac)
	if !f.SkipConfigOnNICMutation {
		f.xml[domainName] = removeNICFromDomainXML(f.xml[domainName], mac)
	}
	f.detachNICN++
	f.record("detach-nic", domainName, "mac="+mac)
	return nil
}

// nicMacInDomainXML reports whether a domain XML carries an <interface> with the
// given MAC address (case-insensitive — real libvirt normalizes MAC case, and
// callers may supply either). Mirrors grpcapi.nicMacInXML — the substring the
// hotplug NIC membership verification keys off.
func nicMacInDomainXML(domainXML, mac string) bool {
	if domainXML == "" || mac == "" {
		return false
	}
	lx := strings.ToLower(domainXML)
	lm := strings.ToLower(mac)
	return strings.Contains(lx, "address='"+lm+"'") || strings.Contains(lx, `address="`+lm+`"`)
}

// insertNICIntoDomainXML adds an <interface> element carrying the given MAC to a
// domain's XML, synthesizing a minimal skeleton when the domain has no XML yet.
// Idempotent: an already-present MAC is left untouched.
func insertNICIntoDomainXML(domainXML, domainName, bridge, model, mac string) string {
	if domainXML == "" {
		domainXML = "<domain type='kvm'><name>" + domainName + "</name><devices></devices></domain>"
	}
	if nicMacInDomainXML(domainXML, mac) {
		return domainXML
	}
	iface := "<interface type='bridge'><source bridge='" + bridge + "'/>" +
		"<mac address='" + mac + "'/><model type='" + model + "'/></interface>"
	if strings.Contains(domainXML, "</devices>") {
		return strings.Replace(domainXML, "</devices>", iface+"</devices>", 1)
	}
	return domainXML + iface
}

// removeNICFromDomainXML removes the <interface>…</interface> element whose <mac
// address> matches mac from a domain's XML, leaving any other interfaces intact.
// Case-insensitive matching mirrors nicMacInDomainXML; indices are computed on a
// lower-cased copy but sliced from the original (ASCII-only XML, so byte offsets
// align) to preserve the original text's casing.
func removeNICFromDomainXML(domainXML, mac string) string {
	if domainXML == "" {
		return domainXML
	}
	lm := strings.ToLower(mac)
	needleA := "address='" + lm + "'"
	needleB := `address="` + lm + `"`
	lx := strings.ToLower(domainXML)
	from := 0
	for {
		rel := strings.Index(lx[from:], "<interface")
		if rel < 0 {
			return domainXML
		}
		start := from + rel
		endRel := strings.Index(lx[start:], "</interface>")
		if endRel < 0 {
			return domainXML
		}
		end := start + endRel + len("</interface>")
		if block := lx[start:end]; strings.Contains(block, needleA) || strings.Contains(block, needleB) {
			return domainXML[:start] + domainXML[end:]
		}
		from = end
	}
}

// AttachNICCount / DetachNICCount return how many times the NIC hot-plug primitives
// have been invoked — test accessors for at-most-once assertions.
func (f *Fake) AttachNICCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachNICN
}
func (f *Fake) DetachNICCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachNICN
}

// AttachHostdev hot-attaches a PCI passthrough device WITHOUT a user alias — the
// legacy SR-IOV/type running-only path. It models the live+persistent membership
// (keyed on the pci address for later detach) exactly like AttachHostdevWithAlias
// with an empty alias.
func (f *Fake) AttachHostdev(domainName, pciAddress string) error {
	return f.AttachHostdevWithAlias(domainName, pciAddress, "")
}

// AttachHostdevWithAlias hot-attaches a PCI passthrough device carrying a stable
// user alias (ua-<device>-<member>), tracking both the live view (activeXML —
// always updated, mirroring a real live attach landing immediately) and, unless
// SkipConfigOnHostdevMutation models a live-succeeded-but-config-not-applied
// divergence, the persistent view (xml) too — the real attach applies
// DomainDeviceModifyLive|Config.
func (f *Fake) AttachHostdevWithAlias(domainName, pciAddress, alias string) error {
	if f.FailAttachHostdev != nil {
		if err := f.FailAttachHostdev(domainName, pciAddress, alias); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[domainName] = insertHostdevIntoDomainXML(f.activeBaseline(domainName), domainName, pciAddress, alias)
	if !f.SkipConfigOnHostdevMutation {
		f.xml[domainName] = insertHostdevIntoDomainXML(f.xml[domainName], domainName, pciAddress, alias)
	}
	f.attachHostdevN++
	f.record("attach-hostdev", domainName, fmt.Sprintf("pci=%s alias=%s", pciAddress, alias))
	return nil
}

// DetachHostdev hot-detaches a PCI passthrough device by its pci address,
// mirroring AttachHostdevWithAlias's live/persistent tracking split.
func (f *Fake) DetachHostdev(domainName, pciAddress string) error {
	if f.FailDetachHostdev != nil {
		if err := f.FailDetachHostdev(domainName, pciAddress); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeXML[domainName] = removeHostdevFromDomainXML(f.activeBaseline(domainName), pciAddress)
	if !f.SkipConfigOnHostdevMutation {
		f.xml[domainName] = removeHostdevFromDomainXML(f.xml[domainName], pciAddress)
	}
	f.detachHostdevN++
	f.record("detach-hostdev", domainName, "pci="+pciAddress)
	return nil
}

// DetachHostdevConfig removes a PCI passthrough device from the PERSISTENT (inactive)
// view ONLY — the config-only detach a shut-off domain requires. Unlike DetachHostdev it
// never touches the live view (activeXML): there is no live instance to modify. It counts
// separately (detachHostdevConfigN) so a test can assert the config path (not the live
// one) was used on a shut-off domain.
func (f *Fake) DetachHostdevConfig(domainName, pciAddress string) error {
	if f.FailDetachHostdevConfig != nil {
		if err := f.FailDetachHostdevConfig(domainName, pciAddress); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.xml[domainName] = removeHostdevFromDomainXML(f.xml[domainName], pciAddress)
	f.detachHostdevConfigN++
	f.record("detach-hostdev-config", domainName, "pci="+pciAddress)
	return nil
}

// AttachHostdevCount / DetachHostdevCount return how many times the hostdev
// hot-plug primitives have been invoked — test accessors for at-most-once
// assertions.
func (f *Fake) AttachHostdevCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachHostdevN
}
func (f *Fake) DetachHostdevCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachHostdevN
}

// DetachHostdevConfigCount returns how many times the CONFIG-only hostdev detach has been
// invoked — the shut-off reclaim path's at-most-once / config-vs-live test accessor.
func (f *Fake) DetachHostdevConfigCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachHostdevConfigN
}

// hostdevAliasInDomainXML reports whether a domain XML carries a <hostdev> whose
// <alias name=...> matches alias (either quote style). Mirrors
// grpcapi.hostdevAliasInXML — the substring the running-path hostdev membership
// verification keys off.
func hostdevAliasInDomainXML(domainXML, alias string) bool {
	if domainXML == "" || alias == "" {
		return false
	}
	return strings.Contains(domainXML, "name='"+alias+"'") || strings.Contains(domainXML, `name="`+alias+`"`)
}

// insertHostdevIntoDomainXML adds a <hostdev> element carrying the pci address
// (as a data-pci attribute so DetachHostdev can match it) and, when non-empty, an
// <alias> child, to a domain's XML — synthesizing a minimal skeleton when the
// domain has no XML yet. Idempotent on the alias when one is set.
func insertHostdevIntoDomainXML(domainXML, domainName, pciAddress, alias string) string {
	if domainXML == "" {
		domainXML = "<domain type='kvm'><name>" + domainName + "</name><devices></devices></domain>"
	}
	if alias != "" && hostdevAliasInDomainXML(domainXML, alias) {
		return domainXML
	}
	hd := "<hostdev mode='subsystem' type='pci' managed='yes' data-pci='" + pciAddress + "'>"
	// Emit the <source><address> the way real libvirt does so
	// libvirt.HostdevSourcePCIAddresses (the by-source-BDF membership authority the
	// legacy detach path reads — legacy hostdevs carry no alias) can find this device.
	if pciAddress != "" {
		p := libvirt.ParsePCIAddress(pciAddress)
		hd += "<source><address domain='" + p.Domain + "' bus='" + p.Bus +
			"' slot='" + p.Slot + "' function='" + p.Function + "'/></source>"
	}
	if alias != "" {
		hd += "<alias name='" + alias + "'/>"
	}
	hd += "</hostdev>"
	if strings.Contains(domainXML, "</devices>") {
		return strings.Replace(domainXML, "</devices>", hd+"</devices>", 1)
	}
	return domainXML + hd
}

// removeHostdevFromDomainXML removes the <hostdev>…</hostdev> element whose
// data-pci attribute matches pciAddress, leaving any other hostdevs intact.
func removeHostdevFromDomainXML(domainXML, pciAddress string) string {
	if domainXML == "" {
		return domainXML
	}
	needleA := "data-pci='" + pciAddress + "'"
	needleB := `data-pci="` + pciAddress + `"`
	from := 0
	for {
		rel := strings.Index(domainXML[from:], "<hostdev")
		if rel < 0 {
			return domainXML
		}
		start := from + rel
		endRel := strings.Index(domainXML[start:], "</hostdev>")
		if endRel < 0 {
			return domainXML
		}
		end := start + endRel + len("</hostdev>")
		if block := domainXML[start:end]; strings.Contains(block, needleA) || strings.Contains(block, needleB) {
			return domainXML[:start] + domainXML[end:]
		}
		from = end
	}
}
func (f *Fake) BlockResize(domainName, path string, sizeBytes int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("block-resize", domainName, fmt.Sprintf("path=%s size=%d", path, sizeBytes))
	return nil
}
func (f *Fake) SetBootOrder(domainName, bootOrder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("boot-order", domainName, bootOrder)
	return nil
}

// Migration — record and pretend success.

func (f *Fake) MigrateToTarget(name, dconnuri string, p libvirt.MigrateParams) error {
	if f.FailMigrateToTarget != nil {
		if err := f.FailMigrateToTarget(name, dconnuri); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("migrate", name, "to="+dconnuri)
	return nil
}

func (f *Fake) DomainJobProgress(name string) (memPct, diskPct float32) {
	return 100, 100
}

// Snapshots.

func (f *Fake) CreateSnapshot(domainName, snapshotName string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snapshots[domainName] == nil {
		f.snapshots[domainName] = map[string]struct{}{}
	}
	f.snapshots[domainName][snapshotName] = struct{}{}
	f.cutoverDisks(domainName, snapshotName)
	f.record("snapshot", domainName, snapshotName)
	return time.Now().UnixNano(), nil
}
func (f *Fake) RevertToSnapshot(domainName, snapshotName string, restorePreDefine func() error) error {
	f.mu.Lock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: no snapshot %q for %q", snapshotName, domainName)
	}
	f.record("revert", domainName, snapshotName)
	f.mu.Unlock()
	if restorePreDefine != nil {
		return restorePreDefine()
	}
	return nil
}
func (f *Fake) DeleteSnapshot(domainName, snapshotName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.snapshots[domainName], snapshotName)
	f.record("snapshot-delete", domainName, snapshotName)
	return nil
}
func (f *Fake) FlattenSnapshot(domainName, snapshotName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		return fmt.Errorf("libvirtfake: no snapshot %q for %q", snapshotName, domainName)
	}
	delete(f.snapshots[domainName], snapshotName)
	f.record("snapshot-flatten", domainName, snapshotName)
	return nil
}

func (f *Fake) CreateLiveSnapshot(domainName, snapshotName, vmstatePath string, captureSuspended func() error) (diskBytes, vmstateBytes int64, err error) {
	f.mu.Lock()
	if f.snapshots[domainName] == nil {
		f.snapshots[domainName] = map[string]struct{}{}
	}
	f.snapshots[domainName][snapshotName] = struct{}{}
	f.cutoverDisks(domainName, snapshotName)
	f.record("snapshot-live", domainName, snapshotName)
	f.mu.Unlock()
	if f.FailCreateLiveSnapshot != nil {
		if err := f.FailCreateLiveSnapshot(domainName, snapshotName); err != nil {
			return 0, 0, err
		}
	}
	if captureSuspended != nil {
		if err := captureSuspended(); err != nil {
			return 0, 0, err
		}
	}
	return time.Now().UnixNano(), 4096, nil
}

// SetDiskSource sets a domain's disk source (test helper).
func (f *Fake) SetDiskSource(domain, dev, src string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.diskSources[domain] == nil {
		f.diskSources[domain] = map[string]string{}
	}
	f.diskSources[domain][dev] = src
}

// DomainDiskSources returns target-dev → live source. Defaults to a single
// vda disk if nothing was configured for the domain.
func (f *Fake) DomainDiskSources(domain string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.diskSources[domain] {
		out[k] = v
	}
	if len(out) == 0 {
		out["vda"] = "/var/lib/litevirt/disks/" + domain + "-root.qcow2"
	}
	return out, nil
}

// cutoverDisks simulates libvirt's external-snapshot overlay rename: each disk
// source <stem>.<ext> becomes <stem>.<snapname>. Caller holds f.mu.
func (f *Fake) cutoverDisks(domain, snapname string) {
	if f.diskSources[domain] == nil {
		f.diskSources[domain] = map[string]string{"vda": "/var/lib/litevirt/disks/" + domain + "-root.qcow2"}
	}
	for dev, src := range f.diskSources[domain] {
		f.diskSources[domain][dev] = strings.TrimSuffix(src, filepath.Ext(src)) + "." + snapname
	}
}

func (f *Fake) RevertToLiveSnapshot(domainName, snapshotName, vmstatePath string, restorePreDefine func() error) error {
	f.mu.Lock()
	if _, ok := f.snapshots[domainName][snapshotName]; !ok {
		f.mu.Unlock()
		return fmt.Errorf("libvirtfake: no snapshot %q for %q", snapshotName, domainName)
	}
	f.record("revert-live", domainName, snapshotName)
	f.mu.Unlock()
	if restorePreDefine != nil {
		return restorePreDefine()
	}
	return nil
}

func (f *Fake) FreezeGuest(domainName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("fs-freeze", domainName, "")
	return nil
}

func (f *Fake) ThawGuest(domainName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("fs-thaw", domainName, "")
	return nil
}

func (f *Fake) SetMemory(domainName string, memMiB int) error {
	if f.FailSetMemory != nil {
		if err := f.FailSetMemory(domainName, memMiB); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("set-memory", domainName, fmt.Sprintf("%d", memMiB))
	return nil
}

func (f *Fake) SetVCPUs(name string, count int) error {
	if f.FailSetVCPUs != nil {
		if err := f.FailSetVCPUs(name, count); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("set-vcpus", name, fmt.Sprintf("%d", count))
	return nil
}

// Stats / introspection.

func (f *Fake) NodeInfo() (cpus int, memMiB int, err error) {
	return 8, 32 * 1024, nil
}
func (f *Fake) GetDomainStats(name string) (*libvirt.DomainStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.stats[name]; ok {
		return s, nil
	}
	return &libvirt.DomainStats{Name: name}, nil
}
func (f *Fake) GetAllDomainStats() ([]*libvirt.DomainStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*libvirt.DomainStats, 0, len(f.domains))
	for n := range f.domains {
		if s, ok := f.stats[n]; ok {
			out = append(out, s)
		} else {
			out = append(out, &libvirt.DomainStats{Name: n})
		}
	}
	return out, nil
}

func (f *Fake) ExecInGuest(name, command string, args []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("exec-in-guest", name, command)
	return "", nil
}

func (f *Fake) EnsureStoragePool(name, driver, source, target string, opts map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ensure-pool", name, driver)
	return nil
}

// PoolDestroyIfDefined records the libvirt-undefine belt-and-suspenders step on
// pool delete. Idempotent in the real client (no-op when the pool isn't defined);
// here it always records so a test can assert the delete path reached it. A
// FailPoolDestroy hook lets a scenario model an undefine failure.
func (f *Fake) PoolDestroyIfDefined(name string) error {
	if f.FailPoolDestroy != nil {
		if err := f.FailPoolDestroy(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("pool-destroy", name, "")
	return nil
}

func (f *Fake) ConfigureVLANTap(domainName, bridge, mac string, vlanID int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("vlan-tap", domainName, fmt.Sprintf("bridge=%s mac=%s vlan=%d", bridge, mac, vlanID))
	return nil
}
func (f *Fake) ConfigureTrunkTap(domainName, bridge, mac string, vlanIDs []int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("trunk-tap", domainName, fmt.Sprintf("bridge=%s mac=%s vlans=%v", bridge, mac, vlanIDs))
	return nil
}

// TapDevice returns a deterministic fake tap name derived from the domain so
// fleet tests can exercise the firewall's per-NIC binding path.
func (f *Fake) TapDevice(domainName, mac string) (string, error) {
	return "tap-" + domainName, nil
}

// Lifecycle hooks — daemon-only paths; the fake no-ops them.

func (f *Fake) StartReconnectLoop(ctx context.Context) {}
func (f *Fake) RegisterDomainEventCallback(cb libvirt.DomainEventCallback) {
	// Scenarios that want to drive callbacks can call Fake.FireEvent
	// directly (TODO if needed).
}
func (f *Fake) Close() error { return nil }
