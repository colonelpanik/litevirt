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
	snapshots   map[string]map[string]struct{} // domain → snapshot names
	diskSources map[string]map[string]string   // domain → target-dev → source file
	stats       map[string]*libvirt.DomainStats
	reasons     map[string]string // domain → injected DomainStateReason.Reason
	events      []Event

	// Optional time source for events. Defaults to time.Now.
	Now func() time.Time

	// Fail* hooks let scenarios inject failures into specific methods.
	// Nil = default success.
	FailDefineDomain    func(xml string) error
	FailStartDomain     func(name string) error
	FailShutdownDomain  func(name string) error
	FailUndefineDomain  func(name string, removeStorage bool) error
	FailUndefinePreserv func(name string) error
	// FailCreateLiveSnapshot fires AFTER the disk overlay has cut over, modeling a
	// RAM-save/capture failure that leaves the VM on an overlay.
	FailCreateLiveSnapshot func(domain, snap string) error
	FailDomainState        func(name string) error
	FailDomainStateReason  func(name string) error
	FailMigrateToTarget    func(name, dconnuri string) error
	FailBlockPull          func(domain, disk string) error
	FailPoolDestroy        func(name string) error
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

func (f *Fake) DumpXML(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.xml[name]; ok {
		return x, nil
	}
	return "", fmt.Errorf("libvirtfake: no XML for %q", name)
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("attach-disk", domainName, fmt.Sprintf("path=%s target=%s bus=%s", path, targetDev, bus))
	return nil
}
func (f *Fake) DetachDisk(domainName, targetDev string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("detach-disk", domainName, "target="+targetDev)
	return nil
}
func (f *Fake) AttachNIC(domainName, bridge, model, mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("attach-nic", domainName, fmt.Sprintf("bridge=%s mac=%s", bridge, mac))
	return nil
}
func (f *Fake) DetachNIC(domainName, mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("detach-nic", domainName, "mac="+mac)
	return nil
}
func (f *Fake) AttachHostdev(domainName, pciAddress string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("attach-hostdev", domainName, "pci="+pciAddress)
	return nil
}
func (f *Fake) DetachHostdev(domainName, pciAddress string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("detach-hostdev", domainName, "pci="+pciAddress)
	return nil
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("set-memory", domainName, fmt.Sprintf("%d", memMiB))
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
