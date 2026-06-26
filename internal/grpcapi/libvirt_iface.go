package grpcapi

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// LibvirtBackend is the contract `*grpcapi.Server` consumes from the
// libvirt layer. Lifting this out as an interface lets the in-process
// fleet harness (and other test surfaces) substitute a fake without
// pulling go-libvirt's TCP/unix-socket client into the test process.
//
// `*libvirt.Client` satisfies this interface via structural typing —
// no production code change is needed at the daemon construction site
// because the concrete type's method set is a superset.
//
// Keep this interface a *strict* superset of what server-side handlers
// actually call. If you add a method to *libvirt.Client that grpcapi
// needs, add it here too — otherwise the fake won't know to mock it
// and the test will compile but fail at runtime when a handler hits
// the unimplemented path.
type LibvirtBackend interface {
	// Domain lifecycle.
	DefineDomain(xmlConfig string) error
	StartDomain(name string) error
	ShutdownDomain(name string) error
	DestroyDomain(name string) error
	UndefineDomain(name string, removeStorage bool) error
	UndefineDomainPreservingState(name string) error // undefine keeping NVRAM/vTPM (redefine-class, G1)
	DomainState(name string) (string, error)
	DomainExists(name string) bool
	ListDomains() ([]string, error)
	DumpXML(name string) (string, error)
	WaitForShutdown(name string, timeout time.Duration) bool

	// VNC / SPICE.
	GetVMVNCPort(name string) (int, error)
	GetVMSpicePort(name string) (int, error)
	ConsolePTYPath(name string) (string, error)

	// Hot-plug.
	AttachDisk(domainName, path, targetDev, bus string) error
	DetachDisk(domainName, targetDev string) error
	AttachNIC(domainName, bridge, model, mac string) error
	DetachNIC(domainName, mac string) error
	AttachHostdev(domainName, pciAddress string) error
	DetachHostdev(domainName, pciAddress string) error
	BlockResize(domainName, path string, sizeBytes int64) error
	SetBootOrder(domainName, bootOrder string) error

	// Migration.
	MigrateToTarget(name, dconnuri string, p libvirt.MigrateParams) error
	DomainJobProgress(name string) (memPct, diskPct float32)

	// Block-pull (live-restore localize): flatten an NBD-backed overlay's
	// backing chain into the overlay, polling BlockJobStatus to completion.
	BlockPull(domain, disk string) error
	BlockJobStatus(domain, disk string) (libvirt.BlockJobStatus, error)

	// Snapshots.
	CreateSnapshot(domainName, snapshotName string) (int64, error)
	RevertToSnapshot(domainName, snapshotName string, restorePreDefine func() error) error
	DeleteSnapshot(domainName, snapshotName string) error
	// FlattenSnapshot live-merges each disk's active overlay down into the named
	// snapshot's base (block-commit + pivot), then drops the snapshot metadata —
	// leaving the running VM on a single standalone disk (no backing chain). Used
	// when deleting the last snapshot so the disk stops growing a chain and stays
	// migratable. Running domains only.
	FlattenSnapshot(domainName, snapshotName string) error
	// Live/RAM snapshots (#3): capture guest RAM into vmstatePath alongside the
	// external disk snapshot, and revert both to the snapshot instant.
	CreateLiveSnapshot(domainName, snapshotName, vmstatePath string, captureSuspended func() error) (diskBytes, vmstateBytes int64, err error)
	RevertToLiveSnapshot(domainName, snapshotName, vmstatePath string, restorePreDefine func() error) error
	// DomainDiskSources returns target-dev → live source-file. Used to reconcile
	// vm_disks.path after a snapshot op moves the domain onto an overlay
	// (<disk>.<snapname>), so backup/migration/restart use the real active disk.
	DomainDiskSources(domainName string) (map[string]string, error)

	// Guest filesystem quiesce (#2): freeze/thaw via the qemu-guest-agent so a
	// backup captures an application-consistent point-in-time.
	FreezeGuest(domainName string) error
	ThawGuest(domainName string) error

	// Memory ballooning (#4): set the live balloon target (MiB) on a running VM.
	SetMemory(domainName string, memMiB int) error

	// Stats / introspection.
	NodeInfo() (cpus int, memMiB int, err error)
	GetDomainStats(name string) (*libvirt.DomainStats, error)
	GetAllDomainStats() ([]*libvirt.DomainStats, error)

	// In-guest exec (qemu-guest-agent).
	ExecInGuest(name, command string, args []string) (string, error)

	// Storage pool ensure (CreateVM path).
	EnsureStoragePool(name, driver, source, target string, opts map[string]string) error

	// VLAN tap configuration — invoked after CreateVM's StartDomain
	// to push bridge-vlan rules onto the tap device libvirt created.
	ConfigureVLANTap(domainName, bridge, mac string, vlanID int) error
	ConfigureTrunkTap(domainName, bridge, mac string, vlanIDs []int) error
	// TapDevice returns the host tap name for a domain NIC (by MAC), read from
	// the live domain XML. Recorded into vm_interfaces.tap_device so the
	// distributed firewall's per-NIC tier can target the interface.
	TapDevice(domainName, mac string) (string, error)

	// Daemon lifecycle wiring — used by daemon.Run, not handlers.
	// Included so we can pass the same backend through.
	StartReconnectLoop(ctx context.Context)
	RegisterDomainEventCallback(cb libvirt.DomainEventCallback)
	Close() error
}

// Compile-time guard: the real client must continue to satisfy the
// interface as both surfaces evolve. If you add a method to the
// interface, this line will fail to compile until *libvirt.Client
// implements it — that's the design.
var _ LibvirtBackend = (*libvirt.Client)(nil)
