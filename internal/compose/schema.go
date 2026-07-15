// Package compose parses litevirt compose YAML files and generates execution plans.
package compose

import "fmt"

// File is the top-level compose document.
type File struct {
	Version  string                `yaml:"version"`
	Name     string                `yaml:"name"`
	Images   map[string]ImageDef   `yaml:"images"`
	Networks map[string]NetworkDef `yaml:"networks"`
	Volumes  map[string]VolumeDef  `yaml:"volumes"`
	VMs      map[string]VMDef      `yaml:"vms"`
	// Workloads is the unified container/VM map; entries with
	// `kind: lxc | oci` route to the Containers runtime. Entries
	// without `kind:` (or `kind: vm`) behave identically to a `vms:`
	// entry. The parser folds `workloads:` into `VMs` after load so
	// existing compose code only needs to look at `VMs`.
	Workloads     map[string]VMDef  `yaml:"workloads,omitempty"`
	DNS           *DNSDef           `yaml:"dns"`
	Notifications *NotificationsDef `yaml:"notifications"`

	// BackupRepos registers logical backup-repo name → path mappings for the
	// cluster, so a VM's `backup: { repo: <name> }` resolves without editing
	// daemon config. CRDT-replicated; removed when the stack is deleted.
	BackupRepos map[string]BackupRepoDef `yaml:"backup-repos,omitempty"`

	// SecurityGroups defines reusable rule sets that NICs reference by
	// name (NetworkAttachment.SecurityGroups). distributed
	// firewall.
	SecurityGroups map[string]SecurityGroupDef `yaml:"security-groups,omitempty"`

	// IPSets defines named address lists. Rules can reference one with
	// `cidr: "@<ipset-name>"`. Same scoping as SecurityGroups.
	IPSets map[string]IPSetDef `yaml:"ipsets,omitempty"`

	// FirewallDefaults sets cluster-wide policy + cluster-tier rules
	// that apply to every NIC under this stack. Per-host overrides
	// live in the host config rather than compose.
	FirewallDefaults *FirewallDefaultsDef `yaml:"firewall,omitempty"`
}

// SecurityGroupDef is a named bundle of firewall rules.
type SecurityGroupDef struct {
	Description string            `yaml:"description,omitempty"`
	Rules       []FirewallRuleDef `yaml:"rules"`
}

// IPSetDef is a named CIDR list, rendered as an nftables set object.
type IPSetDef struct {
	Description string   `yaml:"description,omitempty"`
	CIDRs       []string `yaml:"cidrs"`
}

// BackupRepoDef registers a logical backup-repo name → on-disk path.
type BackupRepoDef struct {
	Path string `yaml:"path"`
}

// FirewallRuleDef is one rule inside a security group or the firewall
// defaults block. Mirrors internal/firewall.Rule but lives in the
// compose package so YAML stays free of internal types.
type FirewallRuleDef struct {
	Direction string `yaml:"direction"`        // "ingress" | "egress"
	Proto     string `yaml:"proto,omitempty"`  // "tcp" | "udp" | "icmp" | "all"
	Port      string `yaml:"port,omitempty"`   // "80" | "8000-9000"
	CIDR      string `yaml:"cidr,omitempty"`   // CIDR or "@ipset"
	Action    string `yaml:"action,omitempty"` // "accept" | "drop" | "reject"
	Comment   string `yaml:"comment,omitempty"`
}

// FirewallDefaultsDef sets cluster-tier rules and the default policy.
type FirewallDefaultsDef struct {
	// DefaultDeny, when true, makes the forward chain's default policy
	// drop. Anything not explicitly accepted is dropped. Reply traffic
	// is always allowed (conntrack established/related).
	DefaultDeny bool `yaml:"default-deny,omitempty"`
	// ClusterRules apply before per-NIC rules. Use them for blanket
	// allow/deny that should never be overridden.
	ClusterRules []FirewallRuleDef `yaml:"cluster-rules,omitempty"`
}

// ImageDef describes a base image reference.
type ImageDef struct {
	Source   string `yaml:"source"`
	Format   string `yaml:"format"` // qcow2 | iso
	Checksum string `yaml:"checksum"`
}

// NetworkDef describes a logical network.
type NetworkDef struct {
	Type          string   `yaml:"type"`      // bridge | vxlan | isolated | sriov | direct
	Interface     string   `yaml:"interface"` // bridge name on host
	VLAN          int      `yaml:"vlan"`
	VNI           int      `yaml:"vni"`
	Underlay      string   `yaml:"underlay"`
	Learning      bool     `yaml:"learning"`
	Port          int      `yaml:"port"`
	Subnet        string   `yaml:"subnet"`
	DHCP          bool     `yaml:"dhcp"`
	NAT           *bool    `yaml:"nat"` // enable NAT/masquerade (default true)
	PF            string   `yaml:"pf"`  // SR-IOV physical function
	SpoofCheck    bool     `yaml:"spoof-check"`
	External      bool     `yaml:"external"`       // use pre-existing network, don't create/destroy
	HostIsolation bool     `yaml:"host-isolation"` // block VM→host management traffic
	DNS           []string `yaml:"dns"`            // DNS resolvers for isolated VMs (default: 1.1.1.1, 8.8.8.8)
}

// NATEnabled returns true unless NAT is explicitly disabled.
func (n NetworkDef) NATEnabled() bool {
	if n.NAT == nil {
		return true
	}
	return *n.NAT
}

// Workloads is the unified container/VM map. Each entry has a Kind
// discriminator: "vm" (default) for a libvirt-managed VM, or "lxc" /
// "oci" for a container. Existing stacks that use the legacy `vms:`
// map keep working because the parser folds it into Workloads with
// Kind="vm".
type WorkloadKind string

const (
	WorkloadKindVM  WorkloadKind = "vm"
	WorkloadKindLXC WorkloadKind = "lxc"
	WorkloadKindOCI WorkloadKind = "oci"
)

// VolumeDef describes a named volume / disk pool.
//
// Supported drivers:
//
//	local     — qcow2 files under <dataDir>/disks (or Target).
//	dir       — qcow2 files under an operator-specified Target directory.
//	nfs       — Source is "host:/export"; mounted lazily under Target.
//	iscsi     — Source is the IQN; LUNs are pre-provisioned on the SAN.
//	ceph      — Source is the pool name; rbd CLI shell-out.
//	zfs       — Source is the parent dataset (e.g. "tank/litevirt").
//	btrfs     — Source is an absolute path on a btrfs filesystem.
//	lvm-thin  — Source is the VG; options.thinpool is required.
type VolumeDef struct {
	Driver  string            `yaml:"driver"`
	Source  string            `yaml:"source"`
	Target  string            `yaml:"target"`
	Options map[string]string `yaml:"options"`
}

// VMDef is a full VM specification inside a compose file. Despite the
// name it covers containers too — the Kind field discriminates. New
// stacks should use the unified `workloads:` map; `vms:` is preserved
// as a legacy alias that defaults Kind to vm.
type VMDef struct {
	// Service inheritance — resolved before validation.
	Extends string `yaml:"extends"`

	// Kind selects the runtime: "vm" (default), "lxc", or "oci".
	// "oci" pulls an OCI image and runs it as an LXC container.
	Kind WorkloadKind `yaml:"kind,omitempty"`

	// Image & Boot
	Image    string `yaml:"image"`
	ISO      string `yaml:"iso"`
	Firmware string `yaml:"firmware"` // uefi | bios
	Machine  string `yaml:"machine"`  // q35 | pc

	// Compute
	CPU     int    `yaml:"cpu"`
	MaxCPU  int    `yaml:"max-cpu"`  // vCPU hotplug ceiling (> cpu) for live CPU hot-add; requires live_resize
	CPUMode string `yaml:"cpu-mode"` // host-passthrough | host-model | custom
	Memory  Memory `yaml:"memory"`   // int MiB or string "8G"
	// Memory ballooning (#4). max-memory (> memory) raises the balloon ceiling
	// so the guest can be inflated up to it; min-memory is the floor the host may
	// reclaim to. Both accept int MiB or "8G" strings. 0/unset = fixed memory.
	MinMemory Memory `yaml:"min-memory"`
	MaxMemory Memory `yaml:"max-memory"`

	// Boot ordering (#10). onboot autostarts the VM when its host boots;
	// startup-order sequences onboot VMs (lower first); start-delay/stop-delay
	// pace the ordered start/stop.
	Onboot       bool `yaml:"onboot"`
	StartupOrder int  `yaml:"startup-order"`
	StartDelay   int  `yaml:"start-delay"`
	StopDelay    int  `yaml:"stop-delay"`

	// Replicas — pointer so we can distinguish "omitted" (nil → default 1)
	// from explicit "replicas: 0" (scale-to-zero).
	Replicas *int `yaml:"replicas"`

	// Guest agent
	GuestAgent *bool `yaml:"guest-agent"`

	// Graphics console preferences. Empty = VNC only (default).
	// `vnc: false` → headless. `spice: true` → add a SPICE device alongside VNC.
	Graphics *GraphicsDef `yaml:"graphics"`

	// Disks — supports both shorthand ("root: 20G") and full form
	Disks map[string]DiskDef `yaml:"disks"`

	// Network interfaces
	Network []NetworkAttachment `yaml:"network"`

	// Cloud-init
	CloudInit *CloudInitDef `yaml:"cloud-init"`

	// Placement
	Placement *PlacementDef `yaml:"placement"`

	// Migration policy
	Migrate *MigrateDef `yaml:"migrate"`

	// Update strategy
	Update *UpdateDef `yaml:"update"`

	// Load balancer
	LoadBalancer *LBDef `yaml:"loadbalancer"`

	// Health check
	HealthCheck *HealthCheckDef `yaml:"healthcheck"`

	// Lifecycle hooks
	Hooks *HooksDef `yaml:"hooks"`

	// Shutdown timeout
	StopGracePeriod string `yaml:"stop-grace-period"` // "30s", "2m" — ACPI shutdown timeout

	// Restart policy
	Restart *RestartDef `yaml:"restart"`

	// PCI device passthrough
	Devices []DeviceDef `yaml:"devices"`

	// Resource tuning
	Resources *ResourcesDef `yaml:"resources"`

	// Boot ordering
	DependsOn DependsOn `yaml:"depends-on"`

	// Labels
	Labels map[string]string `yaml:"labels"`

	// IP hint for non-cloud-init VMs
	IPHint string `yaml:"ip-hint"`

	// Backup configuration.
	// When unset the VM is not backed up by the scheduler — operators
	// can still take ad-hoc snapshots via `lv backup`.
	Backup *BackupDef `yaml:"backup"`
}

// BackupDef configures the PBS-equivalent backup pipeline for one VM.
// repo names a backup repository configured in the cluster ("backup-repos:"
// stanza). schedule is a cron expression evaluated by internal/scheduler;
// retention runs after each successful push.
type BackupDef struct {
	Repo       string        `yaml:"repo"`
	Schedule   string        `yaml:"schedule"` // cron (e.g. "0 2 * * *")
	Retention  *RetentionDef `yaml:"retention,omitempty"`
	Encryption string        `yaml:"encryption,omitempty"` // "" | "aes256gcm" | "tenant-key"
}

// RetentionDef expresses the same N daily / N weekly / N monthly /
// N yearly buckets as Proxmox PBS.
type RetentionDef struct {
	KeepLast    int `yaml:"keep-last"`
	KeepDaily   int `yaml:"keep-daily"`
	KeepWeekly  int `yaml:"keep-weekly"`
	KeepMonthly int `yaml:"keep-monthly"`
	KeepYearly  int `yaml:"keep-yearly"`
}

// Memory accepts both int (MiB) and string ("8G") YAML values.
type Memory int

func (m *Memory) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try int first
	var i int
	if err := unmarshal(&i); err == nil {
		*m = Memory(i)
		return nil
	}
	// Try string like "8G", "512M"
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := parseMemoryString(s)
	if err != nil {
		return fmt.Errorf("invalid memory value %q: %w", s, err)
	}
	*m = Memory(v)
	return nil
}

// DiskDef supports shorthand "20G" and full form.
type DiskDef struct {
	Size         string `yaml:"size"`
	Bus          string `yaml:"bus"`
	Cache        string `yaml:"cache"`
	Storage      string `yaml:"storage"`       // references volumes section
	ClusterSize  string `yaml:"cluster_size"`  // qcow2 cluster size (e.g. "64K", "2M")
	RefcountBits int    `yaml:"refcount_bits"` // qcow2 refcount width (1–64, default 16)
}

func (d *DiskDef) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try shorthand string "20G"
	var s string
	if err := unmarshal(&s); err == nil {
		d.Size = s
		return nil
	}
	// Full form
	type diskDefAlias DiskDef
	return unmarshal((*diskDefAlias)(d))
}

// NetworkAttachment is a VM's connection to a network.
type NetworkAttachment struct {
	Name    string `yaml:"name"`
	Model   string `yaml:"model"`
	IP      string `yaml:"ip"`
	Gateway string `yaml:"gateway"`
	MAC     string `yaml:"mac"`
	Trunk   []int  `yaml:"trunk"`

	// IPv6 / IPv6Gateway are the v6 counterparts. Empty = use SLAAC
	// (router advertisement) or DHCPv6 if the network is configured
	// for it. Networks themselves carry both an IPv4 subnet and an
	// optional IPv6 subnet — these per-NIC fields override defaults.
	IPv6        string `yaml:"ipv6,omitempty"`
	IPv6Gateway string `yaml:"ipv6-gateway,omitempty"`

	// SecurityGroups are names that resolve to top-level
	// security-groups: definitions. Empty = inherit cluster + host
	// rules only (no per-NIC SG layer).
	SecurityGroups []string `yaml:"security-groups,omitempty"`
}

// CloudInitDef holds cloud-init configuration.
type CloudInitDef struct {
	UserData      string            `yaml:"userdata"`
	NetworkConfig string            `yaml:"networkconfig"`
	MetaData      map[string]string `yaml:"metadata"`
}

// GraphicsDef controls which console graphics devices are attached to the
// VM. `vnc` defaults to true (most VMs need a display); `spice` opt-in.
type GraphicsDef struct {
	VNC   *bool `yaml:"vnc"`   // pointer so "vnc: false" disables; nil = default true
	SPICE bool  `yaml:"spice"` // explicit opt-in
}

// PlacementDef controls VM scheduling.
type PlacementDef struct {
	Host         string            `yaml:"host"`
	AntiAffinity []string          `yaml:"anti-affinity"`
	Affinity     []string          `yaml:"affinity"`
	Require      map[string]string `yaml:"require"`
	Prefer       map[string]string `yaml:"prefer"`
	Spread       bool              `yaml:"spread"`       // legacy; use Policy=spread-strict
	MaxPerNode   int               `yaml:"max-per-node"` // 0 = unlimited

	// Policy: balance | bin-pack | spread-strict | cost-aware. Empty defaults
	// to balance. See docs/placement.md and
	Policy string `yaml:"policy"`

	// Mode is a named-bundle alias (`performance`, `savings`, `ha-critical`,
	// `spot-cheap`). Expanded at parse time into Policy + Rebalance fields.
	// If both Mode and explicit Policy/Rebalance are set, explicit wins.
	Mode string `yaml:"mode"`

	// Rebalance: day-2 reconciliation behavior for this VM. nil = inherit
	// from cluster default.
	Rebalance *RebalanceDef `yaml:"rebalance"`

	// NoMigrate: this VM opts out of all live migration (rebalancer ignores
	// it; storage motion not allowed). Set automatically by admission for
	// VMs with non-migratable PCI passthrough.
	NoMigrate bool `yaml:"no-migrate"`
}

// RebalanceDef controls per-VM (or per-stack / per-cluster) rebalancer
// behavior. See for the mode matrix.
type RebalanceDef struct {
	Mode      string           `yaml:"mode"`      // off | dry-run | on-demand | auto
	Threshold int              `yaml:"threshold"` // min imbalance % (default 15)
	Cooldown  string           `yaml:"cooldown"`  // "5m" — min interval per VM
	Budget    *RebalanceBudget `yaml:"budget"`
}

// RebalanceBudget caps how aggressive the rebalancer may be.
type RebalanceBudget struct {
	MaxConcurrent int    `yaml:"max-concurrent"` // simultaneous live migrations cluster-wide
	MaxPerHour    int    `yaml:"max-per-hour"`
	Window        string `yaml:"window"` // named cluster time window (e.g. "off-hours")
}

// RestartDef controls auto-restart behaviour for stopped/crashed VMs.
type RestartDef struct {
	Condition   string `yaml:"condition"`    // "none" | "on-failure" | "always"
	Delay       string `yaml:"delay"`        // "5s", "1m"
	MaxAttempts int    `yaml:"max-attempts"` // 0 = unlimited
	Window      string `yaml:"window"`       // "1h" — reset attempt counter after this duration
}

// MigrateDef controls migration behaviour.
type MigrateDef struct {
	Strategy      string `yaml:"strategy"` // live | cold | none
	MaxDowntime   string `yaml:"max-downtime"`
	AutoConverge  bool   `yaml:"auto-converge"`
	WithStorage   bool   `yaml:"with-storage"`
	OnHostFailure string `yaml:"on-host-failure"` // restart-any | restart-same | none
	Priority      int    `yaml:"priority"`
	FenceStrategy string `yaml:"fence-strategy"` // best-effort | ipmi | manual | watchdog
	BandwidthMiB  int    `yaml:"bandwidth-mib-sec"`
	TimeoutSec    int    `yaml:"timeout-sec"`
}

// UpdateDef controls rolling update behaviour.
type UpdateDef struct {
	Strategy          string `yaml:"strategy"` // in-place | recreate | snapshot-and-replace | rolling | all-at-once | blue-green
	MaxUnavailable    int    `yaml:"max-unavailable"`
	MaxSurge          int    `yaml:"max-surge"`
	Order             string `yaml:"order"` // start-first | stop-first
	HealthWait        string `yaml:"health-wait"`
	RollbackOnFailure bool   `yaml:"rollback-on-failure"`
	PauseBetween      string `yaml:"pause-between"`
}

// LBDef defines load balancer configuration.
type LBDef struct {
	Enabled   bool      `yaml:"enabled"`
	VIP       string    `yaml:"vip"`
	Ports     []LBPort  `yaml:"ports"`
	Algorithm string    `yaml:"algorithm"` // roundrobin | leastconn | source
	Health    *LBHealth `yaml:"health"`
	Hosts     []string  `yaml:"hosts"`
	Sticky    bool      `yaml:"sticky-sessions"`
	SNAT      bool      `yaml:"snat"` // SNAT outbound VM traffic to VIP
}

// LBPort defines a single LB listener.
type LBPort struct {
	Listen        int       `yaml:"listen"`
	Target        int       `yaml:"target"`
	Protocol      string    `yaml:"protocol"` // tcp | http
	RedirectHTTPS bool      `yaml:"redirect-https"`
	TLS           *LBTLSDef `yaml:"tls"`
}

// LBTLSDef holds TLS termination config.
type LBTLSDef struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// LBHealth defines LB backend health checking.
type LBHealth struct {
	UseVMHealthcheck bool   `yaml:"use-vm-healthcheck"`
	Type             string `yaml:"type"`
	Path             string `yaml:"path"`
	IntervalMS       int    `yaml:"interval-ms"`
}

// HealthCheckDef defines VM-level health checking.
type HealthCheckDef struct {
	Type     string `yaml:"type"`   // tcp | http | ping | exec
	Target   string `yaml:"target"` // port or URL
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
	Retries  int    `yaml:"retries"`
	Action   string `yaml:"action"` // restart | migrate | alert
}

// HooksDef contains lifecycle hook scripts.
type HooksDef struct {
	PreStart    string `yaml:"pre-start"`
	PostStart   string `yaml:"post-start"`
	PreStop     string `yaml:"pre-stop"`
	PostStop    string `yaml:"post-stop"`
	PreMigrate  string `yaml:"pre-migrate"`
	PostMigrate string `yaml:"post-migrate"`
}

// DeviceDef describes a PCI device passthrough request.
type DeviceDef struct {
	Type    string `yaml:"type"`    // gpu | network | nvme | infiniband | pci
	Vendor  string `yaml:"vendor"`  // PCI vendor ID e.g. "10de"
	Model   string `yaml:"model"`   // optional model string match
	Count   int    `yaml:"count"`   // number of devices (default 1)
	Address string `yaml:"address"` // exact PCI address e.g. "0000:41:00.0"
	SRIOV   bool   `yaml:"sriov"`   // request an SR-IOV VF
	Parent  string `yaml:"parent"`  // SR-IOV: allocate from this PF
	Mapping string `yaml:"mapping"` // cluster-wide resource-mapping name (#14)
}

// ResourcesDef holds advanced resource tuning.
type ResourcesDef struct {
	HugePages    bool   `yaml:"hugepages"`
	CPUPinning   []int  `yaml:"cpu-pinning"`
	NUMATopology string `yaml:"numa-topology"`
	IOThreads    int    `yaml:"io-threads"`
}

// DependsOn maps dependency VM names to their conditions.
// Supports both list form (all vm_started) and map form (per-dependency condition).
type DependsOn map[string]DependencyDef

// DependencyDef specifies the condition for a dependency.
type DependencyDef struct {
	Condition string `yaml:"condition"` // "vm_started" | "vm_healthy"
}

// UnmarshalYAML allows DependsOn to accept both list and map forms:
//
//	depends-on: [db, redis]                        → all vm_started
//	depends-on:
//	  db: { condition: vm_healthy }
//	  redis: { condition: vm_started }
func (d *DependsOn) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try list form first.
	var list []string
	if err := unmarshal(&list); err == nil {
		*d = make(DependsOn, len(list))
		for _, name := range list {
			(*d)[name] = DependencyDef{Condition: "vm_started"}
		}
		return nil
	}
	// Map form.
	type alias DependsOn
	var m alias
	if err := unmarshal(&m); err != nil {
		return err
	}
	// Default condition to vm_started.
	for k, v := range m {
		if v.Condition == "" {
			v.Condition = "vm_started"
			m[k] = v
		}
	}
	*d = DependsOn(m)
	return nil
}

// DNSDef holds cluster DNS configuration.
type DNSDef struct {
	Domain string `yaml:"domain"`
}

// NotificationsDef holds webhook configuration.
type NotificationsDef struct {
	Webhook string `yaml:"webhook"`
}

// ScopedNetworkName returns the stack-scoped name for a network.
// Stack-owned networks are stored as "{stack}_{name}" to prevent
// cross-stack collisions. Standalone networks (empty stack) keep their
// raw name.
func ScopedNetworkName(stackName, netName string) string {
	if stackName == "" {
		return netName
	}
	return stackName + "_" + netName
}
