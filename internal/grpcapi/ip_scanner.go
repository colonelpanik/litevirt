package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

// IPScanner periodically discovers IPs for local VMs via ARP/DHCP and
// persists them to Corrosion. Also broadcasts unicast FDB entries for
// VMs on VXLAN networks so peers can route directly without flooding.
type IPScanner struct {
	hostName string
	db       *corrosion.Client
	server   *Server // for broadcastFDBUpdate
}

// NewIPScanner creates an IP scanner bound to a server.
func NewIPScanner(server *Server) *IPScanner {
	return &IPScanner{
		hostName: server.hostName,
		db:       server.db,
		server:   server,
	}
}

// Start runs the IP scanner loop until ctx is cancelled.
func (s *IPScanner) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scan(ctx)
		}
	}
}

// ScanOnce runs exactly one discovery pass — what Start's ticker drives.
//
// Exported so the pass can be exercised without a 30-second wall-clock wait.
// It is the only way to reach the discovery gate from outside this package: the
// gate turns a discovered address into a NetBox claim, and a scenario about what
// it refuses to record cannot be built out of RPCs alone.
func (s *IPScanner) ScanOnce(ctx context.Context) { s.scan(ctx) }

func (s *IPScanner) scan(ctx context.Context) {
	s.scanVMs(ctx)
	s.scanContainers(ctx)
}

func (s *IPScanner) scanVMs(ctx context.Context) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		return
	}

	for _, vm := range vms {
		if vm.State != "running" {
			continue
		}
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
		for _, iface := range ifaces {
			if iface.IP != "" {
				continue
			}
			ip := s.server.discoverNICAddress(iface.MAC)
			if ip == "" {
				continue
			}

			// GATED, not written directly. On a NetBox-bound network the address
			// is recorded only once NetBox has granted it to this NIC; on an
			// unbound one this is the write it always was. See
			// netbox_discovery.go — this tick is the pass that DOES claim, which
			// is why the read RPCs can leave it to us.
			recorded := s.server.claimAndRecordDiscoveredVMIP(ctx, &vm, iface.NetworkName, iface.MAC, ip)
			slog.Debug("ip_scanner: discovered IP",
				"vm", vm.Name, "network", iface.NetworkName, "ip", ip, "recorded", recorded)

			// The FDB entry is deliberately OUTSIDE that gate, below: it maps a
			// MAC to a VTEP and carries no address at all, so it is L2
			// reachability for a guest that exists either way. Suppressing it
			// would black-hole a running VM over an address bookkeeping dispute.

			// Update DNS record so VM is reachable by name — but only for an
			// address litevirt actually recorded. A DNS record asserts the same
			// address to a second reader, so publishing one the NIC row was not
			// allowed to carry would put the two records into exactly the
			// disagreement the gate exists to prevent.
			if domain := s.server.dnsDomain; recorded && domain != "" {
				dnsName := dns.VMRecordName(vm.Name, vm.StackName, domain)
				if err := dns.UpsertRecord(ctx, s.db, dnsName, ip); err != nil {
					slog.Warn("ip_scanner: DNS upsert failed", "vm", vm.Name, "error", err)
				}
			}

			// Broadcast unicast FDB entry for VXLAN networks.
			nr, err := corrosion.GetNetwork(ctx, s.db, iface.NetworkName)
			if err != nil || nr == nil || nr.Type != "vxlan" {
				continue
			}
			var def compose.NetworkDef
			if err := json.Unmarshal([]byte(nr.Config), &def); err != nil || def.VNI == 0 {
				continue
			}
			localVTEP := s.server.getHostVTEP(ctx, iface.NetworkName, s.hostName)
			if localVTEP != "" {
				s.server.broadcastFDBUpdate(ctx, iface.NetworkName, def.VNI, iface.MAC, "", localVTEP)
			}
		}
	}
}

// scanContainers is the convergent CT-DNS reconciler: for each RUNNING local
// container it discovers the live IP (lxc-info), persists a freshly-discovered or
// changed address into the managed interface row, and (re)upserts the auto DNS
// record so the container is name-resolvable. It runs on the container's OWN host
// (lxc-info is host-local) and is idempotent — covers static IPs (known at create),
// DHCP IPs (discovered here), migrate (the target host re-creates the record), and
// IP changes (UpsertRecord replaces). Removal is the delete/migrate cascade's job.
func (s *IPScanner) scanContainers(ctx context.Context) {
	if s.server.containerRuntime == nil {
		return
	}
	cts, err := corrosion.ListContainers(ctx, s.db, s.hostName)
	if err != nil {
		return
	}
	for _, ct := range cts {
		if ct.State != "running" {
			continue
		}
		ifaces, _ := corrosion.GetContainerInterfaces(ctx, s.db, s.hostName, ct.Name)
		if len(ifaces) == 0 {
			continue // legacy/unmanaged NIC — no record to maintain
		}
		// lxc-info returns the container's primary IP (one address); map it to the
		// first managed NIC. The recorded IP wins if discovery comes back empty.
		live, _ := s.server.containerRuntime.IPContainer(ctx, ct.Name)
		recorded := ""
		for _, ifc := range ifaces {
			if ifc.IP != "" {
				recorded = ifc.IP
				break
			}
		}
		ip := recorded
		if live != "" {
			ip = live
		}
		if ip == "" {
			continue // no IP known yet (DHCP still pending)
		}
		// Persist a newly-discovered / changed address onto the primary managed NIC.
		if live != "" && live != recorded {
			if err := corrosion.UpdateContainerInterfaceIP(ctx, s.db, s.hostName, ct.Name, ifaces[0].Ordinal, live); err != nil {
				slog.Warn("ip_scanner: persist container IP failed", "container", ct.Name, "error", err)
			}
		}
		s.server.upsertContainerDNS(ctx, ct.Name, containerStackLabel(ct), ip)
	}
}

// CleanupFDBForVM broadcasts FDB removal for all interfaces of a VM on VXLAN networks.
// Called from DeleteVM to ensure peers remove stale unicast entries.
func (s *Server) CleanupFDBForVM(ctx context.Context, vmName string) {
	ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vmName)
	for _, iface := range ifaces {
		nr, err := corrosion.GetNetwork(ctx, s.db, iface.NetworkName)
		if err != nil || nr == nil || nr.Type != "vxlan" {
			continue
		}
		var def compose.NetworkDef
		if err := json.Unmarshal([]byte(nr.Config), &def); err != nil || def.VNI == 0 {
			continue
		}
		hostVTEP := s.getHostVTEP(ctx, iface.NetworkName, s.hostName)
		if hostVTEP != "" {
			s.broadcastFDBUpdate(ctx, iface.NetworkName, def.VNI, iface.MAC, hostVTEP, "")
		}
	}
}
