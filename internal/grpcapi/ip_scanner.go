package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
			ip := lv.GetIPFromARP(iface.MAC)
			if ip == "" {
				ip = lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", iface.MAC)
			}
			if ip == "" {
				continue
			}

			corrosion.UpdateVMInterfaceIP(ctx, s.db, vm.Name, iface.NetworkName, ip)
			slog.Debug("ip_scanner: discovered IP", "vm", vm.Name, "network", iface.NetworkName, "ip", ip)

			// Update DNS record so VM is reachable by name.
			if domain := s.server.dnsDomain; domain != "" {
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
