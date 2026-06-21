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
