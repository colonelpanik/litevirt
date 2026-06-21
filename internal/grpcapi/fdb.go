package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// updateFDBForMigration updates FDB entries across all VTEP peers after a VM
// migrates from oldHost to newHost. This ensures unicast MAC→VTEP entries
// point to the correct host.
func (s *Server) updateFDBForMigration(ctx context.Context, iface corrosion.InterfaceRecord, oldHost, newHost string) {
	nr, err := corrosion.GetNetwork(ctx, s.db, iface.NetworkName)
	if err != nil || nr == nil || nr.Type != "vxlan" {
		return
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(nr.Config), &def); err != nil {
		return
	}
	if def.VNI == 0 {
		return
	}

	oldVTEP := s.getHostVTEP(ctx, iface.NetworkName, oldHost)
	newVTEP := s.getHostVTEP(ctx, iface.NetworkName, newHost)
	if newVTEP == "" {
		return
	}

	s.broadcastFDBUpdate(ctx, iface.NetworkName, def.VNI, iface.MAC, oldVTEP, newVTEP)
}

// getHostVTEP returns the VTEP IP for a given host on a network.
func (s *Server) getHostVTEP(ctx context.Context, networkName, hostName string) string {
	vteps, _ := network.GetVTEPs(ctx, s.db, networkName)
	for _, v := range vteps {
		if v.HostName == hostName {
			return v.VTEPAddr
		}
	}
	return ""
}

// broadcastFDBUpdate sends a unicast FDB update to all VTEP peers for a network.
// If oldVTEP is set, the old entry is removed. If newVTEP is set, a new entry is added.
func (s *Server) broadcastFDBUpdate(ctx context.Context, networkName string, vni int, mac, oldVTEP, newVTEP string) {
	vteps, err := network.GetVTEPs(ctx, s.db, networkName)
	if err != nil {
		return
	}
	for _, v := range vteps {
		if v.HostName == s.hostName {
			// Local update.
			if oldVTEP != "" {
				network.DeleteFDBEntry(vni, mac, oldVTEP)
			}
			if newVTEP != "" {
				if err := network.AddFDBEntry(vni, mac, newVTEP); err != nil {
					slog.Warn("broadcastFDBUpdate: local add", "mac", mac, "vtep", newVTEP, "error", err)
				}
			}
			continue
		}
		go func(host string) {
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			client.UpdateFDB(ctx, &pb.UpdateFDBRequest{
				Vni:       int32(vni),
				Mac:       mac,
				OldVtepIp: oldVTEP,
				NewVtepIp: newVTEP,
			})
		}(v.HostName)
	}
}
