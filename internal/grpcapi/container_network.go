package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// containerVethName is the deterministic host veth name for a container NIC.
// Defined in corrosion (shared with the health/relocate path); kept as a local
// alias for readability here.
func containerVethName(ctName string, ordinal int) string {
	return corrosion.ContainerVethName(ctName, ordinal)
}

// resolveBridgeToNetwork returns the single managed network whose rendered
// bridge equals bridge; ok=false if zero or many match (⇒ legacy-unmanaged).
func (s *Server) resolveBridgeToNetwork(ctx context.Context, bridge string) (string, bool) {
	nets, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return "", false
	}
	match, n := "", 0
	for _, nr := range nets {
		if resolveBridge(ctx, s.db, nr.Name) == bridge {
			match, n = nr.Name, n+1
		}
	}
	return match, n == 1
}

// containerNICPlan is the resolved per-create network wiring.
type containerNICPlan struct {
	lxcNics  []ContainerNICOpt
	ifaces   []corrosion.ContainerInterfaceRecord
	leases   []corrosion.IPLease
	specNets []corrosion.ContainerNetwork
}

// resolveContainerNICs turns the requested NICs into runtime attachments, the
// managed-interface rows, the IPAM leases to take, and the create-spec network
// intent. A NIC is MANAGED when it names — or its bridge resolves to — exactly
// one known network; otherwise it's a legacy raw-bridge attachment with no
// managed state (no interface row, IPAM, or veth). Pure resolution: it computes
// candidate IPs but writes nothing (the caller persists rows + leases atomically).
func (s *Server) resolveContainerNICs(ctx context.Context, ctName string, nics []*pb.ContainerNetwork) (*containerNICPlan, error) {
	p := &containerNICPlan{}
	for i, n := range nics {
		netName := n.NetworkName
		var def *compose.NetworkDef
		switch {
		case netName != "":
			if def = lookupNetworkDef(ctx, s.db, netName); def == nil {
				return nil, status.Errorf(codes.InvalidArgument, "network %q not found", netName)
			}
		case n.Bridge != "":
			if name, ok := s.resolveBridgeToNetwork(ctx, n.Bridge); ok {
				netName = name
				def = lookupNetworkDef(ctx, s.db, name)
			}
		}

		if def == nil {
			// Legacy-unmanaged raw bridge: pass through verbatim. No managed state.
			p.lxcNics = append(p.lxcNics, ContainerNICOpt{Name: n.Name, Bridge: n.Bridge, IP: n.Ip, MAC: n.Mac})
			p.specNets = append(p.specNets, corrosion.ContainerNetwork{Name: n.Name, Bridge: n.Bridge, IP: n.Ip, MAC: n.Mac})
			continue
		}

		// Managed NIC.
		bridge := resolveBridge(ctx, s.db, netName)
		mac := n.Mac
		if mac == "" {
			mac = GenerateMAC()
		}
		veth := containerVethName(ctName, i)
		ip := n.Ip
		if ip == "" && def.Subnet != "" {
			cand, err := network.ComputeCandidateIP(ctx, s.db, netName, def.Subnet)
			if err != nil {
				return nil, status.Errorf(codes.ResourceExhausted, "allocate IP on network %q: %v", netName, err)
			}
			ip = cand
		}
		p.lxcNics = append(p.lxcNics, ContainerNICOpt{Name: n.Name, Bridge: bridge, IP: ip, MAC: mac, Veth: veth})
		p.ifaces = append(p.ifaces, corrosion.ContainerInterfaceRecord{
			HostName: s.hostName, CtName: ctName, NetworkName: netName, Ordinal: i,
			MAC: mac, IP: ip, VethDevice: veth, SecurityGroups: n.SecurityGroups,
		})
		if ip != "" { // static or litevirt-assigned → take a lease; DHCP (blank) → none
			p.leases = append(p.leases, corrosion.IPLease{
				Network: netName, IP: ip, MAC: mac, OwnerKind: "ct", OwnerHost: s.hostName, OwnerName: ctName,
			})
		}
		// create_spec stores the user's STATIC IP intent (n.Ip) — an auto-allocated
		// address is left empty so a rebuild re-allocates rather than reusing a stale one.
		p.specNets = append(p.specNets, corrosion.ContainerNetwork{
			Name: n.Name, Bridge: bridge, IP: n.Ip, MAC: mac,
			NetworkName: netName, SecurityGroups: n.SecurityGroups,
		})
	}
	return p, nil
}

// releaseContainerNICs releases a container's managed IPAM leases and tombstones
// its interface rows (the delete cascade). Best-effort: returns the first error
// for logging but always attempts every step.
func (s *Server) releaseContainerNICs(ctx context.Context, ctName string) error {
	ifaces, err := corrosion.GetContainerInterfaces(ctx, s.db, s.hostName, ctName)
	if err != nil {
		return err
	}
	var firstErr error
	for _, ifc := range ifaces {
		if ifc.IP != "" {
			if e := network.ReleaseIPFor(ctx, s.db, ifc.NetworkName, "ct", s.hostName, ctName); e != nil && firstErr == nil {
				firstErr = e
			}
		}
	}
	if e := corrosion.DeleteContainerInterfaces(ctx, s.db, s.hostName, ctName); e != nil && firstErr == nil {
		firstErr = e
	}
	return firstErr
}
