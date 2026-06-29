package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// cloneContainerNICs rebuilds the MANAGED interface rows + create-spec networks
// for a CLONE from its source's create spec. The clone is a NEW workload: it gets
// a deterministic per-NIC MAC + veth (from the clone's name — matching what the
// runtime clone writes on-disk) and a DYNAMIC IP (blank: a clone must not reuse
// the source's address), so no IPAM lease is taken here. Legacy raw NICs are
// copied verbatim (no managed state).
func (s *Server) cloneContainerNICs(ctName string, srcSpec corrosion.ContainerCreateSpec) ([]corrosion.ContainerInterfaceRecord, []corrosion.ContainerNetwork) {
	var ifaces []corrosion.ContainerInterfaceRecord
	var specNets []corrosion.ContainerNetwork
	for i, n := range srcSpec.Networks {
		if n.NetworkName == "" {
			specNets = append(specNets, n) // legacy/unmanaged → copy as-is
			continue
		}
		mac := corrosion.ContainerMAC(s.hostName, ctName, i)
		veth := corrosion.ContainerVethName(ctName, i)
		ifaces = append(ifaces, corrosion.ContainerInterfaceRecord{
			HostName: s.hostName, CtName: ctName, NetworkName: n.NetworkName, Ordinal: i,
			MAC: mac, IP: "", VethDevice: veth, SecurityGroups: n.SecurityGroups,
		})
		specNets = append(specNets, corrosion.ContainerNetwork{
			Name: n.Name, Bridge: n.Bridge, MAC: mac, NetworkName: n.NetworkName, SecurityGroups: n.SecurityGroups,
		})
	}
	return ifaces, specNets
}

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
	specNets []corrosion.ContainerNetwork
}

// resolveContainerNICs turns the requested NICs into runtime attachments, the
// managed-interface rows, and the create-spec network intent, ALLOCATING each
// managed NIC's IPAM lease as it goes (tombstone/race-safe). A NIC is MANAGED
// when it names — or its bridge resolves to — exactly one known network;
// otherwise it's a legacy raw-bridge attachment with no managed state (no
// interface row, IPAM, or veth). On error the caller must release this
// container's leases (network.ReleaseContainerLeases) to undo partial allocation.
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

		// Managed NIC. Containers support only L2 bridge-family networks; direct
		// (macvtap) and SR-IOV are VM-only (they'd render VM-shaped link values
		// like "direct:<iface>" into lxc.net.N.link).
		switch def.Type {
		case "direct", "sriov":
			return nil, status.Errorf(codes.InvalidArgument,
				"network %q type %q is not supported for containers", netName, def.Type)
		}
		// Provision the network on this host (creates/ensures the bridge/vxlan/
		// isolated device) and use the real bridge — like the VM path.
		bridge, perr := provisionNetworkForVM(ctx, s.db, netName, s.hostName)
		if perr != nil {
			// vxlan / isolated devices MUST be provisioned by litevirt (lxc can't
			// auto-create them), so a provision failure means the link won't exist —
			// hard-fail rather than track a managed NIC on a phantom device. A plain
			// bridge falls back to the resolved name (lxc auto-creates it, or it's
			// pre-existing), matching VM create.
			if def.Type == "vxlan" || def.Type == "isolated" {
				return nil, status.Errorf(codes.FailedPrecondition, "provision %s network %q: %v", def.Type, netName, perr)
			}
			slog.Warn("container network provision failed; using resolved bridge name",
				"network", netName, "error", perr)
			bridge = resolveBridge(ctx, s.db, netName)
		} else if bridge == "" {
			bridge = resolveBridge(ctx, s.db, netName)
		}
		mac := n.Mac
		if mac == "" {
			// Wide (40-bit), host-aware, deterministic CT MAC — same generator the
			// clone/relocate paths use, so a rebuild reproduces it and two same-named
			// CTs on different hosts (shared L2) don't collide. (GenerateMAC's 24-bit
			// 52:54:00 space is VM-shared; CTs get the wider scheme.)
			mac = corrosion.ContainerMAC(s.hostName, ctName, i)
		}
		veth := containerVethName(ctName, i)
		// Allocate the IP NOW (writing the lease) — tombstone- and race-safe. A
		// static request reserves that exact address (fail if held by another);
		// otherwise litevirt allocates from the subnet; a subnet-less network is
		// DHCP (blank IP, no lease). The caller releases all of this container's
		// leases (network.ReleaseContainerLeases) if create later fails.
		ip := ""
		switch {
		case n.Ip != "":
			ok, rerr := network.ReserveContainerIP(ctx, s.db, netName, n.Ip, mac, s.hostName, ctName)
			if rerr != nil {
				return nil, status.Errorf(codes.Internal, "reserve IP %q on %q: %v", n.Ip, netName, rerr)
			}
			if !ok {
				return nil, status.Errorf(codes.AlreadyExists, "static IP %q on network %q is already in use", n.Ip, netName)
			}
			ip = n.Ip
		case def.Subnet != "":
			cand, aerr := network.AllocateIPFor(ctx, s.db, netName, def.Subnet, mac, "ct", s.hostName, ctName)
			if aerr != nil {
				return nil, status.Errorf(codes.ResourceExhausted, "allocate IP on network %q: %v", netName, aerr)
			}
			ip = cand
		}
		p.lxcNics = append(p.lxcNics, ContainerNICOpt{Name: n.Name, Bridge: bridge, IP: ip, MAC: mac, Veth: veth})
		p.ifaces = append(p.ifaces, corrosion.ContainerInterfaceRecord{
			HostName: s.hostName, CtName: ctName, NetworkName: netName, Ordinal: i,
			MAC: mac, IP: ip, VethDevice: veth, SecurityGroups: n.SecurityGroups,
		})
		// create_spec stores the EFFECTIVE IP (static or auto-allocated), so a
		// rebuild (restore/migrate/relocate) re-reserves the same address instead of
		// losing an auto-allocated one. The rebuild's reserve is conditional (never
		// steals), so reusing it is safe.
		p.specNets = append(p.specNets, corrosion.ContainerNetwork{
			Name: n.Name, Bridge: bridge, IP: ip, MAC: mac,
			NetworkName: netName, SecurityGroups: n.SecurityGroups,
		})
	}
	return p, nil
}

// releaseContainerNICs releases a container's managed IPAM leases and tombstones
// its interface rows (the delete cascade). Best-effort: returns the first error
// for logging but always attempts every step.
func (s *Server) releaseContainerNICs(ctx context.Context, ctName string) error {
	// Release every IPAM lease this container holds on the host (across networks),
	// then tombstone its interface rows. ReleaseContainerLeases works even when the
	// interface rows are absent (e.g. rolling back a create that failed before the
	// rows were written).
	firstErr := network.ReleaseContainerLeases(ctx, s.db, s.hostName, ctName)
	if e := corrosion.DeleteContainerInterfaces(ctx, s.db, s.hostName, ctName); e != nil && firstErr == nil {
		firstErr = e
	}
	return firstErr
}
