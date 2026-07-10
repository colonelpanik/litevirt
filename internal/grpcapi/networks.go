package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/safename"
)

// CreateNetwork provisions a network on this host and persists it. A network is
// either GLOBAL (req.Project == "" → admin-managed, RBAC-anchored at root) or
// OWNED by a project (RBAC at /projects/<p>/...): only that project's workloads
// (or root) may attach to an owned network.
func (s *Server) CreateNetwork(ctx context.Context, req *pb.CreateNetworkRequest) (*pb.NetworkInfo, error) {
	// Empty project = global/shared; do NOT normalize to "_default" (that would
	// make it an OWNED network of the default project, not global). Validate the
	// name format of a non-empty project.
	project := req.Project
	if project != "" {
		if _, err := safename.CanonicalProjectName(project); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid project %q: %v", project, err)
		}
	}
	if err := s.RequirePerm(ctx, networkRBACPathFor(project, req.Name), "network.create", "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	ntype := req.Type
	if ntype == "" {
		ntype = "bridge"
	}

	// Check for duplicates.
	existing, err := corrosion.GetNetwork(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check existing: %v", err)
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "network %q already exists", req.Name)
	}

	def := compose.NetworkDef{
		Type:       ntype,
		Interface:  req.Iface,
		VLAN:       int(req.Vlan),
		VNI:        int(req.Vni),
		Underlay:   req.Underlay,
		Learning:   req.Learning,
		Port:       int(req.Port),
		Subnet:     req.Subnet,
		DHCP:       req.Dhcp,
		PF:         req.Pf,
		SpoofCheck: req.SpoofCheck,
	}
	if def.Interface == "" {
		def.Interface = req.Name
	}

	ni, err := s.provisionAndPersistNetwork(ctx, req.Name, "", project, def)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "provision network: %v", err)
	}

	s.publish("network.created", req.Name, fmt.Sprintf("type=%s", ntype))
	s.audit(ctx, "network.create", req.Name, "project="+project, "ok")
	return ni, nil
}

// GetNetwork returns details for a single network. Read is project-scoped: a
// global network is visible to any viewer, an owned one only to its project (or
// root).
func (s *Server) GetNetwork(ctx context.Context, req *pb.GetNetworkRequest) (*pb.NetworkInfo, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	nr, err := corrosion.GetNetwork(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get network: %v", err)
	}
	if nr == nil {
		return nil, status.Errorf(codes.NotFound, "network %q not found", req.Name)
	}
	if err := s.authorizeResourceRead(ctx, nr.Project, networkRBACPathFor(nr.Project, nr.Name), "network.read"); err != nil {
		return nil, err
	}

	ni := networkRecordToInfo(nr)

	// Count VMs on this network.
	count, _ := corrosion.CountVMsOnNetwork(ctx, s.db, req.Name)
	ni.VmCount = int32(count)

	return ni, nil
}

// DeleteNetwork tears down a network and removes it from the database. The RBAC
// check is scoped to the network's OWNING project (global → root), so a
// project-scoped operator can delete only their own networks, never a global or
// another project's.
func (s *Server) DeleteNetwork(ctx context.Context, req *pb.DeleteNetworkRequest) (*emptypb.Empty, error) {
	// Operator role floor BEFORE the lookup (a viewer can't probe existence); the
	// project-scoped check follows once we know the network's owning project.
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// Fail closed on a read error — we must not delete a network we couldn't
	// resolve the ownership of.
	nr, err := corrosion.GetNetwork(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get network: %v", err)
	}
	if nr == nil {
		return nil, status.Errorf(codes.NotFound, "network %q not found", req.Name)
	}
	if err := s.RequirePerm(ctx, networkRBACPathFor(nr.Project, req.Name), "network.delete", "operator"); err != nil {
		return nil, err
	}

	// Check if VMs are still using this network.
	count, _ := corrosion.CountVMsOnNetwork(ctx, s.db, req.Name)
	if count > 0 && !req.Force {
		return nil, status.Errorf(codes.FailedPrecondition,
			"network %q has %d VM(s) attached — use --force to delete anyway", req.Name, count)
	}

	// Deprovision the network infrastructure.
	def := networkRecordToDef(nr)
	if err := network.Deprovision(ctx, s.db, req.Name, def, s.hostName); err != nil {
		slog.Warn("network deprovision failed", "network", req.Name, "error", err)
	}
	s.reconcileFirewall(ctx) // drop this network's NAT/isolation from the ruleset now

	// Soft-delete the DB record.
	if err := corrosion.DeleteNetwork(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete network: %v", err)
	}

	s.publish("network.deleted", req.Name, "")
	s.audit(ctx, "network.delete", req.Name, "", "ok")
	return &emptypb.Empty{}, nil
}

// ListNetworks returns the networks the caller may view: global networks (any
// viewer) + those owned by a project the caller can read. A legacy cluster viewer
// (no project binding) still sees all via the role fallback.
func (s *Server) ListNetworks(ctx context.Context, _ *emptypb.Empty) (*pb.ListNetworksResponse, error) {
	dbNets, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list networks: %v", err)
	}

	// Single query for per-network VM counts instead of N+1.
	vmCount, _ := corrosion.CountVMsByNetwork(ctx, s.db)

	// Build a map from interface name → compose network name so we can
	// match VM interface records (which use bridge names) to DB network records.
	ifaceToNet := make(map[string]string)
	seen := make(map[string]bool)

	resp := &pb.ListNetworksResponse{}
	for _, nr := range dbNets {
		// Project-scoped read filter: skip networks the caller can't view.
		if s.authorizeResourceRead(ctx, nr.Project, networkRBACPathFor(nr.Project, nr.Name), "network.read") != nil {
			continue
		}
		ni := networkRecordToInfo(&nr)

		// VM count: match by compose network name OR by interface name.
		iface := ni.Iface
		if iface == "" {
			iface = nr.Name
		}
		ni.VmCount = int32(vmCount[nr.Name] + vmCount[iface])
		if nr.Name == iface {
			ni.VmCount = int32(vmCount[nr.Name])
		}

		// Mark BOTH the declared network name and its interface as seen.
		// vmCount is keyed by network name (vm_interfaces.network_name),
		// so without seen[nr.Name] the second loop manufactures a phantom
		// Type:"bridge" twin for every declared network whose VMs reference
		// it by name and whose iface name differs (e.g. a "direct" network
		// on bond0.206 showed up a second time, mislabeled "bridge").
		seen[nr.Name] = true
		if ni.Iface != "" {
			ifaceToNet[ni.Iface] = nr.Name
			seen[ni.Iface] = true
		}

		resp.Networks = append(resp.Networks, ni)
	}

	// Include networks only known from VM interfaces (not in DB). These have no
	// managed record (no project), so they're treated as global — viewer-gated.
	if s.authorizeResourceRead(ctx, "", "", "network.read") == nil {
		for name, count := range vmCount {
			if !seen[name] && ifaceToNet[name] == "" {
				resp.Networks = append(resp.Networks, &pb.NetworkInfo{
					Name:    name,
					Type:    "bridge",
					VmCount: int32(count),
				})
			}
		}
	}

	return resp, nil
}

// ── shared helpers ──────────────────────────────────────────────────────────

// provisionAndPersistNetwork persists the network record to Corrosion first,
// then provisions the infrastructure. Persisting first ensures that if the
// config changes (e.g., bridge → direct), the new config is replicated to all
// cluster hosts immediately — preventing other hosts' reconcilers from
// provisioning the stale config.
func (s *Server) provisionAndPersistNetwork(ctx context.Context, name, stackName, project string, def compose.NetworkDef) (*pb.NetworkInfo, error) {
	ntype := def.Type
	if ntype == "" {
		ntype = "bridge"
	}
	cfgJSON, _ := json.Marshal(def)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:      name,
		StackName: stackName,
		Type:      ntype,
		Config:    string(cfgJSON),
		Project:   project, // "" = global/shared
	}); err != nil {
		return nil, fmt.Errorf("persist network: %w", err)
	}

	localIP := getLocalIP()
	if _, err := network.SafeProvision(ctx, s.db, name, def, localIP, s.hostName); err != nil {
		return nil, err
	}
	// Fail closed: don't report a provisioned network while its host-isolation/NAT
	// rules haven't applied.
	if err := s.reconcileFirewallRequired(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "apply firewall for network %q: %v", name, err)
	}

	nr, _ := corrosion.GetNetwork(ctx, s.db, name)
	if nr == nil {
		// Fallback: build from what we know.
		nr = &corrosion.NetworkRecord{
			Name:      name,
			StackName: stackName,
			Type:      ntype,
			Config:    string(cfgJSON),
		}
	}
	return networkRecordToInfo(nr), nil
}

// deprovisionNetworkByName looks up a network record and tears down its infra.
func (s *Server) deprovisionNetworkByName(ctx context.Context, name string) error {
	nr, err := corrosion.GetNetwork(ctx, s.db, name)
	if err != nil || nr == nil {
		return nil // nothing to deprovision
	}
	def := networkRecordToDef(nr)
	if err := network.Deprovision(ctx, s.db, name, def, s.hostName); err != nil {
		return err
	}
	s.reconcileFirewall(ctx) // drop this network's NAT/isolation from the ruleset now
	return corrosion.DeleteNetwork(ctx, s.db, name)
}

// networkRecordToInfo converts a corrosion.NetworkRecord to a pb.NetworkInfo.
func networkRecordToInfo(nr *corrosion.NetworkRecord) *pb.NetworkInfo {
	ni := &pb.NetworkInfo{
		Name:      nr.Name,
		StackName: nr.StackName,
		Type:      nr.Type,
		Project:   nr.Project,
	}
	var cfg struct {
		Interface string `json:"interface"`
		Subnet    string `json:"subnet"`
		DHCP      bool   `json:"dhcp"`
		VNI       int    `json:"vni"`
	}
	if err := json.Unmarshal([]byte(nr.Config), &cfg); err == nil {
		ni.Iface = cfg.Interface
		ni.Subnet = cfg.Subnet
		ni.Vni = int32(cfg.VNI)
		ni.Dhcp = cfg.Subnet != "" || cfg.DHCP
		if cfg.Subnet != "" {
			if gw, _, _, _, err := network.SubnetRange(cfg.Subnet); err == nil {
				ni.Gateway = gw
			}
		}
	}
	return ni
}

// networkRecordToDef converts a corrosion.NetworkRecord to a compose.NetworkDef.
func networkRecordToDef(nr *corrosion.NetworkRecord) compose.NetworkDef {
	var def compose.NetworkDef
	json.Unmarshal([]byte(nr.Config), &def) //nolint:errcheck
	def.Type = nr.Type
	return def
}

// ── Internal RPCs: Network Sync ─────────────────────────────────────────────

// ProvisionNetwork provisions a network on this host (called by peers during stack deploy).
func (s *Server) ProvisionNetwork(ctx context.Context, req *pb.ProvisionNetworkRequest) (*emptypb.Empty, error) {
	// Peer-only: provisioning is fanned out host-to-host over peer mTLS; there is
	// no direct CLI/UI caller.
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(req.Config), &def); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse config: %v", err)
	}
	def.Type = req.NetType
	// Interface should already be set in the config JSON by the caller.
	// Don't fall back to req.Name here — it may be stack-scoped.

	// Persist the network record locally so CreateVM can look it up
	// immediately — don't rely on replication from the calling host.
	ntype := req.NetType
	if ntype == "" {
		ntype = "bridge"
	}
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:      req.Name,
		StackName: req.StackName,
		Type:      ntype,
		Config:    req.Config,
	}); err != nil {
		slog.Warn("ProvisionNetwork: persist failed", "network", req.Name, "error", err)
	}

	localIP := getLocalIP()
	if _, err := network.SafeProvision(ctx, s.db, req.Name, def, localIP, s.hostName); err != nil {
		return nil, status.Errorf(codes.Internal, "provision network %q: %v", req.Name, err)
	}
	// Fail closed: don't report a provisioned network while its host-isolation/NAT
	// rules haven't applied.
	if err := s.reconcileFirewallRequired(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "apply firewall for network %q: %v", req.Name, err)
	}

	// For VXLAN, notify existing peers about our VTEP.
	if def.Type == "vxlan" && def.VNI != 0 {
		s.notifyVTEPPeers(ctx, req.Name, def.VNI, localIP)
	}

	return &emptypb.Empty{}, nil
}

// SyncVTEP adds a flood entry for a remote VTEP on this host.
func (s *Server) SyncVTEP(ctx context.Context, req *pb.SyncVTEPRequest) (*emptypb.Empty, error) {
	// Peer-only: VTEP flood sync is a host-to-host fan-out over peer mTLS.
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := network.FloodEntry(int(req.Vni), req.VtepIp); err != nil {
		return nil, status.Errorf(codes.Internal, "add flood entry: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// GetVMIPRemote discovers a workload's IP LOCALLY for a peer doing LB backend
// discovery: a VM (owner_kind "" / "vm") by MAC via ARP/DHCP, or a container
// (owner_kind "ct") by name via lxc-info, falling back to its recorded managed
// interface row. PEER-ONLY: it's a cluster-internal discovery call, so it requires
// a peer host certificate (an operator bearer/user credential cannot reach it) —
// this also closes the gap that it was previously ungated.
func (s *Server) GetVMIPRemote(ctx context.Context, req *pb.GetVMIPRequest) (*pb.GetVMIPResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.OwnerKind == "ct" {
		// owner_name is wire-supplied and composes a shell argument (lxc-info -n) and
		// a DB lookup — validate it before any runtime/DB touch (defense in depth even
		// though this RPC is peer-only).
		if err := safename.ValidateContainerName(req.OwnerName); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		ip := ""
		if s.containerRuntime != nil {
			if v, err := s.containerRuntime.IPContainer(ctx, req.OwnerName); err == nil {
				ip = v
			}
		}
		if ip == "" {
			ifaces, _ := corrosion.GetContainerInterfaces(ctx, s.db, s.hostName, req.OwnerName)
			for _, ifc := range ifaces {
				if ifc.IP != "" {
					ip = ifc.IP
					break
				}
			}
		}
		return &pb.GetVMIPResponse{Ip: ip}, nil
	}
	ip := lv.GetIPFromARP(req.Mac)
	if ip == "" {
		ip = lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", req.Mac)
	}
	return &pb.GetVMIPResponse{Ip: ip}, nil
}

// UpdateFDB updates a unicast FDB entry on this host (called by peers during migration/discovery).
func (s *Server) UpdateFDB(ctx context.Context, req *pb.UpdateFDBRequest) (*emptypb.Empty, error) {
	// Peer-only: FDB updates are a host-to-host fan-out over peer mTLS.
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.OldVtepIp != "" {
		network.DeleteFDBEntry(int(req.Vni), req.Mac, req.OldVtepIp)
	}
	if req.NewVtepIp != "" {
		if err := network.AddFDBEntry(int(req.Vni), req.Mac, req.NewVtepIp); err != nil {
			return nil, status.Errorf(codes.Internal, "add FDB: %v", err)
		}
	}
	return &emptypb.Empty{}, nil
}

// provisionNetworkOnRemote forwards a ProvisionNetwork RPC to a remote host.
// Best-effort — logs warnings on failure but doesn't block the caller.
func (s *Server) provisionNetworkOnRemote(ctx context.Context, targetHost, networkName string) {
	if targetHost == s.hostName {
		return // local, already handled
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil || nr == nil {
		return // not in DB — flat bridge, nothing to provision
	}
	client, conn, err := s.peerClient(ctx, targetHost)
	if err != nil {
		slog.Warn("provisionNetworkOnRemote: cannot reach host", "host", targetHost, "error", err)
		return
	}
	defer conn.Close()
	if _, err := client.ProvisionNetwork(ctx, remoteProvisionRequest(networkName, nr)); err != nil {
		slog.Warn("provisionNetworkOnRemote: provision failed", "host", targetHost, "network", networkName, "error", err)
	}
}

// provisionNetworkRequest is the single builder for a ProvisionNetwork request.
// Every call site MUST go through it so a field (notably stack_name, whose
// omission orphaned networks at teardown) can never be silently dropped again.
func provisionNetworkRequest(name, cfgJSON, netType, stackName string) *pb.ProvisionNetworkRequest {
	if netType == "" {
		netType = "bridge"
	}
	return &pb.ProvisionNetworkRequest{
		Name:      name,
		Config:    cfgJSON,
		NetType:   netType,
		StackName: stackName,
	}
}

// remoteProvisionRequest builds the ProvisionNetwork request sent to a peer when
// a network must exist on another host (e.g. during migration), from its record.
func remoteProvisionRequest(networkName string, nr *corrosion.NetworkRecord) *pb.ProvisionNetworkRequest {
	return provisionNetworkRequest(networkName, nr.Config, nr.Type, nr.StackName)
}

// notifyVTEPPeersForNetwork looks up the network record, and if it's VXLAN,
// notifies peers about this host's VTEP. Convenience wrapper for use in CreateVM.
func (s *Server) notifyVTEPPeersForNetwork(ctx context.Context, networkName string) {
	nr, err := corrosion.GetNetwork(ctx, s.db, networkName)
	if err != nil || nr == nil || nr.Type != "vxlan" {
		return
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(nr.Config), &def); err != nil || def.VNI == 0 {
		return
	}
	localIP := getLocalIP()
	s.notifyVTEPPeers(ctx, networkName, def.VNI, localIP)
}

// notifyVTEPPeers tells all existing VTEP hosts for a network to add this host's flood entry.
func (s *Server) notifyVTEPPeers(ctx context.Context, networkName string, vni int, localVTEP string) {
	vteps, err := network.GetVTEPs(ctx, s.db, networkName)
	if err != nil {
		return
	}
	for _, v := range vteps {
		if v.HostName == s.hostName {
			continue
		}
		go func(host string) {
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			client.SyncVTEP(ctx, &pb.SyncVTEPRequest{
				NetworkName: networkName,
				VtepIp:      localVTEP,
				Vni:         int32(vni),
			})
		}(v.HostName)
	}
}
