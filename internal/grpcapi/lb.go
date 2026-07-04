package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lb"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

func (s *Server) ListLoadBalancers(ctx context.Context, _ *emptypb.Empty) (*pb.ListLBResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT name, stack_name, vip, algorithm, hosts, ports, enabled FROM lb_configs WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query lb_configs: %v", err)
	}

	resp := &pb.ListLBResponse{}
	for _, r := range rows {
		algo := r.String("algorithm")
		if algo == "" {
			algo = "roundrobin"
		}
		state := "active"
		if r.Int("enabled") == 0 {
			state = "disabled"
		}
		var lbHosts []string
		if h := r.String("hosts"); h != "" && h != "[]" {
			json.Unmarshal([]byte(h), &lbHosts)
		}
		var ports []*pb.LBPort
		if p := r.String("ports"); p != "" && p != "[]" {
			json.Unmarshal([]byte(p), &ports)
		}
		resp.Lbs = append(resp.Lbs, &pb.LoadBalancer{
			Name:       r.String("name"),
			Vip:        r.String("vip"),
			Algorithm:  algo,
			ActiveHost: s.hostName,
			LbHosts:    lbHosts,
			State:      state,
			StackName:  r.String("stack_name"),
			Ports:      ports,
			Backends:   s.lbBackends(ctx, r.String("name")),
		})
	}
	return resp, nil
}

// lbBackends returns the live backend list for an LB by looking up running VMs
// in the corresponding stack, or explicit backends from lb_backends table.
// containerBackendIP resolves a stack container's address for LB backend use, in
// order: the static label (corrosion.LabelIP), the recorded managed-NIC IP (the
// container_interfaces row — replicated, so it covers a DHCP IP the owning host's
// scanner already discovered, even for a REMOTE container), then a live lxc-info
// lookup if it runs on this host, then (allowRemote) a peer lookup on the owning
// host. Returns "" when no IP is known yet (e.g. a DHCP NIC still acquiring) — the
// caller skips that backend and retries next sweep; never a stale/guessed address.
func (s *Server) containerBackendIP(ctx context.Context, ct corrosion.ContainerRecord, allowRemote bool) string {
	if ip := ct.Labels[corrosion.LabelIP]; ip != "" {
		return ip
	}
	ifaces, _ := corrosion.GetContainerInterfaces(ctx, s.db, ct.HostName, ct.Name)
	for _, ifc := range ifaces {
		if ifc.IP != "" {
			return ifc.IP
		}
	}
	if ct.State != "running" {
		return ""
	}
	if ct.HostName == s.hostName {
		if s.containerRuntime != nil {
			if ip, err := s.containerRuntime.IPContainer(ctx, ct.Name); err == nil {
				return ip
			}
		}
		return ""
	}
	if allowRemote {
		return s.remoteContainerIP(ctx, ct.HostName, ct.Name)
	}
	return ""
}

// remoteContainerIP asks the owning peer for a container's live IP via the
// generalized GetVMIPRemote (owner_kind="ct"). Best-effort, "" on any error.
func (s *Server) remoteContainerIP(ctx context.Context, host, ctName string) string {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return ""
	}
	defer conn.Close()
	resp, err := client.GetVMIPRemote(ctx, &pb.GetVMIPRequest{OwnerKind: "ct", OwnerName: ctName})
	if err != nil {
		return ""
	}
	return resp.Ip
}

// resolvedBackend is one LB backend (VM or container) with its discovered
// address and run-state, independent of the caller's output shape.
type resolvedBackend struct {
	Name    string
	IP      string
	Running bool
}

// remoteVMIP asks a peer for a VM interface's live IP (best-effort, "" on any error).
func (s *Server) remoteVMIP(ctx context.Context, host, mac, networkName string) string {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return ""
	}
	defer conn.Close()
	resp, err := client.GetVMIPRemote(ctx, &pb.GetVMIPRequest{Mac: mac, NetworkName: networkName})
	if err != nil {
		return ""
	}
	return resp.Ip
}

// resolveStackBackends resolves the LB backends for a stack — its VMs (address
// from the vm_interfaces row, then local ARP/DHCP for running VMs on this host,
// then a peer GetVMIPRemote lookup when allowRemote) and its containers
// (containerBackendIP). When persist is set, a freshly-discovered VM IP is
// written back to vm_interfaces. The status path uses allowRemote=false /
// persist=false (fast, read-only — keeps `lv lb ls` cheap); the render path
// uses allowRemote=true / persist=true (full discovery). This is the single
// source of truth for "which backends does this stack's LB have."
func (s *Server) resolveStackBackends(ctx context.Context, stackName string, allowRemote, persist bool) []resolvedBackend {
	vms, err := corrosion.ListVMs(ctx, s.db, stackName, "")
	if err != nil {
		slog.Warn("resolveStackBackends: list VMs", "stack", stackName, "error", err)
		return nil
	}
	var out []resolvedBackend
	for _, vm := range vms {
		running := vm.State == "running"
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
		ip := ""
		for _, iface := range ifaces {
			ip = iface.IP
			// Live discovery only makes sense for a running VM.
			if ip == "" && running && vm.HostName == s.hostName {
				ip = lv.GetIPFromARP(iface.MAC)
			}
			if ip == "" && running && vm.HostName == s.hostName {
				ip = lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", iface.MAC)
			}
			if ip == "" && running && allowRemote && vm.HostName != s.hostName {
				ip = s.remoteVMIP(ctx, vm.HostName, iface.MAC, iface.NetworkName)
			}
			if persist && running && ip != "" && ip != iface.IP {
				corrosion.UpdateVMInterfaceIP(ctx, s.db, vm.Name, iface.NetworkName, ip)
			}
			if ip != "" {
				break
			}
		}
		out = append(out, resolvedBackend{Name: vm.Name, IP: ip, Running: running})
	}
	// Containers in the stack (found via the reserved stack label). The render path
	// (allowRemote) resolves a remote DHCP container's IP via the owning peer.
	cts, _ := corrosion.ListContainersByStack(ctx, s.db, stackName)
	for _, ct := range cts {
		out = append(out, resolvedBackend{Name: ct.Name, IP: s.containerBackendIP(ctx, ct, allowRemote), Running: ct.State == "running"})
	}
	return out
}

// lbBackends returns the backend list for the LB status views. Run-state derived
// (a backend is "active" when its workload is running); InspectLoadBalancer
// overlays real HAProxy health on top. Read-only and no peer RPCs so `lv lb ls`
// stays fast.
func (s *Server) lbBackends(ctx context.Context, lbName string) []*pb.LBBackend {
	// Explicit backends first (standalone LBs).
	if explicit, _ := corrosion.ListLBBackends(ctx, s.db, lbName); len(explicit) > 0 {
		var backends []*pb.LBBackend
		for _, b := range explicit {
			st := "active"
			if !b.Enabled {
				st = "disabled"
			}
			backends = append(backends, &pb.LBBackend{VmName: b.VMName, Address: b.Address, Status: st})
		}
		return backends
	}

	stackName := strings.TrimSuffix(lbName, "-lb")
	if stackName == lbName {
		return nil
	}

	var backends []*pb.LBBackend
	for _, rb := range s.resolveStackBackends(ctx, stackName, false, false) {
		st := "active"
		if !rb.Running {
			st = "down"
		}
		backends = append(backends, &pb.LBBackend{VmName: rb.Name, Address: rb.IP, Status: st})
	}
	return backends
}

// mapHAProxyStatus maps a raw HAProxy server status ("UP 2/3", "DOWN (agent)",
// "MAINT (via x/y)", "DRAIN", "NOLB") to litevirt's backend-status vocabulary,
// falling back to the workload-derived status on anything unexpected.
func mapHAProxyStatus(raw, fallback string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return fallback
	}
	switch {
	case fields[0] == "UP":
		return "active"
	case fields[0] == "DOWN":
		return "down"
	case strings.HasPrefix(fields[0], "MAINT"):
		return "maint"
	case fields[0] == "DRAIN":
		return "draining"
	case fields[0] == "NOLB":
		return "nolb"
	default:
		return fallback
	}
}

// lbHealthByServer returns the real HAProxy backend health (server name → raw
// status) for an LB, querying the local stats socket or forwarding to the LB
// host when haproxy isn't local. Used to overlay true health on the run-state
// status in InspectLoadBalancer.
func (s *Server) lbHealthByServer(ctx context.Context, lbName string) (map[string]string, error) {
	if s.lbHealthOverride != nil {
		return s.lbHealthOverride(ctx, lbName)
	}
	mgr := lb.NewManager()
	stats, err := mgr.GetStats(ctx, lbName)
	if err != nil {
		// HAProxy not running locally — forward to an LB host that has it.
		resp := s.forwardLBStats(ctx, &pb.LBStatsRequest{Name: lbName})
		if resp == nil {
			return nil, err
		}
		out := make(map[string]string, len(resp.Backends))
		for _, b := range resp.Backends {
			out[b.Name] = b.Status
		}
		return out, nil
	}
	out := map[string]string{}
	for _, e := range stats.Entries {
		if e.Type == 2 { // server row
			out[e.ServerName] = e.Status
		}
	}
	return out, nil
}

func (s *Server) InspectLoadBalancer(ctx context.Context, req *pb.InspectLBRequest) (*pb.LoadBalancer, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT name, stack_name, vip, algorithm, hosts, ports, enabled FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, req.Name)
	if err != nil || len(rows) == 0 {
		return nil, status.Errorf(codes.NotFound, "load balancer %q not found", req.Name)
	}
	r := rows[0]
	algo := r.String("algorithm")
	if algo == "" {
		algo = "roundrobin"
	}
	state := "active"
	if r.Int("enabled") == 0 {
		state = "disabled"
	}

	var lbHosts []string
	if h := r.String("hosts"); h != "" && h != "[]" {
		json.Unmarshal([]byte(h), &lbHosts)
	}
	if len(lbHosts) == 0 {
		// Empty hosts: resolve to hosts running VMs in this stack.
		if stackName := r.String("stack_name"); stackName != "" {
			vms, _ := corrosion.ListVMs(ctx, s.db, stackName, "")
			seen := map[string]bool{}
			for _, vm := range vms {
				if !seen[vm.HostName] {
					seen[vm.HostName] = true
					lbHosts = append(lbHosts, vm.HostName)
				}
			}
		}
	}

	var ports []*pb.LBPort
	if p := r.String("ports"); p != "" && p != "[]" {
		json.Unmarshal([]byte(p), &ports)
	}

	result := &pb.LoadBalancer{
		Name:       r.String("name"),
		Vip:        r.String("vip"),
		Algorithm:  algo,
		ActiveHost: s.hostName,
		LbHosts:    lbHosts,
		State:      state,
		StackName:  r.String("stack_name"),
		Ports:      ports,
		Backends:   s.lbBackends(ctx, r.String("name")),
	}

	// Overlay REAL HAProxy health onto the run-state-derived backend status, so
	// inspect reflects whether a backend is actually serving (not just whether
	// its workload is running). Inspect-only: listing every LB would fan out a
	// stats query per LB. On failure, keep run-state status + flag it.
	health, herr := s.lbHealthByServer(ctx, result.Name)
	if herr == nil {
		for _, b := range result.Backends {
			if hs, ok := health[b.VmName]; ok {
				b.Status = mapHAProxyStatus(hs, b.Status)
			}
		}
	} else if state == "active" {
		for _, b := range result.Backends {
			b.LastError = "haproxy health unavailable"
		}
	}

	// VIP health: an enabled LB is "degraded" when its VIP isn't actually
	// assigned anywhere. HAProxy binds the VIP non-locally, so without this a
	// down-VIP LB would still look "active". Checks keepalived across all target
	// hosts (local directly, remote via RPC).
	if state == "active" && s.lbVIPDegraded(ctx, result.Name, lbHosts) {
		result.State = "degraded"
	}
	return result, nil
}

// lbVIPDegraded reports whether an LB's VIP looks unassigned: across its target
// hosts, at least one answered the keepalived check AND none reported running
// (for a multi-host LB, one live keepalived can hold the VIP via VRRP, so any-up
// = healthy). Local hosts use the direct check; remote hosts use the RPC. An
// old peer that doesn't implement the RPC (or is unreachable) isn't counted as
// an answer — so we never falsely mark degraded in a mixed-version cluster.
func (s *Server) lbVIPDegraded(ctx context.Context, name string, lbHosts []string) bool {
	anyUp, anyAnswered := false, false
	for _, h := range lbHosts {
		if h == s.hostName {
			anyAnswered = true
			if s.lbKeepalivedRunning(name) {
				anyUp = true
			}
			continue
		}
		if running, ok := s.remoteLBKeepalived(ctx, h, name); ok {
			anyAnswered = true
			if running {
				anyUp = true
			}
		}
	}
	return anyAnswered && !anyUp
}

// remoteLBKeepalived asks a peer whether its keepalived for the LB is running.
// ok=false when the peer is unreachable or runs a version without the RPC
// (Unimplemented) — the caller then doesn't treat it as a definitive answer.
func (s *Server) remoteLBKeepalived(ctx context.Context, host, name string) (running, ok bool) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	resp, err := client.LBKeepalivedRunning(ctx, &pb.LBKeepalivedRequest{Name: name})
	if err != nil {
		return false, false
	}
	return resp.Running, true
}

// LBKeepalivedRunning reports whether THIS host's keepalived for the LB is alive
// (VIP assignable). Peers call it for InspectLoadBalancer's remote VIP-health.
func (s *Server) LBKeepalivedRunning(ctx context.Context, req *pb.LBKeepalivedRequest) (*pb.LBKeepalivedResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	return &pb.LBKeepalivedResponse{Running: s.lbKeepalivedRunning(req.Name)}, nil
}

// lbKeepalivedRunning reports whether this host's keepalived for an LB is alive
// (VIP assigned). Test seam: lbKeepalivedOverride replaces the real check.
func (s *Server) lbKeepalivedRunning(name string) bool {
	if s.lbKeepalivedOverride != nil {
		return s.lbKeepalivedOverride(name)
	}
	return lb.NewManager().KeepalivedRunning(name)
}

func (s *Server) DisableBackend(ctx context.Context, req *pb.DisableBackendRequest) (*pb.LoadBalancer, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	mgr := lb.NewManager()
	if err := mgr.SetBackendEnabled(ctx, req.LbName, req.Backend, false); err != nil {
		slog.Warn("disable backend", "lb", req.LbName, "backend", req.Backend, "error", err)
	}
	s.publish("lb.backend.disabled", req.LbName, fmt.Sprintf("backend=%s", req.Backend))
	s.audit(ctx, "lb.backend.disable", req.LbName, req.Backend, "ok")
	return s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: req.LbName})
}

func (s *Server) EnableBackend(ctx context.Context, req *pb.EnableBackendRequest) (*pb.LoadBalancer, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	mgr := lb.NewManager()
	if err := mgr.SetBackendEnabled(ctx, req.LbName, req.Backend, true); err != nil {
		slog.Warn("enable backend", "lb", req.LbName, "backend", req.Backend, "error", err)
	}
	s.publish("lb.backend.enabled", req.LbName, fmt.Sprintf("backend=%s", req.Backend))
	s.audit(ctx, "lb.backend.enable", req.LbName, req.Backend, "ok")
	return s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: req.LbName})
}

// ── CRUD + Stats + Drain ─────────────────────────────────────────────────────

// allocVRID picks a VRRP router-id for lbName that doesn't collide with the
// (hash-derived) VRID of any other active LB, probing to a free slot if needed
// and warning when it has to (F11). Operators can still assign explicitly.
func (s *Server) allocVRID(ctx context.Context, lbName string) int {
	used := map[int]bool{}
	if cfgs, err := corrosion.ListLBConfigs(ctx, s.db); err == nil {
		for _, c := range cfgs {
			if c.Name == lbName {
				continue
			}
			used[lb.AllocVRID(c.Name)] = true
		}
	}
	vrid := lb.AllocVRIDExcluding(lbName, used)
	if hashed := lb.AllocVRID(lbName); vrid != hashed {
		slog.Warn("LB VRRP router-id collision avoided by probing — assign an explicit VRID for stability",
			"lb", lbName, "hashed_vrid", hashed, "chosen_vrid", vrid)
	}
	return vrid
}

// validBackendAddress accepts a bare IP ("10.0.0.1", "::1") or an IP:port
// ("10.0.0.1:8080", "[::1]:80"). It rejects anything else — crucially anything
// with whitespace, quotes, or newlines that could inject directives into the
// HAProxy/keepalived templates (F2). Hostnames are intentionally not accepted:
// litevirt backends are always IPs.
func validBackendAddress(addr string) bool {
	if addr == "" {
		return false
	}
	if net.ParseIP(addr) != nil {
		return true
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535
}

func lbBackendName(b *pb.LBBackendAddress) string {
	if b.Name != "" {
		return b.Name
	}
	return b.Address
}

func reserveLBBackendName(seen map[string]struct{}, name string) error {
	if _, ok := seen[name]; ok {
		return status.Errorf(codes.InvalidArgument, "duplicate backend name %q", name)
	}
	seen[name] = struct{}{}
	return nil
}

func (s *Server) CreateLoadBalancer(ctx context.Context, req *pb.CreateLBRequest) (*pb.LoadBalancer, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	if !validResourceName(req.Name) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid load balancer name %q: only letters, digits, '_', '.', '-' are allowed", req.Name)
	}
	if req.Vip == "" {
		return nil, status.Error(codes.InvalidArgument, "vip required")
	}
	// Backend names/addresses are rendered into the root-run HAProxy +
	// keepalived configs, so validate them before anything is persisted.
	for _, b := range req.Backends {
		if b.Name != "" && !validResourceName(b.Name) {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid backend name %q: only letters, digits, '_', '.', '-' are allowed", b.Name)
		}
		if !validBackendAddress(b.Address) {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid backend address %q: must be an IP or IP:port", b.Address)
		}
	}
	if len(req.Ports) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one port required")
	}
	if len(req.Backends) == 0 && len(req.VmBackends) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one backend required")
	}
	backendNames := map[string]struct{}{}
	for _, b := range req.Backends {
		if err := reserveLBBackendName(backendNames, lbBackendName(b)); err != nil {
			return nil, err
		}
	}
	for _, vmName := range req.VmBackends {
		if err := reserveLBBackendName(backendNames, vmName); err != nil {
			return nil, err
		}
	}

	vipIP, vipPrefix, err := lb.ParseVIP(req.Vip)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid VIP: %v", err)
	}

	// Check name not already in use. A DB error must NOT be read as "free" —
	// that would bypass the uniqueness guard (F9).
	existing, err := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check name uniqueness: %v", err)
	}
	if len(existing) > 0 {
		return nil, status.Errorf(codes.AlreadyExists, "load balancer %q already exists", req.Name)
	}

	// Check VIP not already in use.
	existingVIP, err := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE vip = ? AND enabled = 1 AND deleted_at IS NULL`, req.Vip)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check VIP uniqueness: %v", err)
	}
	if len(existingVIP) > 0 {
		return nil, status.Errorf(codes.AlreadyExists, "VIP %s already in use by %q", req.Vip, existingVIP[0].String("name"))
	}

	// Split-brain gate (Phase 2): creating a VIP is a NEW runtime-ownership claim. The
	// DB uniqueness check above only proves no OTHER row uses it — not that the address
	// is actually free in the kernel. A prior delete or partition could have left a
	// keepalived still answering the VIP after its row disappeared; claiming it then
	// would overlap. Require a cluster KERNEL-ABSENCE proof: the VIP must be unassigned
	// on every cluster host. Fails closed if it can't be confirmed (unreachable host /
	// enumeration error) — the same pre-Phase-5 availability tradeoff as elsewhere.
	// Inert until vip_demote_v1 is enforced cluster-wide.
	if reason, refused := s.vipClaimRefused(ctx, req.Vip); refused {
		s.noteGateRefused(corrosion.ActionLBApply, reason)
		return nil, status.Errorf(codes.FailedPrecondition, "lb create refused: VIP not provably free — %s", reason)
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "roundrobin"
	}

	// Build backends.
	var lbBackends []lb.Backend
	var backendRecords []corrosion.LBBackendRecord
	backendPort := int(req.Ports[0].Target)

	// Mint a fresh generation token for this incarnation. Readers render only
	// backends carrying the current config's generation, so a stale backend a
	// partitioned peer still holds (and this node never saw) can merge under
	// anti-entropy but never renders — recreating the same name can't re-route
	// traffic to a removed backend.
	generation := newID()

	// Explicit backends.
	for _, b := range req.Backends {
		addr := b.Address
		name := b.Name
		if name == "" {
			name = addr
		}
		lbBackends = append(lbBackends, lb.Backend{Name: name, IP: addr, Port: backendPort})
		backendRecords = append(backendRecords, corrosion.LBBackendRecord{
			LBName: req.Name, Name: name, Address: addr, Enabled: true,
		})
	}

	// VM backends — resolve IPs.
	for _, vmName := range req.VmBackends {
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vmName)
		for _, iface := range ifaces {
			ip := iface.IP
			if ip == "" && iface.MAC != "" {
				ip = lv.GetIPFromARP(iface.MAC)
			}
			if ip != "" {
				lbBackends = append(lbBackends, lb.Backend{Name: vmName, IP: ip, Port: backendPort})
				backendRecords = append(backendRecords, corrosion.LBBackendRecord{
					LBName: req.Name, Name: vmName, Address: ip, IsVM: true, VMName: vmName, Enabled: true,
				})
				break
			}
		}
	}

	// Persist the config + the full backend set as ONE atomic batch stamped with
	// the new generation: a recreate bulk-tombstones any prior backends and
	// re-stamps the survivors, so the persistent model is never left half-written
	// for the DB-render reapply to act on (was warn-only per-row before).
	hostsJSON, _ := json.Marshal(req.Hosts)
	portsJSON, _ := json.Marshal(req.Ports)
	if err := corrosion.PersistLBFull(ctx, s.db, corrosion.LBConfigRecord{
		Name:       req.Name,
		VIP:        req.Vip,
		Algorithm:  algorithm,
		Hosts:      string(hostsJSON),
		Ports:      string(portsJSON),
		Enabled:    true,
		Generation: generation,
	}, backendRecords); err != nil {
		return nil, status.Errorf(codes.Internal, "persist LB config: %v", err)
	}

	// Build ports.
	var ports []lb.Port
	for _, p := range req.Ports {
		ports = append(ports, lb.Port{
			Listen:   int(p.Listen),
			Target:   int(p.Target),
			Protocol: p.Protocol,
		})
	}

	// Determine LB hosts.
	targetHosts := req.Hosts
	if len(targetHosts) == 0 {
		targetHosts = []string{s.hostName}
	}

	// Apply locally if this host is a target.
	for _, h := range targetHosts {
		if h == s.hostName {
			priority := 50
			if targetHosts[0] == s.hostName {
				priority = 100
			}
			cfg := lb.Config{
				Name:      req.Name,
				VIP:       vipIP,
				VIPPrefix: vipPrefix,
				Interface: lb.DetectInterfaceForIP(vipIP),
				VRID:      s.allocVRID(ctx, req.Name),
				Priority:  priority,
				Backends:  lbBackends,
				Ports:     ports,
				Algorithm: algorithm,
			}
			if err := s.applyLBLocal(ctx, cfg); err != nil {
				// Provisioning failed on this host (bad backend address, VIP
				// conflict, invalid config, …). Roll back the persisted config so
				// `lv lb ls` doesn't show a phantom "active" LB that isn't
				// actually serving, and surface the failure to the caller instead
				// of silently logging it.
				corrosion.SoftDeleteLBBackends(ctx, s.db, req.Name)
				corrosion.SoftDeleteLBConfig(ctx, s.db, req.Name)
				s.audit(ctx, "lb.create", req.Name, req.Vip, "error: "+err.Error())
				return nil, status.Errorf(codes.Internal,
					"load balancer %q provisioning failed on %s: %v", req.Name, s.hostName, err)
			}
			break
		}
	}

	// Forward to remote LB hosts.
	var pbBackends []*pb.LBBackend
	for _, b := range lbBackends {
		pbBackends = append(pbBackends, &pb.LBBackend{VmName: b.Name, Address: b.IP, Status: "active"})
	}
	for _, h := range targetHosts {
		if h == s.hostName {
			continue
		}
		go func(host string) {
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			proof := s.mintLBProof(ctx, req.Name, host)
			if s.gateActive(ctx) && proof == nil {
				slog.Error("CreateLoadBalancer: cannot mint LB proof under enforcement; skipping remote apply",
					"host", host, "lb", req.Name)
				return
			}
			if _, aerr := client.ApplyLB(ctx, &pb.ApplyLBRequest{
				LbName: req.Name, Vip: req.Vip, Algorithm: algorithm,
				Backends: pbBackends, Ports: req.Ports, Hosts: req.Hosts, Proof: proof,
			}); aerr != nil {
				slog.Warn("CreateLoadBalancer: remote apply failed", "host", host, "lb", req.Name, "error", aerr)
			}
		}(h)
	}

	s.publish("lb.created", req.Name, fmt.Sprintf("vip=%s", req.Vip))
	s.audit(ctx, "lb.create", req.Name, req.Vip, "ok")
	return s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: req.Name})
}

// applyLBLocal provisions the LB on this host (haproxy + keepalived). The
// lbApplyDisabled test seam lets unit tests exercise CreateLoadBalancer's
// persistence + rollback logic without root privileges or a haproxy binary.
func (s *Server) applyLBLocal(ctx context.Context, cfg lb.Config) error {
	// Split-brain gate (Phase 1): claiming/serving a VIP requires local quorum,
	// enforced at this single chokepoint so BOTH the ApplyLB RPC and the
	// event-triggered refresh path (refreshLBLocal → applyLBFromSpec) are covered —
	// an isolated minority host must not bring up a VIP via keepalived. Fail-open
	// until split_brain_gate_v1 is cluster-wide. (Routine LB apply is event-driven,
	// not failover-lease-driven, so local ExecutionGate — not a coordinator proof —
	// is the right gate; a proof is validated separately when a caller supplies one.)
	if reason, refused := s.lbGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionLBApply, reason)
		return status.Errorf(codes.FailedPrecondition, "lb apply refused: %s", reason)
	}
	// NOTE: the Phase-2 VIP-takeover gate is NOT here. Whether a new claim is safe is
	// a TRANSITION decision (which OLD holder is being removed and must release), and
	// only the orchestration sites (applyLBFromSpec / UpdateLoadBalancer) know old vs
	// new. A local snapshot check here — "is any other current holder assigned?" —
	// would wrongly refuse normal multi-host VRRP (exactly one holder should be the
	// master). The orchestration gate runs BEFORE this apply is reached (locally or
	// via a forwarded ApplyLB), so this chokepoint only enforces the Phase-1 quorum
	// gate above.
	var err error
	if s.lbApplyOverride != nil {
		err = s.lbApplyOverride(ctx, cfg)
	} else {
		err = lb.NewManager().Apply(ctx, cfg)
	}
	if err == nil {
		s.recordLBKeepalived(cfg.Name) // publish whether the VIP came up
	}
	return err
}

// CheckVIPParticipant reports whether THIS host could HOLD or BECOME MASTER of the VIP —
// it renders a keepalived config for it (VRRP participant: master OR backup) or the
// address is assigned on its kernel. The by-VIP ownership signal Phase 2 gates on; a
// kernel-address-only check would miss a backup. Peer-only. Fails CLOSED on an `ip`
// error (returns an error so the caller treats it as "still claiming").
func (s *Server) CheckVIPParticipant(ctx context.Context, req *pb.CheckVIPParticipantRequest) (*pb.CheckVIPParticipantResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "CheckVIPParticipant is peer-only")
	}
	claims, err := lb.NewManager().ClaimsVIP(req.Vip)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot determine VIP participation: %v", err)
	}
	return &pb.CheckVIPParticipantResponse{Claims: claims}, nil
}

// RelayCheckVIPParticipant probes a THIRD host {target_host, vip} on the caller's behalf —
// the relay leg of the fresh-VIP absence proof for a target the caller can't reach directly
// (a permanent directional segmentation where this relay CAN reach it). It DECIDES nothing
// and keeps NO cache / no wall-clock freshness claim / no durable proof: it does a FRESH
// capability Ping (target must advertise vip_release_probe_v1 — it answers absence probes
// authoritatively) THEN a FRESH CheckVIPParticipant against the target, and returns a
// tri-state. Every failure — unreachable/unsupported target, RPC error — maps to UNKNOWN so
// the caller fails closed. Peer-only (mTLS).
func (s *Server) RelayCheckVIPParticipant(ctx context.Context, req *pb.RelayCheckVIPParticipantRequest) (*pb.RelayCheckVIPParticipantResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "RelayCheckVIPParticipant is peer-only")
	}
	if req.TargetHost == "" || req.Vip == "" {
		return nil, status.Error(codes.InvalidArgument, "target_host and vip required")
	}
	unknown := &pb.RelayCheckVIPParticipantResponse{Result: pb.RelayVIPResult_RELAY_VIP_UNKNOWN}

	// Target is THIS relay itself → answer from the local by-VIP check (no self-dial).
	if req.TargetHost == s.hostName {
		claims, err := lb.NewManager().ClaimsVIP(req.Vip)
		if err != nil {
			return unknown, nil
		}
		return &pb.RelayCheckVIPParticipantResponse{Result: relayVIPResult(claims)}, nil
	}
	// Fresh capability Ping: only trust a target that advertises vip_release_probe_v1 (it
	// answers by-VIP absence probes authoritatively, so its CheckVIPParticipant answer is a
	// valid release-proof input). Uncached.
	if s.gate == nil || !s.gate.PeerSupportsFresh(ctx, req.TargetHost, capabilities.VIPReleaseProbeV1) {
		return unknown, nil
	}
	// Fresh CheckVIPParticipant against the target.
	c, closeConn, err := s.dialPeer(ctx, req.TargetHost)
	if err != nil {
		return unknown, nil
	}
	defer closeConn()
	resp, err := c.CheckVIPParticipant(ctx, &pb.CheckVIPParticipantRequest{Vip: req.Vip})
	if err != nil {
		return unknown, nil
	}
	return &pb.RelayCheckVIPParticipantResponse{Result: relayVIPResult(resp.GetClaims())}, nil
}

// relayVIPResult maps a target's boolean claim into the relay tri-state (never UNKNOWN —
// UNKNOWN is reserved for a relay that couldn't reach/verify the target).
func relayVIPResult(claims bool) pb.RelayVIPResult {
	if claims {
		return pb.RelayVIPResult_RELAY_VIP_CLAIMS
	}
	return pb.RelayVIPResult_RELAY_VIP_NO_CLAIMS
}

// CheckLBPresent reports whether THIS host is a configured participant for the LB (has a
// keepalived config or a running keepalived for it) — including a VRRP BACKUP that holds
// no VIP but could become master. Phase 2 uses it to find the true old-holder set for
// implicit/legacy hosts=[] LBs. Peer-only.
func (s *Server) CheckLBPresent(ctx context.Context, req *pb.CheckLBPresentRequest) (*pb.CheckLBPresentResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "CheckLBPresent is peer-only")
	}
	if req.LbName == "" {
		return nil, status.Error(codes.InvalidArgument, "lb_name required")
	}
	return &pb.CheckLBPresentResponse{Present: lb.NewManager().HasLB(req.LbName)}, nil
}

// holderStatus is one configured LB holder's reclaim-relevant state (fresh-probed via
// the probeHolder seam). The transition gate (removedHolderReleased) consults only
// reachable + assigned: a removed holder must be reachable AND report the VIP not
// assigned to count as released. supports (advertises vip_release_probe_v1) is retained
// for the seam/diagnostics but is NOT itself consulted here — the real trust check lives in
// participantReachable / peerVIPClaims, which require the token before trusting an answer.
type holderStatus struct {
	reachable bool // fresh probe succeeded
	supports  bool // advertises vip_release_probe_v1 (answers absence probes authoritatively)
	assigned  bool // VIP currently assigned on its kernel
}

// vipGateActive reports whether Phase-2 MAJORITY-side takeover gating is ENFORCED
// cluster-wide: the same durable, latched Enforced() decision Phase 1 uses — every
// enforcement-relevant member advertises vip_release_probe_v1 (so the majority can obtain a
// trusted release proof about any of them), latched so a partition fails closed. Keyed off
// the release-probe token, not vip_demote_v1: the two flip together, and it is the ability to
// PROVE release cluster-wide that makes proof-gated reclaim safe to enforce. NOT a local
// "does this build advertise it" check, which would activate the flip on the first rolled
// node before the cluster can participate. Overridable in tests via s.vipGateFlipped.
func (s *Server) vipGateActive(ctx context.Context) bool {
	if s.vipGateFlipped != nil {
		return s.vipGateFlipped()
	}
	return s.gate != nil && s.gate.Enforced(ctx, capabilities.VIPReleaseProbeV1)
}

// removedHosts returns the hosts present in old but absent from new — the holders
// being taken OFF the LB by this change. Self is NOT filtered out: if THIS host is
// the one being removed, it must release the VIP too. Empty entries are dropped.
func removedHosts(old, new []string) []string {
	newSet := make(map[string]bool, len(new))
	for _, h := range new {
		newSet[h] = true
	}
	var removed []string
	for _, h := range old {
		if h != "" && !newSet[h] {
			removed = append(removed, h)
		}
	}
	return removed
}

// parseHostsJSON decodes a stored hosts column ("[]" / "" / a JSON array). ok=false
// only when a non-empty value fails to parse — the member set is the Phase-2 boundary,
// so a corrupt value must read as UNKNOWN (fail closed), not as an empty set.
func parseHostsJSON(s string) (hosts []string, ok bool) {
	if s == "" || s == "[]" {
		return nil, true
	}
	if err := json.Unmarshal([]byte(s), &hosts); err != nil {
		return nil, false
	}
	return hosts, true
}

// vipMoveRefused is the Phase-2 orchestration-side gate: may this change cause any
// host to NEWLY claim the VIP? It is a TRANSITION predicate, not a snapshot — it acts
// on ONLY the removed holders (old∖new); an unchanged/added holder that currently has
// the VIP is normal VRRP state (exactly one master) and must NOT block the operation.
//
// For each removed holder it does break-before-make with a STRONG release proof:
//  1. synchronously stand the holder down (RemoveLB → keepalived stopped + config
//     removed, so it can't later become VRRP master and re-claim the VIP);
//  2. then require the VIP address is no longer assigned there.
//
// Absence alone is NOT release: a removed holder that is a VRRP BACKUP reports the VIP
// absent while still able to take over, so we must first make its keepalived inert.
//
// VIP semantics (oldVip = the address current holders serve; newVip = the address after
// this change; equal when the VIP isn't changing): removed holders are proven to release
// oldVip (what they actually had); a fresh claim / VIP change proves newVip is free. This
// split matters for a combined VIP+host change — verifying a removed holder against newVip
// would check an address it never served and miss a stale oldVip assignment.
//
// Fails closed everywhere: unknown old membership refuses; a stand-down that errors
// (unreachable / RPC failure) refuses; a holder still claiming after stand-down refuses.
// When old membership is empty it is resolved from GROUND TRUTH (who actually holds the
// VIP now) so an implicit/legacy stack LB can't hide a removed holder. Inert until
// vip_release_probe_v1 is enforced cluster-wide (the majority-side takeover latch).
func (s *Server) vipMoveRefused(ctx context.Context, lbName, oldVip, newVip string, oldHosts, newHosts []string, oldKnown, hostsChanged bool) (string, bool) {
	if !s.vipGateActive(ctx) {
		return "", false // inert until enforced cluster-wide
	}
	if !oldKnown {
		// Can't determine which holders are being removed — the member set is the
		// Phase-2 security boundary, so an unreadable old set must refuse.
		return health.ReasonVIPReleaseUnconfirmed, true
	}

	// Prove newVip is free before bringing it up, UNLESS we can affirmatively establish
	// the existing participants already legitimately serve exactly it — i.e. only skip when
	// oldVip is KNOWN and equals newVip. This covers three cases as one:
	//   - oldVip != newVip: a VIP change (fresh claim of newVip);
	//   - oldVip == "": the row is absent so the old VIP is UNKNOWN — bringing up newVip is
	//     effectively a fresh claim. Treating "" as "no proof needed" was the hole: a
	//     recreated stack LB whose row was lost but whose stale by-name participants still
	//     exist would fill oldHosts below and skip the fresh-claim branch, claiming newVip
	//     unproven. Must prove it even when by-name participants are found.
	// (Redundant with the no-participant fresh-claim branch for a truly brand-new LB, which
	// is harmless — vipAbsenceRefused short-circuits on the first refusal.)
	if oldVip == "" || oldVip != newVip {
		if reason, refused := s.vipAbsenceRefused(ctx, newVip); refused {
			return reason, true
		}
	}

	if len(oldHosts) == 0 {
		// Stored membership is empty. This is a genuinely-holderless LB OR an
		// implicit/legacy stack LB whose real participants were only ever derived at
		// runtime (never persisted) — in which case old∖new would hide a removed
		// participant. Resolve the ACTUAL participants from ground truth. This asks
		// "who is CONFIGURED for this LB" (keepalived present), NOT just "who holds the
		// VIP address" — a VRRP BACKUP holds no VIP yet can still become master.
		participants, ok := s.actualLBParticipants(ctx, lbName)
		if !ok {
			return health.ReasonVIPReleaseUnconfirmed, true // can't enumerate → fail closed
		}
		oldHosts = participants
	}

	if !hostsChanged {
		// No host move requested (e.g. a VIP-only edit): the target set equals the CURRENT
		// participants, not the literal newHosts. This matters for an implicit hosts=[] LB
		// whose "unchanged" set isn't literally [] — treating [] as the new set would mark
		// every live participant as removed and tear the LB down.
		newHosts = oldHosts
	}

	if len(oldHosts) == 0 {
		// No existing participant to move FROM: this is a FRESH claim (first bring-up or
		// a recreate of a deleted stack LB). Prove the CLAIMED vip (newVip) is free of
		// participants cluster-wide — catches a config-less orphan keepalived or a stale
		// kernel VIP a prior delete/partition left behind, which the by-name participant
		// check can't. (This is why stack LBs, which reach the gate only through here, are
		// covered without a separate call.)
		return s.vipAbsenceRefused(ctx, newVip)
	}

	// The set that must be stood down + provably released before we proceed: holders
	// LEAVING the LB (old∖new). A first-host (VRRP master) change is takeover-like — the
	// OLD master must relinquish before the NEW one claims, else both could master under
	// a VRRP-segment partition — so add the old master too (it is re-applied as a backup
	// afterwards: break-before-make for the master role).
	mustRelease := removedHosts(oldHosts, newHosts)
	masterChanged := len(oldHosts) > 0 && len(newHosts) > 0 && oldHosts[0] != newHosts[0]
	if masterChanged {
		mustRelease = appendUnique(mustRelease, oldHosts[0])
	}

	// Adding a participant OR changing the master brings up a NEW VRRP claimant. That is
	// a new runtime-ownership action: it is only safe if the RETAINED existing
	// participants are reachable (so VRRP adverts flow and the newcomer won't self-elect
	// master alongside an unreachable-but-live holder). Fail closed on any unreachable
	// retained participant. (Retained = old∩new and NOT already being released.)
	adding := len(removedHosts(newHosts, oldHosts)) > 0
	if adding || masterChanged {
		releasing := make(map[string]bool, len(mustRelease))
		for _, h := range mustRelease {
			releasing[h] = true
		}
		newSet := make(map[string]bool, len(newHosts))
		for _, h := range newHosts {
			newSet[h] = true
		}
		for _, h := range oldHosts {
			if releasing[h] || !newSet[h] {
				continue // handled by the release proof below / not retained
			}
			if !s.participantReachable(ctx, h) {
				return health.ReasonVIPReleaseUnconfirmed, true
			}
		}
	}

	for _, h := range mustRelease {
		// (1) Stand the holder down so its keepalived is inert.
		if err := s.standDownHolder(ctx, lbName, h); err != nil {
			return health.ReasonVIPReleaseUnconfirmed, true
		}
		// (2) Require it no longer claims the OLD VIP it was serving (a config for it or
		//     the address) — not newVip, which it never had.
		if !s.removedHolderReleased(ctx, h, oldVip) {
			return health.ReasonVIPReleaseUnconfirmed, true
		}
	}
	return "", false
}

// vipClaimRefused gates a FRESH VIP claim (CreateLoadBalancer): the VIP must be provably
// free of PARTICIPANTS across the cluster before we bring it up — no host renders a
// keepalived config for it (master or backup) and no kernel holds it — so a leftover
// keepalived from a prior delete/partition can't overlap with the new claim. Inert until
// enforced; fails closed when absence can't be confirmed.
func (s *Server) vipClaimRefused(ctx context.Context, vip string) (string, bool) {
	if !s.vipGateActive(ctx) {
		return "", false // inert until enforced cluster-wide
	}
	return s.vipAbsenceRefused(ctx, vip)
}

// vipAbsenceRefused is the by-VIP participant-absence check itself (no gate guard):
// refuse unless the VIP is provably unclaimable across the cluster. Shared by the create
// claim gate and vipMoveRefused's fresh-claim branch.
func (s *Server) vipAbsenceRefused(ctx context.Context, vip string) (string, bool) {
	claimable, ok := s.vipClaimableAnywhere(ctx, vip)
	if !ok || claimable {
		return health.ReasonVIPReleaseUnconfirmed, true // unproven absence / a participant exists → fail closed
	}
	return "", false
}

// vipClaimableAnywhere reports whether ANY cluster host could hold or become master of
// the VIP — a by-VIP PARTICIPANT (renders a keepalived config for it: master OR backup)
// or a kernel address holder. ok=false — fail closed — if the host list can't be
// enumerated or the local check errors. peerVIPClaims fail-closes to claims=true on any
// error, so an unreachable host reads as claiming (absence unproven → refuse).
//
// Scope (High: offline is NOT a fence proof): it probes EVERY non-deleted host, NOT just
// the quorum-"voting-eligible" ones. A host is marked "offline"/"fenced" even when a
// fence only PARTIALLY succeeded (see FenceHost, which marks offline regardless of fence
// success), so those states don't prove the host is down and its VIP gone — excluding
// them could let a still-live host keep a leftover VIP that a fresh claim then overlaps.
// Only a genuinely-removed host (deleted_at, already filtered by ListHosts) is skipped.
// Reclaiming from a PROVEN-fenced host is the Phase-5 domain; here we fail closed (a
// fresh claim is refused while any non-deleted host is unreachable — the safe gap).
//
// OPERATOR CAVEAT (H3): on a DIRECTIONALLY-SEGMENTED topology (a live, non-deleted host
// THIS caller can't reach over gRPC) a caller-local probe alone would refuse fresh VIP
// claims from the segmented side forever. The relay-probe (RelayCheckVIPParticipant) now
// covers that: an unreachable-but-live host is probed via a quorum-visible peer that CAN
// reach it, so the claim proceeds when the relay proves absence. It only stays fail-closed
// when NO reachable peer can reach the target either (a truly isolated host that might hold
// a leftover VIP) — the correct posture, surfaced by the persistent `unsupported_member`
// HA-degraded status. Do NOT silently exclude an unreachable host — that reopens the
// leftover-VIP hole. (Callers with a valid path to every member never hit this.)
func (s *Server) vipClaimableAnywhere(ctx context.Context, vip string) (claimable bool, ok bool) {
	if s.vipHoldersOverride != nil {
		holders, ok := s.vipHoldersOverride(ctx, vip) // test seam
		return len(holders) > 0, ok
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return false, false
	}
	for _, h := range hosts {
		if h.Name == s.hostName {
			c, cerr := lb.NewManager().ClaimsVIP(vip)
			if cerr != nil {
				return false, false // local check failed → unknown → fail closed
			}
			if c {
				return true, true
			}
			continue
		}
		if s.peerVIPClaims(ctx, h.Name, vip) {
			return true, true
		}
	}
	return false, true
}

// appendUnique appends h to xs unless already present.
func appendUnique(xs []string, h string) []string {
	for _, x := range xs {
		if x == h {
			return xs
		}
	}
	return append(xs, h)
}

// participantReachable reports whether an EXISTING LB participant is reachable enough to
// coordinate VRRP with a new claimant AND can be trusted for a release proof. Self is always
// reachable. For a peer it uses a FRESH Ping that also confirms it advertises
// vip_release_probe_v1 (reachable AND answers by-VIP absence probes authoritatively); an
// unreachable/incapable existing participant fails closed. Overridable in tests via the
// probeHolder seam (its reachable field).
func (s *Server) participantReachable(ctx context.Context, host string) bool {
	if host == s.hostName {
		return true
	}
	if s.probeHolder != nil {
		return s.probeHolder(ctx, host, "").reachable
	}
	return s.gate != nil && s.gate.PeerSupportsFresh(ctx, host, capabilities.VIPReleaseProbeV1)
}

// standDownHolder synchronously removes the LB from `host` so its keepalived is stopped
// and its config removed — an inert keepalived cannot later become VRRP master and
// re-claim the VIP, which VIP-address absence alone does NOT guarantee. Returns an error
// (→ refuse) if the removal can't be driven/confirmed. Self is torn down locally; peers
// via a blocking RemoveLB RPC (peer-only handler).
func (s *Server) standDownHolder(ctx context.Context, lbName, host string) error {
	if host == s.hostName {
		return s.removeLBLocal(ctx, lbName)
	}
	if s.removeLBFromHost != nil {
		return s.removeLBFromHost(ctx, lbName, host) // test seam
	}
	c, closeConn, err := s.dialPeer(ctx, host)
	if err == nil {
		_, err = c.RemoveLB(ctx, &pb.RemoveLBRequest{LbName: lbName})
		closeConn()
		if err == nil {
			return nil
		}
	}
	// Couldn't reach/stop the holder. gRPC dials LAZILY, so an unreachable peer errors on the
	// RemoveLB call, not at dialPeer — hence this handles both. If an operator has attested
	// (manual-fence-confirm) the host is DOWN, its keepalived is already gone: it is stood
	// down by fact, and no RemoveLB is possible or needed. This mirrors the release proof
	// removedHolderReleased/peerVIPClaims accept, so both steps of the move gate honor the
	// same attestation. Otherwise fail closed (the RPC failure refuses the move).
	if s.manualFenceConfirmedVIP(ctx, host) {
		return nil
	}
	return err
}

// actualLBParticipants resolves the hosts that are CONFIGURED PARTICIPANTS for the LB by
// asking every cluster host (ground truth: keepalived config/process present, not just a
// kernel VIP — so VRRP backups are included). ok=false — fail closed — if the host list
// can't be enumerated. peerLBPresent fail-closes to present=true on any error, so an
// unreachable host reads as a participant (and, if being removed, will refuse the move).
func (s *Server) actualLBParticipants(ctx context.Context, lbName string) (participants []string, ok bool) {
	if s.lbParticipantsOverride != nil {
		return s.lbParticipantsOverride(ctx, lbName) // test seam
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, false
	}
	for _, h := range hosts {
		if h.Name == s.hostName {
			if lb.NewManager().HasLB(lbName) {
				participants = append(participants, h.Name)
			}
			continue
		}
		if s.peerLBPresent(ctx, h.Name, lbName) {
			participants = append(participants, h.Name)
		}
	}
	return participants, true
}

// peerLBPresent asks a peer whether it is a configured participant for lbName. Fail-
// closed: any error (unreachable / old binary without CheckLBPresent / RPC failure) →
// assume PRESENT, so a removed participant that can't be checked refuses the move.
func (s *Server) peerLBPresent(ctx context.Context, host, lbName string) bool {
	c, closeConn, err := s.dialPeer(ctx, host)
	if err != nil {
		return true
	}
	defer closeConn()
	resp, err := c.CheckLBPresent(ctx, &pb.CheckLBPresentRequest{LbName: lbName})
	if err != nil {
		return true
	}
	return resp.GetPresent()
}

// removedHolderReleased reports whether a holder that was stood down has provably let go
// of the VIP — by the by-VIP CLAIM signal, not just the kernel address: it must no
// longer render a keepalived config for the VIP (so it can't become master again) AND
// not hold the address. After a confirmed RemoveLB (config removed + keepalived stopped)
// both are true; checking claim rather than address alone catches a stand-down that
// somehow left the config. Fail-closed in every uncertain case: a self check that
// errors, an unreachable peer, or a peer that still claims (or won't confirm) → NOT
// released.
func (s *Server) removedHolderReleased(ctx context.Context, host, vip string) bool {
	if host == s.hostName {
		// Local by-VIP check; a probe error is NOT release (fail closed).
		claims, err := lb.NewManager().ClaimsVIP(vip)
		return err == nil && !claims
	}
	if s.probeHolder != nil {
		st := s.probeHolder(ctx, host, vip)
		return st.reachable && !st.assigned // seam: .assigned models "still claims the VIP"
	}
	// peerVIPClaims fail-closes to claims=true on any error, so "not claiming" here means
	// the peer definitively answered released.
	return !s.peerVIPClaims(ctx, host, vip)
}

// peerVIPClaims asks a peer whether it could still hold or become master of the VIP
// (renders a config for it OR holds the address). Fail-closed: any error (unreachable /
// old binary / the peer's own check failed / not release-probe-capable) → assume it STILL
// claims, so the action is refused. A reachable peer's "not claiming" answer is trusted as a
// release-proof input ONLY if it advertises vip_release_probe_v1 — the SAME trust anchor the
// relay path applies to the probed target, so the direct and relayed paths are consistent.
func (s *Server) peerVIPClaims(ctx context.Context, host, vip string) bool {
	// Try a FRESH, authoritative DIRECT answer: the peer must advertise vip_release_probe_v1
	// (PeerSupportsFresh does a fresh Ping, which also proves reachability) AND answer
	// CheckVIPParticipant. gRPC dials LAZILY — an unreachable peer surfaces its error at the
	// Ping / CheckVIPParticipant call, NOT at dialPeer — so every step is checked and any
	// failure falls through to the release-proof resolution below (rather than trusting a
	// half-open connection or a non-probe-capable peer).
	if s.gate != nil && s.gate.PeerSupportsFresh(ctx, host, capabilities.VIPReleaseProbeV1) {
		if c, closeConn, err := s.dialPeer(ctx, host); err == nil {
			resp, cerr := c.CheckVIPParticipant(ctx, &pb.CheckVIPParticipantRequest{Vip: vip})
			closeConn()
			if cerr == nil {
				return resp.GetClaims()
			}
		}
	}
	// No fresh direct answer (unreachable / not probe-capable / RPC error). Accept a release
	// proof — a relayed NO_CLAIMS via a quorum-visible reachable peer (so a permanent
	// directional segmentation doesn't force a blanket fail-closed), or a recent operator
	// manual-fence-confirm (an attestation the host is DOWN, so its VIP is released; the
	// availability-first recovery, `lv host fence-confirm`). Else fail closed (assume it
	// STILL claims). An automatic 'fenced' state does NOT count (it's only a fence attempt).
	if s.relayedVIPNoClaims(ctx, host, vip) {
		return false
	}
	return !s.manualFenceConfirmedVIP(ctx, host)
}

// vipManualFenceWindow bounds how long an operator's manual-fence-confirm authorizes VIP
// reclaim of an UNREACHABLE holder — matches the failover coordinator's recent-fence window.
// After it expires the operator must re-confirm (the fail-closed direction). While the holder
// is reachable this is never consulted — its live probe answers directly.
const vipManualFenceWindow = 5 * time.Minute

// manualFenceConfirmedVIP reports whether an operator has recently confirmed (via
// `lv host fence-confirm <host>`) that host is DOWN — trusted as a proof-grade release proof
// for an UNREACHABLE VIP holder (the supported availability-first recovery path).
//
// It is honored ONLY while the host is NOT a currently-healthy quorum member. The attestation
// means "this host is down"; if the host is a live, reachable, quorum-counted member — because
// it never actually went down, or because it has REJOINED since the confirm — its live state
// governs, not a past attestation. Without this, a reachable-but-uncooperative peer (doesn't
// advertise the probe token / errors on the probe) or a host that rejoined within the window
// could have a stale confirm wrongly free its VIP. The audit window bounds staleness in time;
// this bounds it to the host actually being down. Fail-closed: no db/gate, read error, or a
// healthy host → not confirmed (the holder is assumed to still claim).
func (s *Server) manualFenceConfirmedVIP(ctx context.Context, host string) bool {
	if s.db == nil || s.gate == nil {
		return false
	}
	for _, h := range s.gate.HealthyPeers(ctx) {
		if h == host {
			return false // up + participating → live state governs, not a past confirm
		}
	}
	ok, err := corrosion.HostManualFenceConfirmed(ctx, s.db, host, time.Now(), vipManualFenceWindow)
	return err == nil && ok
}

// relayedVIPNoClaims reports whether a quorum-visible reachable RELAY peer definitively says
// `target` does NOT claim `vip`. This is the ONLY relayed outcome we accept as an absence
// proof; a relayed CLAIMS, UNKNOWN, an unreachable relay, or no eligible relay all return
// false (the caller then fails closed). Trust is anchored two ways: the relay must be a peer
// this node counts toward quorum (HealthyPeers), and reachability is proven by the dial
// succeeding. No caching, no durable proof — a fresh probe for THIS VIP check only.
func (s *Server) relayedVIPNoClaims(ctx context.Context, target, vip string) bool {
	if s.gate == nil {
		return false
	}
	for _, relay := range s.gate.HealthyPeers(ctx) {
		if relay == target || relay == s.hostName {
			continue // never relay to the target itself or to self
		}
		c, closeConn, err := s.dialPeer(ctx, relay)
		if err != nil {
			continue // relay not reachable right now → try the next
		}
		resp, rerr := c.RelayCheckVIPParticipant(ctx, &pb.RelayCheckVIPParticipantRequest{TargetHost: target, Vip: vip})
		closeConn()
		if rerr != nil {
			continue
		}
		switch resp.GetResult() {
		case pb.RelayVIPResult_RELAY_VIP_NO_CLAIMS:
			return true // definitive absence from a quorum-visible reachable relay
		case pb.RelayVIPResult_RELAY_VIP_CLAIMS:
			return false // definitive: target still claims → fail closed
		}
		// RELAY_VIP_UNKNOWN → this relay couldn't verify; try another.
	}
	return false
}

// removeLBLocal stops this host's haproxy/keepalived for an LB and clears its
// health gauge. Single chokepoint so teardown always drops the metric.
func (s *Server) removeLBLocal(ctx context.Context, name string) error {
	err := lb.NewManager().Remove(ctx, name)
	s.clearLBKeepalived(name)
	return err
}

func (s *Server) UpdateLoadBalancer(ctx context.Context, req *pb.UpdateLBRequest) (*pb.LoadBalancer, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	// Validate any newly-added backends before persisting — they render into
	// the root-run HAProxy/keepalived configs (same as CreateLoadBalancer).
	for _, b := range req.AddBackends {
		if b.Name != "" && !validResourceName(b.Name) {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid backend name %q: only letters, digits, '_', '.', '-' are allowed", b.Name)
		}
		if !validBackendAddress(b.Address) {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid backend address %q: must be an IP or IP:port", b.Address)
		}
	}

	// Look up existing config.
	rows, err := s.db.Query(ctx,
		`SELECT name, stack_name, vip, algorithm, hosts, ports, enabled, generation FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, req.Name)
	if err != nil || len(rows) == 0 {
		return nil, status.Errorf(codes.NotFound, "load balancer %q not found", req.Name)
	}
	r := rows[0]

	// Merge changes.
	oldVip := r.String("vip")
	vip := oldVip
	if req.Vip != "" {
		// Check VIP uniqueness. A DB error must not bypass the guard (F9).
		existingVIP, err := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE vip = ? AND name != ? AND enabled = 1 AND deleted_at IS NULL`, req.Vip, req.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "check VIP uniqueness: %v", err)
		}
		if len(existingVIP) > 0 {
			return nil, status.Errorf(codes.AlreadyExists, "VIP %s already in use by %q", req.Vip, existingVIP[0].String("name"))
		}
		vip = req.Vip
	}

	algorithm := r.String("algorithm")
	if req.Algorithm != "" {
		algorithm = req.Algorithm
	}

	oldHostsStr := r.String("hosts")
	hostsStr := oldHostsStr
	if len(req.Hosts) > 0 {
		h, _ := json.Marshal(req.Hosts)
		hostsStr = string(h)
	}

	portsStr := r.String("ports")
	if len(req.Ports) > 0 {
		p, _ := json.Marshal(req.Ports)
		portsStr = string(p)
	}

	// Split-brain gate (Phase 2): gate a host-set change OR a VIP change — the two edits
	// that can bring the VIP up on a new host/address. A pure backend/algorithm edit
	// (req.Hosts empty AND vip unchanged) is NOT gated: it re-renders on the same holders
	// (no takeover), and gating it would, for a stored hosts=[] LB, resolve the live
	// participants and compare them against an empty new set and tear the LB down — which
	// is why vipMoveRefused takes hostsChanged and, when false, treats the target set as
	// the current participants. vipMoveRefused proves the new VIP free (if it changed),
	// verifies removed holders released the OLD VIP, and stands them down break-before-make.
	// oldKnown unless the stored JSON is corrupt. Inert until the flip.
	hostsChanged := len(req.Hosts) > 0
	if hostsChanged || vip != oldVip {
		oldH, oldKnown := parseHostsJSON(oldHostsStr)
		newH, _ := parseHostsJSON(hostsStr)
		if reason, refused := s.vipMoveRefused(ctx, req.Name, oldVip, vip, oldH, newH, oldKnown, hostsChanged); refused {
			s.noteGateRefused(corrosion.ActionLBApply, reason)
			return nil, status.Errorf(codes.FailedPrecondition, "lb update refused: VIP takeover — %s", reason)
		}
	}

	existingBackends, err := corrosion.ListLBBackends(ctx, s.db, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list LB backends: %v", err)
	}
	removedNames := map[string]struct{}{}
	for _, name := range req.RemoveBackends {
		removedNames[name] = struct{}{}
	}
	for _, vmName := range req.RemoveVmBackends {
		removedNames[vmName] = struct{}{}
	}
	backendNames := map[string]struct{}{}
	for _, b := range existingBackends {
		if _, removing := removedNames[b.Name]; !removing {
			backendNames[b.Name] = struct{}{}
		}
	}
	for _, b := range req.AddBackends {
		if err := reserveLBBackendName(backendNames, lbBackendName(b)); err != nil {
			return nil, err
		}
	}
	for _, vmName := range req.AddVmBackends {
		if err := reserveLBBackendName(backendNames, vmName); err != nil {
			return nil, err
		}
	}

	// Collect backend changes; persisted atomically with the config below (one
	// batch) so an edit can't leave a partial model. The PRESERVED generation
	// keeps the already-stored backends matching the config and rendering.
	generation := r.String("generation")
	var tombstones []string
	tombstones = append(tombstones, req.RemoveBackends...)
	tombstones = append(tombstones, req.RemoveVmBackends...)
	var upserts []corrosion.LBBackendRecord
	for _, b := range req.AddBackends {
		name := b.Name
		if name == "" {
			name = b.Address
		}
		upserts = append(upserts, corrosion.LBBackendRecord{
			LBName: req.Name, Name: name, Address: b.Address, Enabled: true,
		})
	}
	for _, vmName := range req.AddVmBackends {
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vmName)
		for _, iface := range ifaces {
			if iface.IP != "" {
				upserts = append(upserts, corrosion.LBBackendRecord{
					LBName: req.Name, Name: vmName, Address: iface.IP, IsVM: true, VMName: vmName, Enabled: true,
				})
				break
			}
		}
	}

	// Persist updated config + backend changes atomically (generation preserved).
	if err := corrosion.PersistLBIncremental(ctx, s.db, corrosion.LBConfigRecord{
		Name:       req.Name,
		StackName:  r.String("stack_name"),
		VIP:        vip,
		Algorithm:  algorithm,
		Hosts:      hostsStr,
		Ports:      portsStr,
		Enabled:    r.Int("enabled") == 1,
		Generation: generation,
	}, upserts, tombstones); err != nil {
		return nil, status.Errorf(codes.Internal, "persist LB config: %v", err)
	}

	// Re-apply HAProxy on all LB hosts (graceful reload).
	allBackends, _ := corrosion.ListLBBackends(ctx, s.db, req.Name)
	var lbBackends []lb.Backend
	var ports []lb.Port
	backendPort := 80

	var parsedPorts []*pb.LBPort
	json.Unmarshal([]byte(portsStr), &parsedPorts)
	for _, p := range parsedPorts {
		ports = append(ports, lb.Port{Listen: int(p.Listen), Target: int(p.Target), Protocol: p.Protocol})
	}
	if len(ports) > 0 {
		backendPort = ports[0].Target
	}
	for _, b := range allBackends {
		if b.Enabled {
			lbBackends = append(lbBackends, lb.Backend{Name: b.Name, IP: b.Address, Port: backendPort})
		}
	}

	// Also gather stack-based backends if this is a stack LB.
	if stackName := r.String("stack_name"); stackName != "" && len(lbBackends) == 0 {
		stackName2 := strings.TrimSuffix(req.Name, "-lb")
		vms, _ := corrosion.ListVMs(ctx, s.db, stackName2, "")
		for _, vm := range vms {
			if vm.State != "running" {
				continue
			}
			ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
			for _, iface := range ifaces {
				if iface.IP != "" {
					lbBackends = append(lbBackends, lb.Backend{Name: vm.Name, IP: iface.IP, Port: backendPort})
					break
				}
			}
		}
	}

	vipIP, vipPrefix, _ := lb.ParseVIP(vip)
	var lbHosts []string
	json.Unmarshal([]byte(hostsStr), &lbHosts)

	// Apply locally.
	for _, h := range lbHosts {
		if h == s.hostName {
			priority := 50
			if len(lbHosts) == 0 || lbHosts[0] == s.hostName {
				priority = 100
			}
			cfg := lb.Config{
				Name: req.Name, VIP: vipIP, VIPPrefix: vipPrefix,
				Interface: lb.DetectInterfaceForIP(vipIP), VRID: s.allocVRID(ctx, req.Name),
				Priority: priority, Backends: lbBackends, Ports: ports, Algorithm: algorithm,
			}
			if err := s.applyLBLocal(ctx, cfg); err != nil {
				slog.Warn("UpdateLoadBalancer: local apply failed", "error", err)
			}
			break
		}
	}

	// Forward to remote hosts.
	var pbBackends []*pb.LBBackend
	for _, b := range lbBackends {
		pbBackends = append(pbBackends, &pb.LBBackend{VmName: b.Name, Address: b.IP, Status: "active"})
	}
	for _, h := range lbHosts {
		if h == s.hostName {
			continue
		}
		go func(host string) {
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			proof := s.mintLBProof(ctx, req.Name, host)
			if s.gateActive(ctx) && proof == nil {
				slog.Error("UpdateLoadBalancer: cannot mint LB proof under enforcement; skipping remote apply",
					"host", host, "lb", req.Name)
				return
			}
			if _, aerr := client.ApplyLB(ctx, &pb.ApplyLBRequest{
				LbName: req.Name, Vip: vip, Algorithm: algorithm,
				Backends: pbBackends, Ports: parsedPorts, Hosts: lbHosts, Proof: proof,
			}); aerr != nil {
				slog.Warn("UpdateLoadBalancer: remote apply failed", "host", host, "lb", req.Name, "error", aerr)
			}
		}(h)
	}

	// Remove LB from hosts that were in the old list but not the new one. When the
	// gate ran (active AND an explicit host change) it already stood the removed holders
	// down (break-before-make); only the ungated path needs it here.
	if !s.vipGateActive(ctx) {
		var oldHosts []string
		if oldHostsStr != "" && oldHostsStr != "[]" {
			json.Unmarshal([]byte(oldHostsStr), &oldHosts)
		}
		s.removeLBFromStaleHosts(ctx, req.Name, oldHosts, lbHosts)
	}

	s.publish("lb.updated", req.Name, fmt.Sprintf("vip=%s", vip))
	s.audit(ctx, "lb.update", req.Name, "", "ok")
	return s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: req.Name})
}

func (s *Server) DeleteLoadBalancer(ctx context.Context, req *pb.DeleteLBRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	// Look up LB to find hosts. Read deleted_at too (unfiltered) so we can tell a
	// truly-absent LB from an already-tombstoned one: the latter is still NotFound
	// to the user, but we refresh its tombstone first so it wins LWW against a
	// stale-clock peer that may have resurrected it.
	rows, err := s.db.Query(ctx, `SELECT hosts, deleted_at FROM lb_configs WHERE name = ?`, req.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup load balancer %q: %v", req.Name, err)
	}
	if len(rows) == 0 {
		return nil, status.Errorf(codes.NotFound, "load balancer %q not found", req.Name)
	}
	if rows[0].String("deleted_at") != "" {
		_ = corrosion.SoftDeleteLBConfig(ctx, s.db, req.Name) // refresh the tombstone
		return nil, status.Errorf(codes.NotFound, "load balancer %q not found", req.Name)
	}

	var lbHosts []string
	if h := rows[0].String("hosts"); h != "" && h != "[]" {
		json.Unmarshal([]byte(h), &lbHosts)
	}

	// Stop locally.
	if err := s.removeLBLocal(ctx, req.Name); err != nil {
		slog.Warn("DeleteLoadBalancer: local remove failed", "error", err)
	}

	// Forward to remote hosts.
	targetHosts := lbHosts
	if len(targetHosts) == 0 {
		hosts, _ := corrosion.ListHosts(ctx, s.db)
		for _, h := range hosts {
			targetHosts = append(targetHosts, h.Name)
		}
	}
	for _, h := range targetHosts {
		if h == s.hostName {
			continue
		}
		go func(host string) {
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			client.RemoveLB(ctx, &pb.RemoveLBRequest{LbName: req.Name})
		}(h)
	}

	// Delete from DB.
	corrosion.SoftDeleteLBBackends(ctx, s.db, req.Name)
	corrosion.SoftDeleteLBConfig(ctx, s.db, req.Name)

	s.publish("lb.deleted", req.Name, "")
	s.audit(ctx, "lb.delete", req.Name, "", "ok")
	return &emptypb.Empty{}, nil
}

func (s *Server) LBStats(ctx context.Context, req *pb.LBStatsRequest) (*pb.LBStatsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	mgr := lb.NewManager()
	stats, err := mgr.GetStats(ctx, req.Name)
	if err != nil {
		// socat missing is a hard prerequisite error — don't try forwarding.
		if strings.Contains(err.Error(), "socat not found") {
			return nil, status.Error(codes.FailedPrecondition,
				"socat is required for HAProxy stats — install with: apt install socat")
		}
		// HAProxy not running locally — try forwarding to an LB host that has it.
		if resp := s.forwardLBStats(ctx, req); resp != nil {
			return resp, nil
		}
		return nil, status.Errorf(codes.Internal, "get stats: %v", err)
	}

	resp := &pb.LBStatsResponse{Name: req.Name}
	for _, e := range stats.Entries {
		switch e.Type {
		case 0: // frontend
			resp.Frontends = append(resp.Frontends, &pb.LBFrontendStats{
				CurrentSessions: e.CurrentSess,
				TotalSessions:   e.TotalSess,
				BytesIn:         e.BytesIn,
				BytesOut:        e.BytesOut,
				RequestRate:     e.Rate,
			})
		case 2: // server
			resp.Backends = append(resp.Backends, &pb.LBBackendStats{
				Name:            e.ServerName,
				Status:          e.Status,
				CurrentSessions: e.CurrentSess,
				TotalSessions:   e.TotalSess,
				BytesIn:         e.BytesIn,
				BytesOut:        e.BytesOut,
				RequestRate:     e.Rate,
				ErrorConn:       e.ErrConn,
				ErrorResp:       e.ErrResp,
				Response_2Xx:    int32(e.Resp2xx),
				Response_4Xx:    int32(e.Resp4xx),
				Response_5Xx:    int32(e.Resp5xx),
				AvgResponseMs:   e.AvgResponseMs,
				AvgQueueMs:      e.AvgQueueMs,
			})
		}
	}
	return resp, nil
}

// forwardLBStats tries to get stats from a peer LB host when HAProxy isn't running locally.
func (s *Server) forwardLBStats(ctx context.Context, req *pb.LBStatsRequest) *pb.LBStatsResponse {
	rows, _ := s.db.Query(ctx, `SELECT hosts, stack_name FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, req.Name)
	if len(rows) == 0 {
		return nil
	}
	var lbHosts []string
	if h := rows[0].String("hosts"); h != "" && h != "[]" {
		json.Unmarshal([]byte(h), &lbHosts)
	}
	if len(lbHosts) == 0 {
		// Resolve from stack VM hosts.
		if stackName := rows[0].String("stack_name"); stackName != "" {
			vms, _ := corrosion.ListVMs(ctx, s.db, stackName, "")
			seen := map[string]bool{}
			for _, vm := range vms {
				if vm.HostName != s.hostName && !seen[vm.HostName] {
					seen[vm.HostName] = true
					lbHosts = append(lbHosts, vm.HostName)
				}
			}
		}
	}
	for _, h := range lbHosts {
		if h == s.hostName {
			continue
		}
		client, conn, err := s.peerClient(ctx, h)
		if err != nil {
			continue
		}
		resp, err := client.LBStats(ctx, req)
		conn.Close()
		if err == nil {
			return resp
		}
	}
	return nil
}

func (s *Server) DrainBackend(ctx context.Context, req *pb.DrainBackendRequest) (*pb.DrainBackendResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.LbName == "" || req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "lb_name and backend required")
	}

	mgr := lb.NewManager()
	conns, err := mgr.DrainBackend(ctx, req.LbName, req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "drain backend: %v", err)
	}

	s.publish("lb.backend.draining", req.LbName, fmt.Sprintf("backend=%s", req.Backend))
	s.audit(ctx, "lb.backend.drain", req.LbName, req.Backend, "ok")
	return &pb.DrainBackendResponse{
		Status:            "draining",
		ActiveConnections: conns,
	}, nil
}

// applyLBFromSpec collects backend IPs and applies the LB config on all
// designated LB hosts (local + remote via peerClient forwarding).
func (s *Server) applyLBFromSpec(ctx context.Context, spec *pb.VMSpec) {
	lbSpec := spec.Loadbalancer
	if lbSpec == nil || !lbSpec.Enabled {
		return
	}

	var ports []lb.Port
	for _, p := range lbSpec.Ports {
		port := lb.Port{
			Listen:   int(p.Listen),
			Target:   int(p.Target),
			Protocol: p.Protocol,
		}
		if p.Tls != nil {
			port.TLS = &lb.TLSConfig{Cert: p.Tls.Cert, Key: p.Tls.Key}
		}
		ports = append(ports, port)
	}

	var health *lb.HealthConfig
	if lbSpec.Health != nil {
		health = &lb.HealthConfig{
			Type: lbSpec.Health.Type,
			Path: lbSpec.Health.Path,
		}
		if lbSpec.Health.Interval != "" {
			if d, err := time.ParseDuration(lbSpec.Health.Interval); err == nil {
				health.IntervalMS = int(d.Milliseconds())
			}
		}
	}

	lbName := spec.StackName + "-lb"
	backends := s.collectLBBackends(ctx, spec.StackName, lbSpec)

	// Read old hosts before computing new ones so we can clean up stale hosts.
	// Read the existing generation too: preserve it when the LB already exists
	// (its explicit backends keep matching), and mint a fresh one only for a
	// brand-new stack LB. A pre-v31 LB reads generation='' and keeps it, so its
	// '' backends still match — don't re-stamp and orphan them.
	var oldHosts []string
	generation := ""
	oldVip := ""
	haveConfig := false
	oldReadOK := true // fail-closed: a DB read error means old membership is UNKNOWN
	if rows, err := s.db.Query(ctx, `SELECT hosts, generation, vip FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, lbName); err != nil {
		oldReadOK = false
	} else if len(rows) > 0 {
		haveConfig = true
		generation = rows[0].String("generation")
		oldVip = rows[0].String("vip")
		if h := rows[0].String("hosts"); h != "" && h != "[]" {
			if jerr := json.Unmarshal([]byte(h), &oldHosts); jerr != nil {
				oldReadOK = false // stored hosts unparseable → old membership UNKNOWN
			}
		}
	}
	if !haveConfig {
		generation = newID()
	}

	// Determine which hosts should run the LB.
	targetHosts := lbSpec.Hosts
	if len(targetHosts) == 0 {
		// Default: hosts that are running VMs in this stack.
		vms, err := corrosion.ListVMs(ctx, s.db, spec.StackName, "")
		if err == nil {
			seen := map[string]bool{}
			for _, vm := range vms {
				if !seen[vm.HostName] {
					seen[vm.HostName] = true
					targetHosts = append(targetHosts, vm.HostName)
				}
			}
		}
	}

	// Split-brain gate (Phase 2, orchestration site): before overwriting the row's hosts
	// and (re)applying, prove the mutation is safe. vipMoveRefused proves a CHANGED VIP is
	// free (oldVip→lbSpec.Vip — a stack LB can change its VIP too, which manual updates
	// already gate), stands down every REMOVED holder (old∖new) break-before-make and
	// verifies it released the OLD VIP it served, and refuses a fresh claim whose VIP a
	// leftover still participates in. Unchanged/added holders are NOT gated (normal VRRP).
	// targetHosts is the authoritative recomputed set, so hostsChanged is true here.
	//
	// Only run when there IS a claim to make (targetHosts non-empty). An empty target (no
	// running VMs / no explicit hosts) makes no new claim, so there's no takeover to gate —
	// and gating it against a resolved participant set would tear the LB down. The
	// stale-removal below handles that teardown instead. Inert until the flip.
	if len(targetHosts) > 0 {
		if reason, refused := s.vipMoveRefused(ctx, lbName, oldVip, lbSpec.Vip, oldHosts, targetHosts, oldReadOK, true); refused {
			s.noteGateRefused(corrosion.ActionLBApply, reason)
			slog.Warn("applyLBFromSpec: VIP takeover refused — a removed holder hasn't released",
				"stack", spec.StackName, "lb", lbName, "reason", reason)
			return
		}
	}

	// Persist LB config to DB so it's visible cluster-wide via replication.
	// This must happen here (not in applyLBForStack) because this host may
	// not be an LB host itself.
	algorithm := lbSpec.Algorithm
	if algorithm == "" {
		algorithm = "roundrobin"
	}
	hostsJSON, _ := json.Marshal(targetHosts)
	portsJSON, _ := json.Marshal(lbSpec.Ports)
	corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name:       lbName,
		StackName:  spec.StackName,
		VIP:        lbSpec.Vip,
		Algorithm:  algorithm,
		Hosts:      string(hostsJSON),
		Ports:      string(portsJSON),
		Enabled:    true,
		Generation: generation,
	})

	// Apply locally if this host is a target.
	for _, h := range targetHosts {
		if h == s.hostName {
			if err := s.applyLBForStack(ctx, lbName, lbSpec.Vip, lbSpec.Algorithm, ports, backends, targetHosts, health, lbSpec.Snat); err != nil {
				slog.Warn("applyLBFromSpec: local apply failed", "stack", spec.StackName, "error", err)
			} else {
				slog.Info("applyLBFromSpec: LB applied locally", "stack", spec.StackName, "backends", len(backends))
			}
			break
		}
	}

	// Forward to remote LB hosts. Use a detached context so the goroutines
	// survive after the triggering RPC completes.
	for _, h := range targetHosts {
		if h == s.hostName {
			continue
		}
		go s.forwardLBApply(context.Background(), h, spec, targetHosts)
	}

	// Remove LB from hosts that are no longer in the target list. This handles the
	// case where VMs migrate and the auto-resolved host list changes (e.g. LB was on
	// hostA, VMs moved to hostB). When the gate ran (active AND there was a claim to
	// make) it already stood the removed holders down (break-before-make); otherwise —
	// ungated, OR a gated teardown with no target hosts — do it here.
	if !s.vipGateActive(ctx) || len(targetHosts) == 0 {
		s.removeLBFromStaleHosts(ctx, lbName, oldHosts, targetHosts)
	}
}

// removeLBFromStaleHosts stops haproxy+keepalived on hosts that were
// previously running the LB but are no longer in the target list.
func (s *Server) removeLBFromStaleHosts(ctx context.Context, lbName string, oldHosts, newHosts []string) {
	newSet := make(map[string]bool, len(newHosts))
	for _, h := range newHosts {
		newSet[h] = true
	}
	for _, h := range oldHosts {
		if newSet[h] {
			continue
		}
		if h == s.hostName {
			// Remove locally.
			if err := s.removeLBLocal(ctx, lbName); err != nil {
				slog.Warn("removeLBFromStaleHosts: local remove failed", "lb", lbName, "error", err)
			} else {
				slog.Info("removeLBFromStaleHosts: removed locally", "lb", lbName)
			}
			continue
		}
		// Remove on remote host.
		go func(host string) {
			rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			client, conn, err := s.peerClient(rctx, host)
			if err != nil {
				slog.Warn("removeLBFromStaleHosts: cannot reach host", "host", host, "lb", lbName, "error", err)
				return
			}
			defer conn.Close()
			if _, err := client.RemoveLB(rctx, &pb.RemoveLBRequest{LbName: lbName}); err != nil {
				slog.Warn("removeLBFromStaleHosts: remote remove failed", "host", host, "lb", lbName, "error", err)
			} else {
				slog.Info("removeLBFromStaleHosts: removed on remote host", "host", host, "lb", lbName)
			}
		}(h)
	}
}

// forwardLBApply sends an ApplyLB request to a remote host.
// mintLBProof mints + persists a single-use lb_apply proof bound to destHost when
// the split-brain gate is active, for forwarding with an ApplyLB call so the
// receiving LB host can validate + claim it (it refuses a proofless peer call once
// enforced). Returns nil pre-activation (fail-open).
func (s *Server) mintLBProof(ctx context.Context, lbName, destHost string) *pb.RuntimeActionProof {
	if !s.gateActive(ctx) {
		return nil
	}
	// Fresh-Ping the destination LB host: never stamp/forward a proof to a target
	// that no longer advertises the gate (a regressed/replaced host that couldn't
	// honor it). Returning nil under enforcement makes every caller's
	// "gateActive && proof == nil → skip forward" guard refuse the apply — the VIP
	// is not brought up on a host that can't participate in the gate (fail closed).
	if !s.destSupportsGate(ctx, destHost) {
		slog.Error("mintLBProof: destination does not advertise the split-brain gate; refusing proof-bearing LB apply",
			"lb", lbName, "dest", destHost)
		s.noteGateRefused(corrosion.ActionLBApply, health.ReasonUnsupportedCapability)
		return nil
	}
	p := corrosion.ActionProof{
		ID: newID(), Action: corrosion.ActionLBApply, TargetKind: "lb",
		TargetName: lbName, DestHost: destHost, Coordinator: s.hostName,
	}
	if err := corrosion.WriteActionProof(ctx, s.db, p); err != nil {
		slog.Warn("mintLBProof: write proof failed", "lb", lbName, "dest", destHost, "error", err)
		return nil
	}
	return &pb.RuntimeActionProof{
		Id: p.ID, Action: p.Action, TargetKind: p.TargetKind, TargetName: p.TargetName,
		DestHost: p.DestHost, Coordinator: p.Coordinator,
	}
}

// forwardLBApply asks a remote host to apply the LB. resolvedHosts is the RESOLVED
// target host set (implicit stack LBs derive it from VM placement) — it MUST be passed
// so the remote computes the same VRRP priority the local apply did; sending the raw
// (possibly empty) lbSpec.Hosts would make ApplyLB hand the remote priority 100
// (len==0), producing two masters.
func (s *Server) forwardLBApply(ctx context.Context, hostName string, spec *pb.VMSpec, resolvedHosts []string) {
	lbSpec := spec.Loadbalancer
	if lbSpec == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client, conn, err := s.peerClient(ctx, hostName)
	if err != nil {
		slog.Warn("forwardLBApply: cannot reach host", "host", hostName, "error", err)
		return
	}
	defer conn.Close()

	backends := s.collectLBBackends(ctx, spec.StackName, lbSpec)
	var pbBackends []*pb.LBBackend
	for _, b := range backends {
		pbBackends = append(pbBackends, &pb.LBBackend{
			VmName:  b.Name,
			Address: b.IP,
			Status:  "active",
		})
	}

	var pbPorts []*pb.LBPort
	for _, p := range lbSpec.Ports {
		pbPorts = append(pbPorts, &pb.LBPort{
			Listen:   p.Listen,
			Target:   p.Target,
			Protocol: p.Protocol,
		})
	}

	lbName := spec.StackName + "-lb"
	proof := s.mintLBProof(ctx, lbName, hostName)
	if s.gateActive(ctx) && proof == nil {
		// Enforced but couldn't mint a proof for this dest (unreachable / doesn't
		// advertise the gate) — refuse to forward an ungated apply (fail closed).
		slog.Error("forwardLBApply: cannot mint LB proof under enforcement; skipping remote apply",
			"host", hostName, "lb", lbName)
		return
	}
	if _, err := client.ApplyLB(ctx, &pb.ApplyLBRequest{
		LbName:    lbName,
		Vip:       lbSpec.Vip,
		Algorithm: lbSpec.Algorithm,
		Backends:  pbBackends,
		Ports:     pbPorts,
		Hosts:     resolvedHosts,
		Proof:     proof,
	}); err != nil {
		slog.Warn("forwardLBApply: remote apply failed", "host", hostName, "error", err)
	} else {
		slog.Info("forwardLBApply: LB applied on remote host", "host", hostName, "stack", spec.StackName)
	}
}

// ApplyLB handles a request from a peer to configure HAProxy + keepalived locally.
func (s *Server) ApplyLB(ctx context.Context, req *pb.ApplyLBRequest) (*emptypb.Empty, error) {
	// Peer-only: ApplyLB is the host→host forwarded-apply RPC (the operator path is
	// Create/UpdateLoadBalancer, which fan out to peers and handle the local host via
	// applyLBLocal). Refuse non-peer callers so an authenticated bearer — even a viewer —
	// can't drive an arbitrary VIP bring-up. Sibling RemoveLB is likewise peer-only.
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "ApplyLB is a peer-only RPC")
	}
	if req.LbName == "" {
		return nil, status.Error(codes.InvalidArgument, "lb_name required")
	}

	// Split-brain gate: the local-quorum ExecutionGate is enforced at the applyLBLocal
	// chokepoint below. Additionally, a forwarded apply must carry a coordinator proof once
	// enforced — otherwise any peer could ask a quorum-holding LB host to claim a VIP
	// unauthorized. No proof under enforcement is refused; a present proof is validated +
	// single-use-claimed below.
	if req.Proof == nil && s.gateActive(ctx) {
		s.noteGateRefused(corrosion.ActionLBApply, health.ReasonProofMissing)
		return nil, status.Error(codes.FailedPrecondition, "lb apply refused: forwarded apply requires a proof under enforcement")
	}
	lbProofID, err := s.claimCarriedProof(ctx, req.Proof, corrosion.ActionLBApply, "lb", req.LbName)
	if err != nil {
		s.noteGateRefused(corrosion.ActionLBApply, health.ReasonProofConflict)
		return nil, err
	}
	// A carried proof MARKER forces the local ExecutionGate even if THIS host hasn't
	// latched enforcement — a partitioned target must not bring up a VIP without
	// local quorum. (applyLBLocal below also gates, but only under local enforcement,
	// so it would miss a proof-carrying apply on a not-yet-enforcing regressed host.)
	if reason, refused := s.execGateForAction(ctx, req.Proof != nil); refused {
		s.noteGateRefused(corrosion.ActionLBApply, reason)
		return nil, status.Errorf(codes.FailedPrecondition, "lb apply refused: %s", reason)
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "roundrobin"
	}

	vipIP, vipPrefix, err := lb.ParseVIP(req.Vip)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid VIP: %v", err)
	}

	// Determine VRRP priority from the hosts list.
	priority := 50
	if len(req.Hosts) == 0 || req.Hosts[0] == s.hostName {
		priority = 100
	}

	lbIface := lb.DetectInterfaceForIP(vipIP)

	var ports []lb.Port
	for _, p := range req.Ports {
		ports = append(ports, lb.Port{
			Listen:   int(p.Listen),
			Target:   int(p.Target),
			Protocol: p.Protocol,
		})
	}

	// Derive backend port from the first port mapping's target.
	backendPort := 80
	if len(ports) > 0 {
		backendPort = ports[0].Target
	}

	var backends []lb.Backend
	for _, b := range req.Backends {
		backends = append(backends, lb.Backend{
			Name: b.VmName,
			IP:   b.Address,
			Port: backendPort,
		})
	}

	cfg := lb.Config{
		Name:      req.LbName,
		VIP:       vipIP,
		VIPPrefix: vipPrefix,
		Interface: lbIface,
		VRID:      s.allocVRID(ctx, req.LbName),
		Priority:  priority,
		Backends:  backends,
		Ports:     ports,
		Algorithm: algorithm,
	}

	if err := s.applyLBLocal(ctx, cfg); err != nil {
		return nil, status.Errorf(codes.Internal, "apply LB: %v", err)
	}

	// Update host-isolation rules if the LB interface is on an isolated bridge.
	// Internal ApplyLB RPC doesn't carry snat flag; default to true (previous behaviour).
	s.updateIsolationForLB(ctx, lbIface, vipIP, ports, true)

	if lbProofID != "" {
		if err := corrosion.CompleteActionProof(ctx, s.db, lbProofID, s.hostName); err != nil {
			slog.Warn("ApplyLB: complete proof", "lb", req.LbName, "proof", lbProofID, "error", err)
		}
	}
	slog.Info("ApplyLB: applied", "lb", req.LbName, "vip", req.Vip, "backends", len(backends))
	return &emptypb.Empty{}, nil
}

// RemoveLB handles a request from a peer to tear down a local LB instance.
func (s *Server) RemoveLB(ctx context.Context, req *pb.RemoveLBRequest) (*emptypb.Empty, error) {
	// Peer-only: RemoveLB stops keepalived + haproxy and tears down the VIP, and Phase 2
	// relies on it to stand a removed holder down before a new host claims the VIP. It is
	// only ever invoked host→host (the operator path is DeleteLoadBalancer, which fans
	// this out to peers and handles the local host directly). Refuse non-peer callers so
	// it can't be driven by a stale/unauthorized client.
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, status.Error(codes.PermissionDenied, "RemoveLB is a peer-only RPC")
	}
	if req.LbName == "" {
		return nil, status.Error(codes.InvalidArgument, "lb_name required")
	}

	// Before removing, check if the LB was on an isolated bridge so we
	// can restore base isolation (no LB exceptions) after teardown.
	rows, _ := s.db.Query(ctx,
		`SELECT vip FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, req.LbName)
	var lbVIP string
	if len(rows) > 0 {
		lbVIP = rows[0].String("vip")
	}

	if err := s.removeLBLocal(ctx, req.LbName); err != nil {
		return nil, status.Errorf(codes.Internal, "remove LB: %v", err)
	}

	// Restore base isolation (drop all, no LB exceptions) + remove SNAT.
	if lbVIP != "" {
		vipIP, _, _ := lb.ParseVIP(lbVIP)
		lbIface := lb.DetectInterfaceForIP(vipIP)
		netDef, _ := s.findIsolatedNetworkForBridge(ctx, lbIface)
		if netDef != nil {
			network.EnsureHostIsolation(lbIface, nil) //nolint:errcheck
			network.RemoveSNAT(lbIface)               //nolint:errcheck
		}
	}

	slog.Info("RemoveLB: removed", "lb", req.LbName)
	return &emptypb.Empty{}, nil
}

// applyLBFromSpecWithRetry is called in a goroutine after CreateVM.
// VMs may not have IPs immediately after boot (DHCP), so it retries
// until backends have IPs, then delegates to applyLBFromSpec.
func (s *Server) applyLBFromSpecWithRetry(ctx context.Context, spec *pb.VMSpec) {
	lbSpec := spec.Loadbalancer
	if lbSpec == nil || !lbSpec.Enabled {
		return
	}

	// Retry up to 6 times with increasing delays: 5s, 10s, 15s, 20s, 25s, 30s.
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt*5) * time.Second
			slog.Info("applyLBFromSpec: waiting for VM IPs", "stack", spec.StackName, "attempt", attempt+1, "delay", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}

		backends := s.collectLBBackends(ctx, spec.StackName, lbSpec)
		if len(backends) == 0 {
			slog.Info("applyLBFromSpec: no backends with IPs yet", "stack", spec.StackName, "attempt", attempt+1)
			continue
		}

		// Delegate to applyLBFromSpec which handles host resolution,
		// DB persistence, local apply, and remote forwarding.
		s.applyLBFromSpec(ctx, spec)
		return
	}

	slog.Warn("applyLBFromSpec: gave up waiting for backend IPs", "stack", spec.StackName)
}

// collectLBBackends gathers IPs for all running VMs in a stack, using ARP/DHCP
// fallback for IPs not yet stored in corrosion.
// collectLBBackends builds the HAProxy server list for the render/apply path:
// running backends with a resolved IP, at the LB's target port. Uses full
// discovery (peer lookups + IP persistence) so a freshly-migrated VM resolves.
func (s *Server) collectLBBackends(ctx context.Context, stackName string, lbSpec *pb.LBSpec) []lb.Backend {
	targetPort := 80
	if len(lbSpec.Ports) > 0 {
		targetPort = int(lbSpec.Ports[0].Target)
	}
	var backends []lb.Backend
	for _, rb := range s.resolveStackBackends(ctx, stackName, true, true) {
		if !rb.Running || rb.IP == "" {
			continue
		}
		backends = append(backends, lb.Backend{Name: rb.Name, IP: rb.IP, Port: targetPort})
	}
	return backends
}

// RefreshLBForStack is the exported wrapper for refreshLBForStack.
// Used by the reconciler callback after failover VM startup.
func (s *Server) RefreshLBForStack(ctx context.Context, stackName string) {
	s.refreshLBForStack(ctx, stackName)
}

// refreshLBForStack re-syncs the LB backend list locally and forwards the
// refresh to all LB hosts so traffic converges across the cluster.
func (s *Server) refreshLBForStack(ctx context.Context, stackName string) {
	spec := s.refreshLBLocal(ctx, stackName)
	if spec == nil {
		return
	}

	// Determine which hosts run the LB.
	lbHosts := spec.Loadbalancer.Hosts
	if len(lbHosts) == 0 {
		hosts, _ := corrosion.ListHosts(ctx, s.db)
		for _, h := range hosts {
			lbHosts = append(lbHosts, h.Name)
		}
	}
	for _, h := range lbHosts {
		if h == s.hostName {
			continue
		}
		go func(host string) {
			client, conn, err := s.peerClient(ctx, host)
			if err != nil {
				return
			}
			defer conn.Close()
			client.RefreshLB(ctx, &pb.RefreshLBRequest{StackName: stackName})
		}(h)
	}
}

// refreshLBLocal applies LB refresh on this host only. Returns the LB spec if found.
// If the LB config record has been deleted (e.g. stack is being torn down), this is a no-op.
func (s *Server) refreshLBLocal(ctx context.Context, stackName string) *pb.VMSpec {
	if stackName == "" {
		return nil
	}

	// Guard: don't re-apply if the LB config has been removed or is being removed.
	lbName := stackName + "-lb"
	rows, _ := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, lbName)
	if len(rows) == 0 {
		return nil
	}

	vms, err := corrosion.ListVMs(ctx, s.db, stackName, "")
	if err != nil || len(vms) == 0 {
		return nil
	}
	for _, vm := range vms {
		if vm.Spec == "" {
			continue
		}
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			continue
		}
		if spec.Loadbalancer != nil && spec.Loadbalancer.Enabled {
			s.applyLBFromSpec(ctx, spec)
			return spec
		}
	}
	return nil
}

// RefreshLB handles the RefreshLB RPC from peers — refreshes locally only (no re-forwarding).
func (s *Server) RefreshLB(ctx context.Context, req *pb.RefreshLBRequest) (*emptypb.Empty, error) {
	s.refreshLBLocal(ctx, req.StackName)
	return &emptypb.Empty{}, nil
}

// ReconcileLBs re-applies all LB configs that should run on this host.
// Called on daemon startup to restart haproxy + keepalived after a daemon restart.
func (s *Server) ReconcileLBs(ctx context.Context) {
	configs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		slog.Warn("reconcileLBs: list configs", "error", err)
		return
	}
	for _, cfg := range configs {
		if !cfg.Enabled || !s.lbRunsOnHost(ctx, cfg) {
			continue
		}
		if cfg.StackName != "" {
			// Stack LB: refreshLBLocal reads the full spec and re-applies.
			s.refreshLBLocal(ctx, cfg.StackName)
			slog.Info("LB reconciled", "lb", cfg.Name, "stack", cfg.StackName)
			continue
		}
		// Explicit (non-stack) LB: reconstruct from the stored row + backends and
		// re-apply. Previously skipped entirely — harmless when nothing ever stopped
		// keepalived spontaneously, but Phase-2 DemoteAll now does, so an explicit LB
		// must be re-appliable to recover on quorum heal (and at startup).
		s.reapplyExplicitLB(ctx, cfg)
	}
}

// RunLBReconciler periodically re-applies this host's enabled LBs whose keepalived is NOT
// running. The one-shot boot ReconcileLBs is refused while the split-brain ExecutionGate is
// in warmup (a fresh restart) or the host is 'upgrading', and nothing else re-applies
// keepalived/haproxy (KillMode=process means a restart emits no VM events) — so a sole VIP
// holder would stay down and VRRP redundancy would silently vanish. This loop retries until
// local quorum lets the gated apply through, and only touches DEAD LBs so a healthy holder is
// never churned. It also recovers a Phase-2 self-demoted VIP once quorum heals.
func (s *Server) RunLBReconciler(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reconcileDeadLBs(ctx)
		}
	}
}

// reconcileDeadLBs re-applies this host's enabled LBs whose keepalived isn't running. The
// re-apply path (refreshLBLocal / reapplyExplicitLB -> applyLBLocal) is split-brain-gated, so
// it no-ops during warmup/upgrading and succeeds once local quorum returns.
func (s *Server) reconcileDeadLBs(ctx context.Context) {
	configs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		return
	}
	for _, cfg := range configs {
		if !cfg.Enabled || !s.lbRunsOnHost(ctx, cfg) || s.lbKeepalivedRunning(cfg.Name) {
			continue
		}
		if cfg.StackName != "" {
			s.refreshLBLocal(ctx, cfg.StackName)
		} else {
			s.reapplyExplicitLB(ctx, cfg)
		}
		slog.Info("LB reconciler: re-applied a stopped LB", "lb", cfg.Name)
	}
}

// reapplyExplicitLB rebuilds an explicit (non-stack) LB's lb.Config from its stored row +
// backends and re-applies it locally (idempotent; the Phase-1 exec gate still guards it).
func (s *Server) reapplyExplicitLB(ctx context.Context, cfg corrosion.LBConfigRecord) {
	vipIP, vipPrefix, err := lb.ParseVIP(cfg.VIP)
	if err != nil {
		slog.Warn("reapplyExplicitLB: parse vip", "lb", cfg.Name, "error", err)
		return
	}
	hosts, _ := parseHostsJSON(cfg.Hosts)
	priority := 50
	if len(hosts) == 0 || hosts[0] == s.hostName {
		priority = 100
	}
	var parsed []*pb.LBPort
	json.Unmarshal([]byte(cfg.Ports), &parsed)
	var ports []lb.Port
	backendPort := 80
	for _, p := range parsed {
		ports = append(ports, lb.Port{Listen: int(p.Listen), Target: int(p.Target), Protocol: p.Protocol})
	}
	if len(ports) > 0 {
		backendPort = ports[0].Target
	}
	var backends []lb.Backend
	if bs, berr := corrosion.ListLBBackends(ctx, s.db, cfg.Name); berr == nil {
		for _, b := range bs {
			if b.Enabled {
				backends = append(backends, lb.Backend{Name: b.Name, IP: b.Address, Port: backendPort})
			}
		}
	}
	if err := s.applyLBLocal(ctx, lb.Config{
		Name: cfg.Name, VIP: vipIP, VIPPrefix: vipPrefix,
		Interface: lb.DetectInterfaceForIP(vipIP), VRID: s.allocVRID(ctx, cfg.Name),
		Priority: priority, Backends: backends, Ports: ports, Algorithm: cfg.Algorithm,
	}); err != nil {
		slog.Warn("reapplyExplicitLB: apply failed", "lb", cfg.Name, "error", err)
	} else {
		slog.Info("LB reconciled", "lb", cfg.Name)
	}
}

// lbRunsOnHost reports whether this host should run the given LB — an explicit
// host in cfg.Hosts, or (when Hosts is empty) a host that has VMs in the LB's
// stack.
func (s *Server) lbRunsOnHost(ctx context.Context, cfg corrosion.LBConfigRecord) bool {
	var hosts []string
	if cfg.Hosts != "" && cfg.Hosts != "[]" {
		json.Unmarshal([]byte(cfg.Hosts), &hosts)
	}
	if len(hosts) == 0 {
		vms, _ := corrosion.ListVMs(ctx, s.db, cfg.StackName, s.hostName)
		return len(vms) > 0
	}
	for _, h := range hosts {
		if h == s.hostName {
			return true
		}
	}
	return false
}

// RunLBMetricsRefresher periodically republishes litevirt_lb_keepalived_up for
// the LBs this host runs, so the gauge tracks live keepalived state rather than
// only the last apply. Cheap — a pidfile check per local LB. Does an immediate
// refresh, then ticks.
func (s *Server) RunLBMetricsRefresher(ctx context.Context, interval time.Duration) {
	s.refreshLBMetrics(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshLBMetrics(ctx)
		}
	}
}

// refreshLBMetrics sets the keepalived-up gauge for every enabled LB this host
// runs (1/0 from the live check) and drops the series for LBs it no longer runs.
func (s *Server) refreshLBMetrics(ctx context.Context) {
	if s.lbMetrics == nil {
		return
	}
	configs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		return
	}
	for _, cfg := range configs {
		if cfg.Enabled && s.lbRunsOnHost(ctx, cfg) {
			s.recordLBKeepalived(cfg.Name)
		} else {
			s.clearLBKeepalived(cfg.Name)
		}
	}
}

// removeLBForStack removes all LB instances associated with a stack on all hosts.
// It checks VM specs for LB configuration and tears down haproxy + keepalived.
// stackHasLBConfig reports whether an lb_config row exists for the LB, including
// soft-deleted rows. DeleteStack soft-deletes the row before tearing the LB
// down, so a `deleted_at IS NULL` filter would miss it and the haproxy /
// keepalived processes would be orphaned.
func (s *Server) stackHasLBConfig(ctx context.Context, lbName string) bool {
	rows, _ := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE name = ?`, lbName)
	return len(rows) > 0
}

func (s *Server) removeLBForStack(ctx context.Context, stackName string, vms []corrosion.VMRecord) {
	if stackName == "" {
		return
	}

	lbName := stackName + "-lb"

	// Whether an LB record EVER existed for this stack — including soft-deleted
	// rows. The VM-spec fallback below is unreliable after a migration, which may
	// re-store the spec without the LB block, so the row is the authoritative
	// teardown signal.
	hasLB := s.stackHasLBConfig(ctx, lbName)

	// Determine which hosts ran the LB so we can remove from all of them.
	var lbHosts []string
	for _, vm := range vms {
		if vm.Spec == "" {
			continue
		}
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			continue
		}
		if spec.Loadbalancer != nil && spec.Loadbalancer.Enabled {
			hasLB = true
			lbHosts = spec.Loadbalancer.Hosts
			break
		}
	}
	if !hasLB {
		return
	}

	// Stop haproxy + keepalived locally.
	slog.Info("removeLBForStack: removing LB", "stack", stackName, "lb", lbName)
	if err := s.removeLBLocal(ctx, lbName); err != nil {
		slog.Warn("removeLBForStack: local remove failed", "lb", lbName, "error", err)
	} else {
		slog.Info("removeLBForStack: local processes stopped", "lb", lbName)
	}

	// Remove from remote LB hosts. Use a detached context with a generous
	// timeout so that parent-context cancellation (e.g. compose-down finishing)
	// does not abort the remote cleanup mid-flight.
	remoteCtx, remoteCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer remoteCancel()

	targetHosts := lbHosts
	if len(targetHosts) == 0 {
		hosts, err := corrosion.ListHosts(ctx, s.db)
		if err == nil {
			for _, h := range hosts {
				targetHosts = append(targetHosts, h.Name)
			}
		}
	}
	var wg sync.WaitGroup
	for _, h := range targetHosts {
		if h == s.hostName {
			continue
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			client, conn, err := s.peerClient(remoteCtx, host)
			if err != nil {
				slog.Warn("removeLBForStack: cannot reach host", "host", host, "error", err)
				return
			}
			defer conn.Close()
			if _, err := client.RemoveLB(remoteCtx, &pb.RemoveLBRequest{LbName: lbName}); err != nil {
				slog.Warn("removeLBForStack: remote remove failed", "host", host, "error", err)
			} else {
				slog.Info("removeLBForStack: removed on remote host", "host", host)
			}
		}(h)
	}
	wg.Wait()

	// Remove LB records from corrosion (replicated to all hosts via gossip).
	// Only delete after remote hosts have had a chance to clean up.
	corrosion.SoftDeleteLBBackends(ctx, s.db, lbName)
	if err := corrosion.SoftDeleteLBConfig(ctx, s.db, lbName); err != nil {
		slog.Warn("removeLBForStack: delete LB record failed", "lb", lbName, "error", err)
	}

	s.publish("lb.removed", lbName, fmt.Sprintf("stack=%s", stackName))
	slog.Info("LB removed for stack", "stack", stackName, "lb", lbName)
}

// applyLBForStack is called by DeployStack when a VM def has loadbalancer.enabled = true.
// It builds the HAProxy + keepalived config and applies it on the designated LB hosts.
func (s *Server) applyLBForStack(ctx context.Context, lbName, vip, algorithm string, ports []lb.Port, backends []lb.Backend, lbHosts []string, health *lb.HealthConfig, snat bool) error {
	// Only apply if this host is in the designated LB hosts list.
	// Callers must resolve empty hosts before calling this function.
	isLBHost := false
	for _, h := range lbHosts {
		if h == s.hostName {
			isLBHost = true
			break
		}
	}
	if !isLBHost {
		return nil
	}

	if algorithm == "" {
		algorithm = "roundrobin"
	}

	vipIP, vipPrefix, err := lb.ParseVIP(vip)
	if err != nil {
		return err
	}

	// Verify VIP is not already claimed by another load balancer (#40).
	// A DB error here must fail the operation (F9): swallowing it would treat a
	// failed lookup as "no conflict" and let a duplicate VIP through.
	existing, err := s.db.Query(ctx,
		`SELECT name FROM lb_configs WHERE vip = ? AND name != ? AND enabled = 1 AND deleted_at IS NULL`,
		vip, lbName)
	if err != nil {
		return fmt.Errorf("check VIP %s uniqueness: %w", vip, err)
	}
	if len(existing) > 0 {
		return fmt.Errorf("VIP %s is already in use by load balancer %q", vip, existing[0].String("name"))
	}

	// Determine VRRP priority: first host in list = master (priority 100), others = backup (50).
	priority := 50
	if len(lbHosts) > 0 && lbHosts[0] == s.hostName {
		priority = 100
	}

	// Determine the interface for VRRP. The VIP should be on the same L2
	// segment as the backends (the bridge). Find the interface whose subnet
	// contains the VIP; fall back to default route interface.
	lbIface := lb.DetectInterfaceForIP(vipIP)

	cfg := lb.Config{
		Name:      lbName,
		VIP:       vipIP,
		VIPPrefix: vipPrefix,
		Interface: lbIface,
		VRID:      s.allocVRID(ctx, lbName),
		Priority:  priority,
		Backends:  backends,
		Ports:     ports,
		Algorithm: algorithm,
		Health:    health,
	}

	if err := s.applyLBLocal(ctx, cfg); err != nil {
		return err
	}

	// Update host-isolation rules if the LB interface is on an isolated bridge.
	s.updateIsolationForLB(ctx, lbIface, vipIP, ports, snat)

	s.publish("lb.applied", lbName, fmt.Sprintf("vip=%s backends=%d", vip, len(backends)))
	return nil
}

// updateIsolationForLB checks if a bridge has host-isolation enabled and, if so,
// re-applies the isolation chain with LB port exceptions so VMs can reach the VIP.
// Also sets up SNAT rules if the network's LB has snat enabled.
func (s *Server) updateIsolationForLB(ctx context.Context, bridge, vip string, ports []lb.Port, snat bool) {
	// Find a network whose bridge matches this interface and has host-isolation.
	netDef, subnet := s.findIsolatedNetworkForBridge(ctx, bridge)
	if netDef == nil {
		return
	}

	// Build LB exceptions for the isolation chain.
	var listenPorts []int
	for _, p := range ports {
		listenPorts = append(listenPorts, p.Listen)
	}
	exc := []network.IsolationLBException{{VIP: vip, Ports: listenPorts}}
	if err := network.EnsureHostIsolation(bridge, exc); err != nil {
		slog.Warn("updateIsolationForLB: failed to update isolation rules", "bridge", bridge, "error", err)
	}

	// Set up SNAT if explicitly enabled.
	if snat && subnet != "" {
		outIface := network.DefaultRouteIface()
		if outIface != "" {
			if err := network.EnsureSNAT(bridge, subnet, vip, outIface); err != nil {
				slog.Warn("updateIsolationForLB: SNAT setup failed", "bridge", bridge, "error", err)
			}
		}
	}
}

// findIsolatedNetworkForBridge looks up all networks in Corrosion and returns the
// first one whose provisioned bridge name matches the given interface and has
// host-isolation enabled. Returns (nil, "") if not found.
func (s *Server) findIsolatedNetworkForBridge(ctx context.Context, bridge string) (*compose.NetworkDef, string) {
	rows, err := s.db.Query(ctx,
		`SELECT name, type, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, ""
	}
	for _, r := range rows {
		var def compose.NetworkDef
		if err := json.Unmarshal([]byte(r.String("config")), &def); err != nil {
			continue
		}
		def.Type = r.String("type")
		if !def.HostIsolation {
			continue
		}
		// Determine what bridge name this network would produce.
		netBridge := def.Interface
		if netBridge == "" {
			netBridge = r.String("name")
		}
		switch def.Type {
		case "vxlan":
			if def.VNI > 0 {
				netBridge = fmt.Sprintf("br-vni%d", def.VNI)
			}
		case "isolated":
			netBridge = network.IsolatedBridgeName(r.String("name"))
		}
		if netBridge == bridge {
			return &def, def.Subnet
		}
	}
	return nil, ""
}
