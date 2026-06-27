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
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
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
// containerBackendIP resolves a stack container's address for LB backend use.
// Containers have no vm_interfaces row, so the address comes from the recorded
// static IP (corrosion.LabelIP, replicated cluster-wide) first, then a local
// lxc-info lookup when the container runs on this host (covers DHCP NICs).
// A DHCP container on a *remote* host with no recorded IP is not yet resolved
// (a peer GetContainerIPRemote, mirroring VMs, is the follow-up).
func (s *Server) containerBackendIP(ctx context.Context, ct corrosion.ContainerRecord) string {
	if ip := ct.Labels[corrosion.LabelIP]; ip != "" {
		return ip
	}
	if ct.HostName == s.hostName && s.containerRuntime != nil {
		if ip, err := s.containerRuntime.IPContainer(ctx, ct.Name); err == nil {
			return ip
		}
	}
	return ""
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
	// Containers in the stack (found via the reserved stack label).
	cts, _ := corrosion.ListContainersByStack(ctx, s.db, stackName)
	for _, ct := range cts {
		out = append(out, resolvedBackend{Name: ct.Name, IP: s.containerBackendIP(ctx, ct), Running: ct.State == "running"})
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

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "roundrobin"
	}

	// Build backends.
	var lbBackends []lb.Backend
	backendPort := int(req.Ports[0].Target)

	// Recreate (same name) clears any locally-known stale backend tombstones for
	// this LB before inserting the requested set, so an old backend can't linger.
	// (Does not cover backend rows a peer has but this node never saw — that needs
	// a generation/epoch design; tracked as a follow-up.)
	if err := corrosion.SoftDeleteLBBackends(ctx, s.db, req.Name); err != nil {
		slog.Warn("CreateLoadBalancer: clear prior backends", "error", err)
	}

	// Explicit backends.
	for _, b := range req.Backends {
		addr := b.Address
		name := b.Name
		if name == "" {
			name = addr
		}
		lbBackends = append(lbBackends, lb.Backend{Name: name, IP: addr, Port: backendPort})
		if err := corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
			LBName: req.Name, Name: name, Address: addr, Enabled: true,
		}); err != nil {
			slog.Warn("CreateLoadBalancer: persist backend", "error", err)
		}
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
				if err := corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
					LBName: req.Name, Name: vmName, Address: ip, IsVM: true, VMName: vmName, Enabled: true,
				}); err != nil {
					slog.Warn("CreateLoadBalancer: persist VM backend", "error", err)
				}
				break
			}
		}
	}

	// Persist LB config.
	hostsJSON, _ := json.Marshal(req.Hosts)
	portsJSON, _ := json.Marshal(req.Ports)
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name:      req.Name,
		VIP:       req.Vip,
		Algorithm: algorithm,
		Hosts:     string(hostsJSON),
		Ports:     string(portsJSON),
		Enabled:   true,
	}); err != nil {
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
			client.ApplyLB(ctx, &pb.ApplyLBRequest{
				LbName: req.Name, Vip: req.Vip, Algorithm: algorithm,
				Backends: pbBackends, Ports: req.Ports, Hosts: req.Hosts,
			})
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
		`SELECT name, stack_name, vip, algorithm, hosts, ports, enabled FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, req.Name)
	if err != nil || len(rows) == 0 {
		return nil, status.Errorf(codes.NotFound, "load balancer %q not found", req.Name)
	}
	r := rows[0]

	// Merge changes.
	vip := r.String("vip")
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

	// Handle backend changes.
	for _, name := range req.RemoveBackends {
		corrosion.TombstoneLBBackend(ctx, s.db, req.Name, name)
	}
	for _, vmName := range req.RemoveVmBackends {
		corrosion.TombstoneLBBackend(ctx, s.db, req.Name, vmName)
	}
	for _, b := range req.AddBackends {
		name := b.Name
		if name == "" {
			name = b.Address
		}
		corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
			LBName: req.Name, Name: name, Address: b.Address, Enabled: true,
		})
	}
	for _, vmName := range req.AddVmBackends {
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vmName)
		for _, iface := range ifaces {
			if iface.IP != "" {
				corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
					LBName: req.Name, Name: vmName, Address: iface.IP, IsVM: true, VMName: vmName, Enabled: true,
				})
				break
			}
		}
	}

	// Persist updated config.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name:      req.Name,
		StackName: r.String("stack_name"),
		VIP:       vip,
		Algorithm: algorithm,
		Hosts:     hostsStr,
		Ports:     portsStr,
		Enabled:   r.Int("enabled") == 1,
	}); err != nil {
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
			client.ApplyLB(ctx, &pb.ApplyLBRequest{
				LbName: req.Name, Vip: vip, Algorithm: algorithm,
				Backends: pbBackends, Ports: parsedPorts, Hosts: lbHosts,
			})
		}(h)
	}

	// Remove LB from hosts that were in the old list but not the new one.
	var oldHosts []string
	if oldHostsStr != "" && oldHostsStr != "[]" {
		json.Unmarshal([]byte(oldHostsStr), &oldHosts)
	}
	s.removeLBFromStaleHosts(ctx, req.Name, oldHosts, lbHosts)

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
	var oldHosts []string
	if rows, err := s.db.Query(ctx, `SELECT hosts FROM lb_configs WHERE name = ? AND deleted_at IS NULL`, lbName); err == nil && len(rows) > 0 {
		if h := rows[0].String("hosts"); h != "" && h != "[]" {
			json.Unmarshal([]byte(h), &oldHosts)
		}
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
		Name:      lbName,
		StackName: spec.StackName,
		VIP:       lbSpec.Vip,
		Algorithm: algorithm,
		Hosts:     string(hostsJSON),
		Ports:     string(portsJSON),
		Enabled:   true,
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
		go s.forwardLBApply(context.Background(), h, spec)
	}

	// Remove LB from hosts that are no longer in the target list.
	// This handles the case where VMs migrate and the auto-resolved
	// host list changes (e.g. LB was on hostA, VMs moved to hostB).
	s.removeLBFromStaleHosts(ctx, lbName, oldHosts, targetHosts)
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
func (s *Server) forwardLBApply(ctx context.Context, hostName string, spec *pb.VMSpec) {
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

	if _, err := client.ApplyLB(ctx, &pb.ApplyLBRequest{
		LbName:    spec.StackName + "-lb",
		Vip:       lbSpec.Vip,
		Algorithm: lbSpec.Algorithm,
		Backends:  pbBackends,
		Ports:     pbPorts,
		Hosts:     lbSpec.Hosts,
	}); err != nil {
		slog.Warn("forwardLBApply: remote apply failed", "host", hostName, "error", err)
	} else {
		slog.Info("forwardLBApply: LB applied on remote host", "host", hostName, "stack", spec.StackName)
	}
}

// ApplyLB handles a request from a peer to configure HAProxy + keepalived locally.
func (s *Server) ApplyLB(ctx context.Context, req *pb.ApplyLBRequest) (*emptypb.Empty, error) {
	if req.LbName == "" {
		return nil, status.Error(codes.InvalidArgument, "lb_name required")
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

	slog.Info("ApplyLB: applied", "lb", req.LbName, "vip", req.Vip, "backends", len(backends))
	return &emptypb.Empty{}, nil
}

// RemoveLB handles a request from a peer to tear down a local LB instance.
func (s *Server) RemoveLB(ctx context.Context, req *pb.RemoveLBRequest) (*emptypb.Empty, error) {
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
		// Use refreshLBLocal which reads the full spec and re-applies.
		if cfg.StackName != "" {
			s.refreshLBLocal(ctx, cfg.StackName)
			slog.Info("LB reconciled on startup", "lb", cfg.Name, "stack", cfg.StackName)
		}
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
