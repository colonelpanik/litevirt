package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type pingOut struct {
	HostName      string `json:"host_name"`
	Version       string `json:"version"`
	SchemaVersion int32  `json:"schema_version"`
}

type whoamiOut struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	Realm     string `json:"realm"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type hostOut struct {
	Name         string            `json:"name"`
	Address      string            `json:"address,omitempty"`
	State        string            `json:"state"`
	Region       string            `json:"region,omitempty"`
	Version      string            `json:"version,omitempty"`
	CPUTotal     int32             `json:"cpu_total"`
	CPUUsed      int32             `json:"cpu_used"`
	MemTotalMiB  int32             `json:"mem_total_mib"`
	MemUsedMiB   int32             `json:"mem_used_mib"`
	DiskTotalGiB int64             `json:"disk_total_gib"`
	DiskUsedGiB  int64             `json:"disk_used_gib"`
	VMCount      int32             `json:"vm_count"`
	Labels       map[string]string `json:"labels,omitempty"`
	Pools        []poolOut         `json:"storage_pools,omitempty"`
	UpdatedAt    string            `json:"updated_at,omitempty"`
}

type vmOut struct {
	Name        string         `json:"name"`
	StackName   string         `json:"stack_name,omitempty"`
	Project     string         `json:"project,omitempty"`
	HostName    string         `json:"host_name"`
	State       string         `json:"state"`
	StateDetail string         `json:"state_detail,omitempty"`
	CPU         int32          `json:"cpu_actual"`
	MemoryMiB   int32          `json:"mem_actual_mib"`
	IsTemplate  bool           `json:"is_template"`
	Interfaces  []interfaceOut `json:"interfaces,omitempty"`
	Disks       []diskOut      `json:"disks,omitempty"`
	CreatedAt   string         `json:"created_at,omitempty"`
	UpdatedAt   string         `json:"updated_at,omitempty"`
}

type interfaceOut struct {
	NetworkName string `json:"network_name,omitempty"`
	Ordinal     int32  `json:"ordinal"`
	MAC         string `json:"mac,omitempty"`
	IP          string `json:"ip,omitempty"`
	Device      string `json:"device,omitempty"`
}

type diskOut struct {
	Name          string `json:"name"`
	HostName      string `json:"host_name,omitempty"`
	SizeBytes     int64  `json:"size_bytes"`
	StorageType   string `json:"storage_type,omitempty"`
	StorageVolume string `json:"storage_volume,omitempty"`
}

type vmStatsOut struct {
	Name           string  `json:"name"`
	CPUPct         float64 `json:"cpu_pct"`
	MemRSSBytes    int64   `json:"mem_rss_bytes"`
	MemTotalBytes  int64   `json:"mem_total_bytes"`
	DiskReadBytes  int64   `json:"disk_read_bytes"`
	DiskWriteBytes int64   `json:"disk_write_bytes"`
	NetRXBytes     int64   `json:"net_rx_bytes"`
	NetTXBytes     int64   `json:"net_tx_bytes"`
}

type hostStatsOut struct {
	HostName       string       `json:"host_name"`
	CPUPct         float64      `json:"cpu_pct"`
	MemUsedBytes   int64        `json:"mem_used_bytes"`
	MemTotalBytes  int64        `json:"mem_total_bytes"`
	DiskReadBytes  int64        `json:"disk_read_bytes"`
	DiskWriteBytes int64        `json:"disk_write_bytes"`
	VMStats        []vmStatsOut `json:"vm_stats,omitempty"`
}

type hostHealthOut struct {
	Entries []hostHealthEntryOut `json:"entries"`
}

type hostHealthEntryOut struct {
	Observer            string `json:"observer"`
	Target              string `json:"target"`
	Status              string `json:"status"`
	ConsecutiveFailures int32  `json:"consecutive_failures"`
	LastSeen            string `json:"last_seen,omitempty"`
}

type containerOut struct {
	HostName    string `json:"host_name"`
	Name        string `json:"name"`
	Project     string `json:"project,omitempty"`
	State       string `json:"state"`
	StateDetail string `json:"state_detail,omitempty"`
	Image       string `json:"image,omitempty"`
	CPULimit    int32  `json:"cpu_limit"`
	MemoryMiB   int32  `json:"memory_mib"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type networkOut struct {
	Name      string `json:"name"`
	StackName string `json:"stack_name,omitempty"`
	Project   string `json:"project,omitempty"`
	Type      string `json:"type,omitempty"`
	Iface     string `json:"iface,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	DHCP      bool   `json:"dhcp"`
	VNI       int32  `json:"vni,omitempty"`
	VMCount   int32  `json:"vm_count"`
}

type poolOut struct {
	Name       string `json:"name"`
	Host       string `json:"host,omitempty"`
	Project    string `json:"project,omitempty"`
	Driver     string `json:"driver"`
	State      string `json:"state,omitempty"`
	Source     string `json:"source,omitempty"`
	Target     string `json:"target,omitempty"`
	TotalGiB   int64  `json:"total_gib"`
	UsedGiB    int64  `json:"used_gib"`
	TotalBytes int64  `json:"total_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
}

type lbOut struct {
	Name       string           `json:"name"`
	StackName  string           `json:"stack_name,omitempty"`
	VIP        string           `json:"vip,omitempty"`
	Algorithm  string           `json:"algorithm,omitempty"`
	ActiveHost string           `json:"active_host,omitempty"`
	State      string           `json:"state,omitempty"`
	LBHosts    []string         `json:"lb_hosts,omitempty"`
	Backends   []backendOut     `json:"backends,omitempty"`
	Ports      []map[string]any `json:"ports,omitempty"`
}

type backendOut struct {
	VMName     string `json:"vm_name,omitempty"`
	Address    string `json:"address,omitempty"`
	Status     string `json:"status,omitempty"`
	ResponseMs int32  `json:"response_ms,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

type lbStatsOut struct {
	Name      string               `json:"name"`
	Frontends []lbFrontendStatsOut `json:"frontends,omitempty"`
	Backends  []lbBackendStatsOut  `json:"backends,omitempty"`
}

type lbFrontendStatsOut struct {
	ListenPort      int32 `json:"listen_port"`
	CurrentSessions int64 `json:"current_sessions"`
	TotalSessions   int64 `json:"total_sessions"`
	BytesIn         int64 `json:"bytes_in"`
	BytesOut        int64 `json:"bytes_out"`
	RequestRate     int64 `json:"request_rate"`
}

type lbBackendStatsOut struct {
	Name            string `json:"name"`
	Address         string `json:"address,omitempty"`
	Status          string `json:"status,omitempty"`
	CurrentSessions int64  `json:"current_sessions"`
	TotalSessions   int64  `json:"total_sessions"`
	BytesIn         int64  `json:"bytes_in"`
	BytesOut        int64  `json:"bytes_out"`
	RequestRate     int64  `json:"request_rate"`
	ErrorConn       int64  `json:"error_conn"`
	ErrorResp       int64  `json:"error_resp"`
	Response2xx     int32  `json:"response_2xx"`
	Response4xx     int32  `json:"response_4xx"`
	Response5xx     int32  `json:"response_5xx"`
	AvgResponseMs   int64  `json:"avg_response_ms"`
	AvgQueueMs      int64  `json:"avg_queue_ms"`
}

type auditOut struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Result    string `json:"result"`
	HostName  string `json:"host_name,omitempty"`
	// Deliberately omit username, target, and detail by default: they can carry
	// operator identity, IPs, paths, and resource-specific payload fragments.
}

type vmEventOut struct {
	ID        string `json:"id,omitempty"`
	VMName    string `json:"vm_name"`
	HostName  string `json:"host_name,omitempty"`
	Type      string `json:"type"`
	Result    string `json:"result,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	// Detail and username are omitted for the same reason audit detail is.
}

type proposalOut struct {
	ID           string  `json:"id"`
	VMName       string  `json:"vm_name"`
	SourceHost   string  `json:"src_host"`
	DestHost     string  `json:"dst_host"`
	Policy       string  `json:"policy,omitempty"`
	ExpectedGain float64 `json:"expected_gain,omitempty"`
	Status       string  `json:"status"`
	ProposedAt   string  `json:"proposed_at,omitempty"`
	ExpiresAt    string  `json:"expires_at,omitempty"`
}

type projectOut struct {
	Name       string    `json:"name"`
	Display    string    `json:"display,omitempty"`
	ParentName string    `json:"parent_name,omitempty"`
	CreatedAt  string    `json:"created_at,omitempty"`
	UpdatedAt  string    `json:"updated_at,omitempty"`
	Quota      *quotaOut `json:"quota,omitempty"`
	Usage      *usageOut `json:"usage,omitempty"`
}

type quotaOut struct {
	ProjectName    string `json:"project_name"`
	VCPULimit      int32  `json:"vcpu_limit"`
	MemMiBLimit    int32  `json:"mem_mib_limit"`
	DiskGiBLimit   int32  `json:"disk_gib_limit"`
	NICLimit       int32  `json:"nic_limit"`
	PublicIPLimit  int32  `json:"public_ip_limit"`
	BackupGiBLimit int32  `json:"backup_gib_limit"`
}

type usageOut struct {
	ProjectName   string `json:"project_name"`
	VCPUUsed      int32  `json:"vcpu_used"`
	MemMiBUsed    int32  `json:"mem_mib_used"`
	DiskGiBUsed   int32  `json:"disk_gib_used"`
	NICUsed       int32  `json:"nic_used"`
	VMCount       int32  `json:"vm_count"`
	PublicIPsUsed int32  `json:"public_ips_used"`
	BackupGiBUsed int32  `json:"backup_gib_used"`
}

func pingDTO(p *pb.PingResponse) pingOut {
	return pingOut{HostName: p.GetHostName(), Version: p.GetVersion(), SchemaVersion: p.GetSchemaVersion()}
}

func whoamiDTO(w *pb.WhoamiResponse) whoamiOut {
	return whoamiOut{Username: w.GetUsername(), Role: w.GetRole(), Realm: w.GetRealm(), ExpiresAt: w.GetExpiresAt()}
}

func hostDTO(h *pb.Host) hostOut {
	pools := make([]poolOut, 0, len(h.GetStoragePools()))
	for _, p := range h.GetStoragePools() {
		pools = append(pools, poolDTO(p))
	}
	return hostOut{
		Name: h.GetName(), Address: h.GetAddress(), State: h.GetState().String(), Region: h.GetRegion(), Version: h.GetVersion(),
		CPUTotal: h.GetCpuTotal(), CPUUsed: h.GetCpuUsed(), MemTotalMiB: h.GetMemTotalMib(), MemUsedMiB: h.GetMemUsedMib(),
		DiskTotalGiB: h.GetDiskTotalGib(), DiskUsedGiB: h.GetDiskUsedGib(), VMCount: h.GetVmCount(), Labels: h.GetLabels(),
		Pools: pools, UpdatedAt: ts(h.GetUpdatedAt()),
	}
}

func mapHosts(in []*pb.Host) []hostOut {
	out := make([]hostOut, 0, len(in))
	for _, h := range in {
		out = append(out, hostDTO(h))
	}
	return out
}

func vmDTO(v *pb.VM) vmOut {
	spec := v.GetSpec()
	ifaces := make([]interfaceOut, 0, len(v.GetInterfaces()))
	for _, nic := range v.GetInterfaces() {
		ifaces = append(ifaces, interfaceOut{NetworkName: nic.GetNetworkName(), Ordinal: nic.GetOrdinal(), MAC: nic.GetMac(), IP: nic.GetIp(), Device: nic.GetTapDevice()})
	}
	disks := make([]diskOut, 0, len(v.GetDisks()))
	for _, d := range v.GetDisks() {
		disks = append(disks, diskOut{Name: d.GetName(), HostName: d.GetHostName(), SizeBytes: d.GetSizeBytes(), StorageType: d.GetStorageType(), StorageVolume: d.GetStorageVolume()})
	}
	return vmOut{
		Name: v.GetName(), StackName: v.GetStackName(), Project: spec.GetProject(), HostName: v.GetHostName(), State: v.GetState().String(),
		StateDetail: v.GetStateDetail(), CPU: v.GetCpuActual(), MemoryMiB: v.GetMemActualMib(), IsTemplate: v.GetIsTemplate(),
		Interfaces: ifaces, Disks: disks, CreatedAt: ts(v.GetCreatedAt()), UpdatedAt: ts(v.GetUpdatedAt()),
	}
}

func mapVMs(in []*pb.VM) []vmOut {
	out := make([]vmOut, 0, len(in))
	for _, v := range in {
		out = append(out, vmDTO(v))
	}
	return out
}

func vmStatsDTO(v *pb.VMStats) vmStatsOut {
	return vmStatsOut{
		Name: v.GetName(), CPUPct: v.GetCpuPct(), MemRSSBytes: v.GetMemRssBytes(), MemTotalBytes: v.GetMemTotalBytes(),
		DiskReadBytes: v.GetDiskRdBytes(), DiskWriteBytes: v.GetDiskWrBytes(), NetRXBytes: v.GetNetRxBytes(), NetTXBytes: v.GetNetTxBytes(),
	}
}

func hostStatsDTO(h *pb.HostResourceStats, limit int) hostStatsOut {
	vms := h.GetVmStats()
	vms = truncate(vms, limit)
	out := hostStatsOut{
		HostName: h.GetHostName(), CPUPct: h.GetCpuPct(), MemUsedBytes: h.GetMemUsedBytes(), MemTotalBytes: h.GetMemTotalBytes(),
		DiskReadBytes: h.GetDiskRdBytes(), DiskWriteBytes: h.GetDiskWrBytes(),
	}
	for _, v := range vms {
		out.VMStats = append(out.VMStats, vmStatsDTO(v))
	}
	return out
}

func hostHealthDTO(h *pb.HostHealthMatrix) hostHealthOut {
	out := hostHealthOut{Entries: make([]hostHealthEntryOut, 0, len(h.GetEntries()))}
	for _, e := range h.GetEntries() {
		out.Entries = append(out.Entries, hostHealthEntryOut{
			Observer:            e.GetObserver(),
			Target:              e.GetTarget(),
			Status:              e.GetStatus(),
			ConsecutiveFailures: e.GetConsecutiveFailures(),
			LastSeen:            ts(e.GetLastSeen()),
		})
	}
	return out
}

func mapContainers(in []*pb.Container) []containerOut {
	out := make([]containerOut, 0, len(in))
	for _, c := range in {
		out = append(out, containerOut{
			HostName: c.GetHostName(), Name: c.GetName(), Project: c.GetProject(), State: c.GetState(), StateDetail: c.GetStateDetail(),
			Image: c.GetImage(), CPULimit: c.GetCpuLimit(), MemoryMiB: c.GetMemoryMib(), UpdatedAt: c.GetUpdatedAt(),
		})
	}
	return out
}

func mapNetworks(in []*pb.NetworkInfo) []networkOut {
	out := make([]networkOut, 0, len(in))
	for _, n := range in {
		out = append(out, networkDTO(n))
	}
	return out
}

func networkDTO(n *pb.NetworkInfo) networkOut {
	return networkOut{
		Name: n.GetName(), StackName: n.GetStackName(), Project: n.GetProject(), Type: n.GetType(), Iface: n.GetIface(),
		Subnet: n.GetSubnet(), Gateway: n.GetGateway(), DHCP: n.GetDhcp(), VNI: n.GetVni(), VMCount: n.GetVmCount(),
	}
}

func poolDTO(p *pb.StoragePool) poolOut {
	return poolOut{
		Name: p.GetName(), Host: p.GetHost(), Project: p.GetProject(), Driver: p.GetDriver(), State: p.GetState(),
		Source: p.GetSource(), Target: p.GetTarget(), TotalGiB: p.GetTotalGib(), UsedGiB: p.GetUsedGib(),
		TotalBytes: p.GetTotalBytes(), UsedBytes: p.GetUsedBytes(),
	}
}

func mapPools(in []*pb.StoragePool) []poolOut {
	out := make([]poolOut, 0, len(in))
	for _, p := range in {
		out = append(out, poolDTO(p))
	}
	return out
}

func lbDTO(lb *pb.LoadBalancer) lbOut {
	out := lbOut{
		Name: lb.GetName(), StackName: lb.GetStackName(), VIP: lb.GetVip(), Algorithm: lb.GetAlgorithm(),
		ActiveHost: lb.GetActiveHost(), State: lb.GetState(), LBHosts: lb.GetLbHosts(),
	}
	for _, b := range lb.GetBackends() {
		out.Backends = append(out.Backends, backendOut{VMName: b.GetVmName(), Address: b.GetAddress(), Status: b.GetStatus(), ResponseMs: b.GetResponseMs(), LastError: b.GetLastError()})
	}
	for _, p := range lb.GetPorts() {
		out.Ports = append(out.Ports, map[string]any{
			"listen":   p.GetListen(),
			"target":   p.GetTarget(),
			"protocol": p.GetProtocol(),
		})
	}
	return out
}

func mapLBs(in []*pb.LoadBalancer) []lbOut {
	out := make([]lbOut, 0, len(in))
	for _, lb := range in {
		out = append(out, lbDTO(lb))
	}
	return out
}

func lbStatsDTO(stats *pb.LBStatsResponse) lbStatsOut {
	out := lbStatsOut{Name: stats.GetName()}
	for _, f := range stats.GetFrontends() {
		out.Frontends = append(out.Frontends, lbFrontendStatsOut{
			ListenPort:      f.GetListenPort(),
			CurrentSessions: f.GetCurrentSessions(),
			TotalSessions:   f.GetTotalSessions(),
			BytesIn:         f.GetBytesIn(),
			BytesOut:        f.GetBytesOut(),
			RequestRate:     f.GetRequestRate(),
		})
	}
	for _, b := range stats.GetBackends() {
		out.Backends = append(out.Backends, lbBackendStatsOut{
			Name:            b.GetName(),
			Address:         b.GetAddress(),
			Status:          b.GetStatus(),
			CurrentSessions: b.GetCurrentSessions(),
			TotalSessions:   b.GetTotalSessions(),
			BytesIn:         b.GetBytesIn(),
			BytesOut:        b.GetBytesOut(),
			RequestRate:     b.GetRequestRate(),
			ErrorConn:       b.GetErrorConn(),
			ErrorResp:       b.GetErrorResp(),
			Response2xx:     b.GetResponse_2Xx(),
			Response4xx:     b.GetResponse_4Xx(),
			Response5xx:     b.GetResponse_5Xx(),
			AvgResponseMs:   b.GetAvgResponseMs(),
			AvgQueueMs:      b.GetAvgQueueMs(),
		})
	}
	return out
}

func mapAudit(in []*pb.AuditEntry) []auditOut {
	out := make([]auditOut, 0, len(in))
	for _, e := range in {
		out = append(out, auditOut{Timestamp: e.GetTimestamp(), Action: e.GetAction(), Result: e.GetResult(), HostName: e.GetHostName()})
	}
	return out
}

func mapVMEvents(in []*pb.VMEvent) []vmEventOut {
	out := make([]vmEventOut, 0, len(in))
	for _, e := range in {
		out = append(out, vmEventOut{ID: e.GetId(), VMName: e.GetVmName(), HostName: e.GetHostName(), Type: e.GetType(), Result: e.GetResult(), Severity: e.GetSeverity(), Timestamp: e.GetTs()})
	}
	return out
}

func mapProposals(in []*pb.RebalanceProposal) []proposalOut {
	out := make([]proposalOut, 0, len(in))
	for _, p := range in {
		out = append(out, proposalOut{ID: p.GetId(), VMName: p.GetVmName(), SourceHost: p.GetSrcHost(), DestHost: p.GetDstHost(), Policy: p.GetPolicy(), ExpectedGain: p.GetExpectedGain(), Status: p.GetStatus(), ProposedAt: p.GetProposedAt(), ExpiresAt: p.GetExpiresAt()})
	}
	return out
}

func (s *Server) mapProjects(ctx context.Context, in []*pb.Project, includeQuota, includeUsage bool) []projectOut {
	out := make([]projectOut, 0, len(in))
	for _, p := range in {
		item := projectOut{Name: p.GetName(), Display: p.GetDisplay(), ParentName: p.GetParentName(), CreatedAt: p.GetCreatedAt(), UpdatedAt: p.GetUpdatedAt()}
		if includeQuota {
			if q, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
				return c.GetProjectQuota(ctx, &pb.GetProjectQuotaRequest{ProjectName: p.GetName()})
			}); err == nil {
				dto := quotaDTO(q.(*pb.ProjectQuota))
				item.Quota = &dto
			}
		}
		if includeUsage {
			if u, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
				return c.GetProjectUsage(ctx, &pb.GetProjectUsageRequest{ProjectName: p.GetName()})
			}); err == nil {
				dto := usageDTO(u.(*pb.ProjectUsage))
				item.Usage = &dto
			}
		}
		out = append(out, item)
	}
	return out
}

func quotaDTO(q *pb.ProjectQuota) quotaOut {
	return quotaOut{
		ProjectName: q.GetProjectName(), VCPULimit: q.GetVcpuLimit(), MemMiBLimit: q.GetMemMibLimit(), DiskGiBLimit: q.GetDiskGibLimit(),
		NICLimit: q.GetNicLimit(), PublicIPLimit: q.GetPublicIpLimit(), BackupGiBLimit: q.GetBackupGibLimit(),
	}
}

func usageDTO(u *pb.ProjectUsage) usageOut {
	return usageOut{
		ProjectName: u.GetProjectName(), VCPUUsed: u.GetVcpuUsed(), MemMiBUsed: u.GetMemMibUsed(), DiskGiBUsed: u.GetDiskGibUsed(),
		NICUsed: u.GetNicUsed(), VMCount: u.GetVmCount(), PublicIPsUsed: u.GetPublicIpsUsed(), BackupGiBUsed: u.GetBackupGibUsed(),
	}
}

func clusterDTO(c *pb.ClusterStatus, limit int) map[string]any {
	return map[string]any{
		"cluster_name": c.GetClusterName(),
		"hosts_total":  c.GetHostsTotal(),
		"hosts_active": c.GetHostsActive(),
		"vms_total":    c.GetVmsTotal(),
		"vms_running":  c.GetVmsRunning(),
		"vms_error":    c.GetVmsError(),
		"alerts_count": len(c.GetAlerts()),
		"events_count": len(c.GetRecentEvents()),
		"hosts":        mapHosts(truncate(c.GetHosts(), limit)),
	}
}

func ts(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	return t.AsTime().Format(timeFormatRFC3339Nano)
}

const timeFormatRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"

func promptSnapshot(ctx context.Context, s *Server) string {
	statusAny, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetClusterStatus(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return fmt.Sprintf("Cluster status unavailable: %v", err)
	}
	b, _ := json.Marshal(clusterDTO(statusAny.(*pb.ClusterStatus), s.opts.MaxListItems))
	return string(b)
}
