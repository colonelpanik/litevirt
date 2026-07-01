package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	defaultName         = "litevirt"
	defaultVersion      = "dev"
	defaultTimeout      = 30 * time.Second
	defaultMaxListItems = 100
	defaultToolPrefix   = "litevirt_"
	jsonMIME            = "application/json"
)

type ConnectFunc func(context.Context) (pb.LiteVirtClient, func(), error)

type Options struct {
	Name         string
	Version      string
	AllowWrite   bool
	Timeout      time.Duration
	MaxListItems int
	ToolPrefix   string
	Logger       *slog.Logger
	Connect      ConnectFunc
}

type Server struct {
	opts Options

	mu     sync.Mutex
	client pb.LiteVirtClient
	close  func()

	toolNames []string
}

type toolEnvelope struct {
	Summary   string     `json:"summary,omitempty"`
	Data      any        `json:"data,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
	Error     *toolError `json:"error,omitempty"`
}

type toolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	Hint      string `json:"hint,omitempty"`
}

func New(ctx context.Context, opts Options) (*Server, error) {
	opts = normalizeOptions(opts)
	s := &Server{opts: opts}
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	if err := s.validateStartup(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func normalizeOptions(opts Options) Options {
	if opts.Name == "" {
		opts.Name = defaultName
	}
	if opts.Version == "" {
		opts.Version = defaultVersion
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MaxListItems <= 0 {
		opts.MaxListItems = defaultMaxListItems
	}
	if opts.ToolPrefix == "" {
		opts.ToolPrefix = defaultToolPrefix
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Connect == nil {
		opts.Connect = cli.Connect
	}
	return opts
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.close != nil {
		s.close()
	}
	s.client = nil
	s.close = nil
}

func (s *Server) connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	c, closer, err := s.opts.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect to litevirt daemon: %w", err)
	}
	s.mu.Lock()
	oldClose := s.close
	s.client = c
	s.close = closer
	s.mu.Unlock()
	if oldClose != nil {
		oldClose()
	}
	return nil
}

func (s *Server) validateStartup(ctx context.Context) error {
	if _, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.Ping(ctx, &pb.PingRequest{})
	}); err != nil {
		return fmt.Errorf("startup ping failed: %w", err)
	}
	if _, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.Whoami(ctx, &emptypb.Empty{})
	}); err != nil {
		return fmt.Errorf("startup whoami failed: %w", err)
	}
	return nil
}

func (s *Server) clientSnapshot() pb.LiteVirtClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client
}

func (s *Server) rpc(ctx context.Context, retry bool, fn func(context.Context, pb.LiteVirtClient) (any, error)) (any, error) {
	c := s.clientSnapshot()
	if c == nil {
		return nil, errors.New("litevirt client is not connected")
	}
	callCtx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	out, err := fn(callCtx, c)
	if err == nil || !retry || status.Code(err) != codes.Unavailable {
		return out, err
	}
	s.opts.Logger.Warn("litevirt MCP reconnect after unavailable", "error", err)
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	c = s.clientSnapshot()
	callCtx, cancel = context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	return fn(callCtx, c)
}

func (s *Server) Run(ctx context.Context) error {
	m := mcp.NewServer(&mcp.Implementation{Name: s.opts.Name, Version: s.opts.Version}, nil)
	s.registerTools(m)
	s.registerResources(m)
	s.registerPrompts(m)
	return m.Run(ctx, &mcp.StdioTransport{})
}

func (s *Server) tool(name string) string {
	return s.opts.ToolPrefix + name
}

func (s *Server) registerTools(m *mcp.Server) {
	s.addTool(m, "ping", "Connectivity self-test against the configured litevirt daemon.", emptySchema(), s.handlePing)
	s.addTool(m, "whoami", "Show the authenticated litevirt identity and role.", emptySchema(), s.handleWhoami)
	s.addTool(m, "cluster_status", "Return a safe cluster status summary with host counts, VM counts, and alert counts.", emptySchema(), s.handleClusterStatus)
	s.addTool(m, "list_hosts", "List hosts with coarse capacity and placement information.", objectSchema(map[string]any{"limit": integerSchema("Maximum hosts to return.")}), s.handleListHosts)
	s.addTool(m, "inspect_host", "Inspect one host with safe fields only.", objectSchema(map[string]any{"name": stringSchema("Host name.")}, "name"), s.handleInspectHost)
	s.addTool(m, "host_stats", "Fetch live aggregate stats for one host.", objectSchema(map[string]any{"name": stringSchema("Host name.")}, "name"), s.handleHostStats)
	s.addTool(m, "host_health", "Return the host health matrix.", emptySchema(), s.handleHostHealth)
	s.addTool(m, "list_vms", "List VMs with safe placement and state fields; VM specs and cloud-init are never returned.", objectSchema(map[string]any{
		"host_name":  stringSchema("Optional host filter."),
		"stack_name": stringSchema("Optional stack filter."),
		"limit":      integerSchema("Maximum VMs to return."),
	}), s.handleListVMs)
	s.addTool(m, "inspect_vm", "Inspect one VM with safe fields only; VM spec, cloud-init, and injected data are omitted.", objectSchema(map[string]any{"name": stringSchema("VM name.")}, "name"), s.handleInspectVM)
	s.addTool(m, "vm_stats", "Fetch live stats for one VM.", objectSchema(map[string]any{"name": stringSchema("VM name.")}, "name"), s.handleVMStats)
	s.addTool(m, "list_vm_events", "List bounded VM events with detail redacted.", objectSchema(map[string]any{
		"vm_name": stringSchema("Optional VM name filter."),
		"since":   stringSchema("Optional RFC3339 lower bound."),
		"limit":   integerSchema("Maximum events to return."),
	}), s.handleListVMEvents)
	s.addTool(m, "list_containers", "List containers. The current litevirt API supports host filtering only.", objectSchema(map[string]any{
		"host_name": stringSchema("Optional host filter."),
		"limit":     integerSchema("Maximum containers to return."),
	}), s.handleListContainers)
	s.addTool(m, "list_networks", "List networks with project ownership and addressing metadata.", objectSchema(map[string]any{"limit": integerSchema("Maximum networks to return.")}), s.handleListNetworks)
	s.addTool(m, "get_network", "Inspect one network with safe fields only.", objectSchema(map[string]any{"name": stringSchema("Network name.")}, "name"), s.handleGetNetwork)
	s.addTool(m, "list_storage_pools", "List storage pools with project ownership and usage metadata.", objectSchema(map[string]any{"limit": integerSchema("Maximum pools to return.")}), s.handleListStoragePools)
	s.addTool(m, "get_storage_pool", "Inspect one storage pool with safe fields only.", objectSchema(map[string]any{
		"name": stringSchema("Storage pool name."),
		"host": stringSchema("Optional host scope."),
	}, "name"), s.handleGetStoragePool)
	s.addTool(m, "list_load_balancers", "List load balancers and backend states.", objectSchema(map[string]any{"limit": integerSchema("Maximum load balancers to return.")}), s.handleListLoadBalancers)
	s.addTool(m, "inspect_lb", "Inspect one load balancer and backend state.", objectSchema(map[string]any{"name": stringSchema("Load balancer name.")}, "name"), s.handleInspectLB)
	s.addTool(m, "lb_stats", "Fetch live HAProxy frontend and backend stats for one load balancer.", objectSchema(map[string]any{"name": stringSchema("Load balancer name.")}, "name"), s.handleLBStats)
	s.addTool(m, "list_audit_log", "List bounded audit entries with user, target, and detail redacted.", objectSchema(map[string]any{
		"action": stringSchema("Optional action filter."),
		"target": stringSchema("Optional target path filter."),
		"user":   stringSchema("Optional username filter."),
		"since":  stringSchema("Optional RFC3339 lower bound."),
		"until":  stringSchema("Optional RFC3339 upper bound."),
		"limit":  integerSchema("Maximum entries to return."),
	}), s.handleListAuditLog)
	s.addTool(m, "list_rebalance_proposals", "List rebalance proposals with bounded output.", objectSchema(map[string]any{
		"status": stringSchema("Optional status filter."),
		"limit":  integerSchema("Maximum proposals to return."),
	}), s.handleListRebalanceProposals)
	s.addTool(m, "list_projects", "List projects and optionally include safe quota and usage summaries.", objectSchema(map[string]any{
		"include_quota": booleanSchema("Include project quotas."),
		"include_usage": booleanSchema("Include project usage."),
		"limit":         integerSchema("Maximum projects to return."),
	}), s.handleListProjects)
	s.addTool(m, "get_project_quota", "Get a project's quota.", objectSchema(map[string]any{"project_name": stringSchema("Project name.")}, "project_name"), s.handleGetProjectQuota)
	s.addTool(m, "get_project_usage", "Get a project's usage.", objectSchema(map[string]any{"project_name": stringSchema("Project name.")}, "project_name"), s.handleGetProjectUsage)

	if !s.opts.AllowWrite {
		return
	}
	writeSchema := objectSchema(map[string]any{"name": stringSchema("Object name."), "confirm": booleanSchema("Must be true to execute.")}, "name", "confirm")
	s.addTool(m, "start_vm", "Start a VM. Requires --allow-write and confirm=true.", writeSchema, s.handleStartVM)
	s.addTool(m, "stop_vm", "Gracefully stop a VM. Force stop is intentionally not exposed. Requires --allow-write and confirm=true.", stopVMWriteSchema(), s.handleStopVM)
	s.addTool(m, "restart_vm", "Restart a VM. Requires --allow-write and confirm=true.", writeSchema, s.handleRestartVM)
	s.addTool(m, "start_container", "Start a container. Requires --allow-write and confirm=true.", objectSchema(map[string]any{
		"name":      stringSchema("Container name."),
		"host_name": stringSchema("Container host."),
		"confirm":   booleanSchema("Must be true to execute."),
	}, "name", "host_name", "confirm"), s.handleStartContainer)
	s.addTool(m, "stop_container", "Stop a container. Requires --allow-write and confirm=true.", objectSchema(map[string]any{
		"name":        stringSchema("Container name."),
		"host_name":   stringSchema("Container host."),
		"timeout_sec": integerSchema("Graceful stop timeout in seconds."),
		"confirm":     booleanSchema("Must be true to execute."),
	}, "name", "host_name", "confirm"), s.handleStopContainer)
	s.addTool(m, "enable_backend", "Enable one load-balancer backend. Requires --allow-write and confirm=true.", backendWriteSchema(), s.handleEnableBackend)
	s.addTool(m, "disable_backend", "Disable one load-balancer backend. Requires --allow-write and confirm=true.", backendWriteSchema(), s.handleDisableBackend)
	s.addTool(m, "drain_backend", "Drain one load-balancer backend. Requires --allow-write and confirm=true.", backendWriteSchema(), s.handleDrainBackend)
}

func (s *Server) addTool(m *mcp.Server, name, description string, schema map[string]any, h func(context.Context, map[string]any) *mcp.CallToolResult) {
	s.toolNames = append(s.toolNames, s.tool(name))
	m.AddTool(&mcp.Tool{
		Name:        s.tool(name),
		Title:       strings.ReplaceAll(name, "_", " "),
		Description: description,
		InputSchema: schema,
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := decodeArgs(req)
		if err != nil {
			return s.fail(err), nil
		}
		if err := validateArgs(args, schema); err != nil {
			return s.fail(err), nil
		}
		return h(ctx, args), nil
	})
}

func decodeArgs(req *mcp.CallToolRequest) (map[string]any, error) {
	if req == nil || req.Params == nil || len(req.Params.Arguments) == 0 {
		return map[string]any{}, nil
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tool arguments: %v", err)
	}
	if args == nil {
		args = map[string]any{}
	}
	return args, nil
}

func validateArgs(args map[string]any, schema map[string]any) error {
	props, _ := schema["properties"].(map[string]any)
	if required, ok := schema["required"].([]string); ok {
		for _, key := range required {
			if _, ok := args[key]; !ok {
				return status.Errorf(codes.InvalidArgument, "missing required argument %q", key)
			}
		}
	}
	for key, value := range args {
		prop, ok := props[key]
		if !ok {
			return status.Errorf(codes.InvalidArgument, "unknown argument %q", key)
		}
		propMap, _ := prop.(map[string]any)
		switch propMap["type"] {
		case "string":
			if _, ok := value.(string); !ok {
				return status.Errorf(codes.InvalidArgument, "argument %q must be a string", key)
			}
		case "boolean":
			if _, ok := value.(bool); !ok {
				return status.Errorf(codes.InvalidArgument, "argument %q must be a boolean", key)
			}
		case "integer":
			f, ok := value.(float64)
			if !ok || math.Trunc(f) != f {
				return status.Errorf(codes.InvalidArgument, "argument %q must be an integer", key)
			}
			if min, ok := numericMinimum(propMap["minimum"]); ok && f < min {
				return status.Errorf(codes.InvalidArgument, "argument %q must be >= %v", key, min)
			}
		}
	}
	return nil
}

func numericMinimum(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

func (s *Server) ok(summary string, data any, truncated bool) *mcp.CallToolResult {
	env := toolEnvelope{Summary: summary, Data: data, Truncated: truncated}
	b, _ := json.Marshal(env)
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(b)}},
		StructuredContent: env,
	}
}

func (s *Server) fail(err error) *mcp.CallToolResult {
	env := toolEnvelope{Error: mapError(err)}
	b, _ := json.Marshal(env)
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(b)}},
		StructuredContent: env,
		IsError:           true,
	}
}

func mapError(err error) *toolError {
	if err == nil {
		return nil
	}
	code := status.Code(err)
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	} else if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	msg := status.Convert(err).Message()
	if code == codes.Unknown {
		msg = err.Error()
	}
	out := &toolError{Code: code.String(), Message: msg}
	switch code {
	case codes.Unauthenticated:
		out.Hint = "Check LV_TOKEN or run litevirt login again; static bearer tokens require restarting the MCP server after renewal."
	case codes.PermissionDenied:
		out.Hint = "The authenticated litevirt principal lacks RBAC for this resource."
	case codes.InvalidArgument:
		out.Hint = "Fix the tool arguments and retry."
	case codes.NotFound:
		out.Hint = "Verify the object name and host/project scope."
	case codes.FailedPrecondition:
		out.Hint = "The request is valid but the object is not in a state that allows the operation."
	case codes.Unavailable:
		out.Retryable = true
		out.Hint = "The daemon is unavailable; retry after connectivity recovers."
	case codes.DeadlineExceeded:
		out.Retryable = true
		out.Hint = "The operation timed out; retry or raise --timeout if the cluster is slow."
	case codes.Canceled:
		out.Hint = "The request was canceled by the caller."
	default:
		out.Hint = "Inspect daemon logs for details."
	}
	return out
}

func (s *Server) handlePing(ctx context.Context, _ map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.Ping(ctx, &pb.PingRequest{})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("litevirt daemon reachable", pingDTO(out.(*pb.PingResponse)), false)
}

func (s *Server) handleWhoami(ctx context.Context, _ map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.Whoami(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("authenticated litevirt identity", whoamiDTO(out.(*pb.WhoamiResponse)), false)
}

func (s *Server) handleClusterStatus(ctx context.Context, _ map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetClusterStatus(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("cluster status", clusterDTO(out.(*pb.ClusterStatus), s.opts.MaxListItems), len(out.(*pb.ClusterStatus).GetHosts()) > s.opts.MaxListItems)
}

func (s *Server) handleListHosts(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListHosts(ctx, &pb.ListHostsRequest{})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListHostsResponse).GetHosts()
	limit := s.limit(args, "limit")
	return s.ok("hosts", mapHosts(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleInspectHost(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.InspectHost(ctx, &pb.InspectHostRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("host inspected", hostDTO(out.(*pb.Host)), false)
}

func (s *Server) handleHostStats(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetHostStats(ctx, &pb.GetHostStatsRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("host stats", hostStatsDTO(out.(*pb.HostResourceStats), s.opts.MaxListItems), len(out.(*pb.HostResourceStats).GetVmStats()) > s.opts.MaxListItems)
}

func (s *Server) handleHostHealth(ctx context.Context, _ map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetHostHealth(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("host health", hostHealthDTO(out.(*pb.HostHealthMatrix)), false)
}

func (s *Server) handleListVMs(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListVMs(ctx, &pb.ListVMsRequest{HostName: stringArg(args, "host_name"), StackName: stringArg(args, "stack_name")})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListVMsResponse).GetVms()
	limit := s.limit(args, "limit")
	return s.ok("vms", mapVMs(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleInspectVM(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("vm inspected", vmDTO(out.(*pb.VM)), false)
}

func (s *Server) handleVMStats(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetVMStats(ctx, &pb.GetVMStatsRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("vm stats", vmStatsDTO(out.(*pb.VMStats)), false)
}

func (s *Server) handleListVMEvents(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	limit := s.limit(args, "limit")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListVMEvents(ctx, &pb.ListVMEventsRequest{VmName: stringArg(args, "vm_name"), Since: stringArg(args, "since"), Limit: int32(limit + 1)})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListVMEventsResponse).GetEvents()
	return s.ok("vm events", mapVMEvents(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleListContainers(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListContainers(ctx, &pb.ListContainersRequest{HostName: stringArg(args, "host_name")})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListContainersResponse).GetContainers()
	limit := s.limit(args, "limit")
	return s.ok("containers", mapContainers(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleListNetworks(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListNetworks(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListNetworksResponse).GetNetworks()
	limit := s.limit(args, "limit")
	return s.ok("networks", mapNetworks(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleGetNetwork(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetNetwork(ctx, &pb.GetNetworkRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("network inspected", networkDTO(out.(*pb.NetworkInfo)), false)
}

func (s *Server) handleListStoragePools(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListStoragePoolsResponse).GetPools()
	limit := s.limit(args, "limit")
	return s.ok("storage pools", mapPools(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleGetStoragePool(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetStoragePool(ctx, &pb.GetStoragePoolRequest{Name: stringArg(args, "name"), Host: stringArg(args, "host")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("storage pool inspected", poolDTO(out.(*pb.GetStoragePoolResponse).GetPool()), false)
}

func (s *Server) handleListLoadBalancers(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListLoadBalancers(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListLBResponse).GetLbs()
	limit := s.limit(args, "limit")
	return s.ok("load balancers", mapLBs(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleInspectLB(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("load balancer inspected", lbDTO(out.(*pb.LoadBalancer)), false)
}

func (s *Server) handleLBStats(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.LBStats(ctx, &pb.LBStatsRequest{Name: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("load balancer stats", lbStatsDTO(out.(*pb.LBStatsResponse)), false)
}

func (s *Server) handleListAuditLog(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	limit := s.limit(args, "limit")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListAuditLog(ctx, &pb.ListAuditLogRequest{
			Limit:  int32(limit + 1),
			Action: stringArg(args, "action"),
			Target: stringArg(args, "target"),
			User:   stringArg(args, "user"),
			Since:  stringArg(args, "since"),
			Until:  stringArg(args, "until"),
		})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListAuditLogResponse).GetEntries()
	return s.ok("audit entries", mapAudit(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleListRebalanceProposals(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListRebalanceProposals(ctx, &pb.ListRebalanceProposalsRequest{StatusFilter: stringArg(args, "status")})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListRebalanceProposalsResponse).GetProposals()
	limit := s.limit(args, "limit")
	return s.ok("rebalance proposals", mapProposals(truncate(items, limit)), len(items) > limit)
}

func (s *Server) handleListProjects(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListProjects(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return s.fail(err)
	}
	items := out.(*pb.ListProjectsResponse).GetProjects()
	limit := s.limit(args, "limit")
	return s.ok("projects", s.mapProjects(ctx, truncate(items, limit), boolArg(args, "include_quota"), boolArg(args, "include_usage")), len(items) > limit)
}

func (s *Server) handleGetProjectQuota(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "project_name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetProjectQuota(ctx, &pb.GetProjectQuotaRequest{ProjectName: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("project quota", quotaDTO(out.(*pb.ProjectQuota)), false)
}

func (s *Server) handleGetProjectUsage(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	name := stringArg(args, "project_name")
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetProjectUsage(ctx, &pb.GetProjectUsageRequest{ProjectName: name})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("project usage", usageDTO(out.(*pb.ProjectUsage)), false)
}

func (s *Server) handleStartVM(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	out, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.StartVM(ctx, &pb.StartVMRequest{Name: stringArg(args, "name")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("vm started", vmDTO(out.(*pb.VM)), false)
}

func (s *Server) handleStopVM(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	out, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.StopVM(ctx, &pb.StopVMRequest{Name: stringArg(args, "name"), Timeout: int32Arg(args, "timeout_sec")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("vm stopped", vmDTO(out.(*pb.VM)), false)
}

func (s *Server) handleRestartVM(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	out, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.RestartVM(ctx, &pb.RestartVMRequest{Name: stringArg(args, "name")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("vm restarted", vmDTO(out.(*pb.VM)), false)
}

func (s *Server) handleStartContainer(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	_, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.StartContainer(ctx, &pb.StartContainerRequest{HostName: stringArg(args, "host_name"), Name: stringArg(args, "name")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("container started", map[string]string{"host_name": stringArg(args, "host_name"), "name": stringArg(args, "name")}, false)
}

func (s *Server) handleStopContainer(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	_, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.StopContainer(ctx, &pb.StopContainerRequest{HostName: stringArg(args, "host_name"), Name: stringArg(args, "name"), TimeoutSec: int32Arg(args, "timeout_sec")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("container stopped", map[string]string{"host_name": stringArg(args, "host_name"), "name": stringArg(args, "name")}, false)
}

func (s *Server) handleEnableBackend(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	out, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.EnableBackend(ctx, &pb.EnableBackendRequest{LbName: stringArg(args, "lb_name"), Backend: stringArg(args, "backend")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("backend enabled", lbDTO(out.(*pb.LoadBalancer)), false)
}

func (s *Server) handleDisableBackend(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	out, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.DisableBackend(ctx, &pb.DisableBackendRequest{LbName: stringArg(args, "lb_name"), Backend: stringArg(args, "backend")})
	})
	if err != nil {
		return s.fail(err)
	}
	return s.ok("backend disabled", lbDTO(out.(*pb.LoadBalancer)), false)
}

func (s *Server) handleDrainBackend(ctx context.Context, args map[string]any) *mcp.CallToolResult {
	if err := requireConfirm(args); err != nil {
		return s.fail(err)
	}
	out, err := s.rpc(ctx, false, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.DrainBackend(ctx, &pb.DrainBackendRequest{LbName: stringArg(args, "lb_name"), Backend: stringArg(args, "backend")})
	})
	if err != nil {
		return s.fail(err)
	}
	resp := out.(*pb.DrainBackendResponse)
	return s.ok("backend draining", map[string]any{"status": resp.GetStatus(), "active_connections": resp.GetActiveConnections()}, false)
}

func requireConfirm(args map[string]any) error {
	if !boolArg(args, "confirm") {
		return status.Error(codes.FailedPrecondition, "confirm must be true for write tools")
	}
	return nil
}

func (s *Server) limit(args map[string]any, key string) int {
	n := intArg(args, key)
	if n <= 0 || n > s.opts.MaxListItems {
		return s.opts.MaxListItems
	}
	return n
}

func stringArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func boolArg(args map[string]any, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func intArg(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

func int32Arg(args map[string]any, key string) int32 {
	return int32(intArg(args, key))
}

func truncate[T any](items []T, limit int) []T {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func emptySchema() map[string]any {
	return objectSchema(nil)
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	out := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func stringSchema(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

func integerSchema(description string) map[string]any {
	return map[string]any{"type": "integer", "description": description, "minimum": 0}
}

func booleanSchema(description string) map[string]any {
	return map[string]any{"type": "boolean", "description": description}
}

func backendWriteSchema() map[string]any {
	return objectSchema(map[string]any{
		"lb_name": stringSchema("Load balancer name."),
		"backend": stringSchema("Backend name."),
		"confirm": booleanSchema("Must be true to execute."),
	}, "lb_name", "backend", "confirm")
}

func stopVMWriteSchema() map[string]any {
	return objectSchema(map[string]any{
		"name":        stringSchema("VM name."),
		"timeout_sec": integerSchema("Graceful stop timeout in seconds."),
		"confirm":     booleanSchema("Must be true to execute."),
	}, "name", "confirm")
}
