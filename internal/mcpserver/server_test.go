package mcpserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fakeLiteVirtClient struct {
	pb.LiteVirtClient

	stopVMCalls int
	stopVMErr   error
	stopVMBlock bool
	stopVMCtx   context.Context

	hostHealth *pb.HostHealthMatrix
	network    *pb.NetworkInfo
	pool       *pb.StoragePool
	lb         *pb.LoadBalancer
	lbStats    *pb.LBStatsResponse
}

func (f *fakeLiteVirtClient) StopVM(ctx context.Context, _ *pb.StopVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	f.stopVMCalls++
	f.stopVMCtx = ctx
	if f.stopVMBlock {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.stopVMErr != nil {
		return nil, f.stopVMErr
	}
	return &pb.VM{Name: "vm1", HostName: "host1", State: pb.VMState_VM_STOPPED}, nil
}

func (f *fakeLiteVirtClient) GetHostHealth(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.HostHealthMatrix, error) {
	if f.hostHealth != nil {
		return f.hostHealth, nil
	}
	return &pb.HostHealthMatrix{}, nil
}

func (f *fakeLiteVirtClient) GetNetwork(context.Context, *pb.GetNetworkRequest, ...grpc.CallOption) (*pb.NetworkInfo, error) {
	if f.network != nil {
		return f.network, nil
	}
	return &pb.NetworkInfo{}, nil
}

func (f *fakeLiteVirtClient) GetStoragePool(context.Context, *pb.GetStoragePoolRequest, ...grpc.CallOption) (*pb.GetStoragePoolResponse, error) {
	if f.pool != nil {
		return &pb.GetStoragePoolResponse{Pool: f.pool}, nil
	}
	return &pb.GetStoragePoolResponse{Pool: &pb.StoragePool{}}, nil
}

func (f *fakeLiteVirtClient) InspectLoadBalancer(context.Context, *pb.InspectLBRequest, ...grpc.CallOption) (*pb.LoadBalancer, error) {
	if f.lb != nil {
		return f.lb, nil
	}
	return &pb.LoadBalancer{}, nil
}

func (f *fakeLiteVirtClient) LBStats(context.Context, *pb.LBStatsRequest, ...grpc.CallOption) (*pb.LBStatsResponse, error) {
	if f.lbStats != nil {
		return f.lbStats, nil
	}
	return &pb.LBStatsResponse{}, nil
}

func testServer(client pb.LiteVirtClient, allowWrite bool) *Server {
	return &Server{
		opts:   normalizeOptions(Options{AllowWrite: allowWrite, Timeout: 10 * time.Millisecond}),
		client: client,
	}
}

func resultEnvelope(t *testing.T, res *mcp.CallToolResult) toolEnvelope {
	t.Helper()
	if res == nil {
		t.Fatal("nil tool result")
	}
	if env, ok := res.StructuredContent.(toolEnvelope); ok {
		return env
	}
	if len(res.Content) == 0 {
		t.Fatal("tool result has no content")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *mcp.TextContent", res.Content[0])
	}
	var env toolEnvelope
	if err := json.Unmarshal([]byte(text.Text), &env); err != nil {
		t.Fatalf("decode tool envelope: %v", err)
	}
	return env
}

func TestStopVMRequiresConfirmBeforeRPC(t *testing.T) {
	fake := &fakeLiteVirtClient{}
	s := testServer(fake, true)
	res := s.handleStopVM(context.Background(), map[string]any{"name": "vm1"})
	if !res.IsError {
		t.Fatal("stop without confirm succeeded")
	}
	env := resultEnvelope(t, res)
	if env.Error == nil || env.Error.Code != codes.FailedPrecondition.String() {
		t.Fatalf("error = %#v, want FailedPrecondition", env.Error)
	}
	if fake.stopVMCalls != 0 {
		t.Fatalf("StopVM calls = %d, want 0", fake.stopVMCalls)
	}
}

func TestWriteUnavailableDoesNotReconnectOrRetry(t *testing.T) {
	fake := &fakeLiteVirtClient{stopVMErr: status.Error(codes.Unavailable, "mid-call")}
	reconnects := 0
	s := &Server{
		opts: normalizeOptions(Options{
			AllowWrite: true,
			Timeout:    10 * time.Millisecond,
			Connect: func(context.Context) (pb.LiteVirtClient, func(), error) {
				reconnects++
				return fake, func() {}, nil
			},
		}),
		client: fake,
	}
	res := s.handleStopVM(context.Background(), map[string]any{"name": "vm1", "confirm": true})
	if !res.IsError {
		t.Fatal("stop with Unavailable succeeded")
	}
	env := resultEnvelope(t, res)
	if env.Error == nil || env.Error.Code != codes.Unavailable.String() {
		t.Fatalf("error = %#v, want Unavailable", env.Error)
	}
	if fake.stopVMCalls != 1 {
		t.Fatalf("StopVM calls = %d, want 1", fake.stopVMCalls)
	}
	if reconnects != 0 {
		t.Fatalf("reconnects = %d, want 0", reconnects)
	}
}

func TestHandlerGRPCErrorBecomesStructuredToolError(t *testing.T) {
	fake := &fakeLiteVirtClient{stopVMErr: status.Error(codes.PermissionDenied, "nope")}
	s := testServer(fake, true)
	res := s.handleStopVM(context.Background(), map[string]any{"name": "vm1", "confirm": true})
	if !res.IsError {
		t.Fatal("permission denied result was not marked as error")
	}
	env := resultEnvelope(t, res)
	if env.Error == nil || env.Error.Code != codes.PermissionDenied.String() {
		t.Fatalf("error = %#v, want PermissionDenied", env.Error)
	}
}

func TestRPCTimeoutReachesClientContext(t *testing.T) {
	fake := &fakeLiteVirtClient{stopVMBlock: true}
	s := testServer(fake, true)
	res := s.handleStopVM(context.Background(), map[string]any{"name": "vm1", "confirm": true})
	if !res.IsError {
		t.Fatal("timeout result was not marked as error")
	}
	env := resultEnvelope(t, res)
	if env.Error == nil || env.Error.Code != codes.DeadlineExceeded.String() {
		t.Fatalf("error = %#v, want DeadlineExceeded", env.Error)
	}
	if fake.stopVMCtx == nil || fake.stopVMCtx.Err() == nil {
		t.Fatalf("client context was not canceled by timeout: %#v", fake.stopVMCtx)
	}
}

func TestRegisteredToolsReadOnlyByDefaultAndWritesOnlyWhenAllowed(t *testing.T) {
	readOnly := testServer(&fakeLiteVirtClient{}, false)
	readOnly.registerTools(mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil))
	writeEnabled := testServer(&fakeLiteVirtClient{}, true)
	writeEnabled.registerTools(mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil))

	readTools := []string{
		"litevirt_ping", "litevirt_whoami", "litevirt_cluster_status", "litevirt_list_hosts", "litevirt_inspect_host",
		"litevirt_host_stats", "litevirt_host_health", "litevirt_list_vms", "litevirt_inspect_vm", "litevirt_vm_stats",
		"litevirt_list_vm_events", "litevirt_list_containers", "litevirt_list_networks", "litevirt_get_network",
		"litevirt_list_storage_pools", "litevirt_get_storage_pool", "litevirt_list_load_balancers", "litevirt_inspect_lb",
		"litevirt_lb_stats", "litevirt_list_audit_log", "litevirt_list_rebalance_proposals", "litevirt_list_projects",
		"litevirt_get_project_quota", "litevirt_get_project_usage",
	}
	writeTools := []string{
		"litevirt_start_vm", "litevirt_stop_vm", "litevirt_restart_vm", "litevirt_start_container", "litevirt_stop_container",
		"litevirt_enable_backend", "litevirt_disable_backend", "litevirt_drain_backend",
	}
	if !reflect.DeepEqual(readOnly.toolNames, readTools) {
		t.Fatalf("read-only tools mismatch\n got: %#v\nwant: %#v", readOnly.toolNames, readTools)
	}
	wantWriteEnabled := append(append([]string{}, readTools...), writeTools...)
	if !reflect.DeepEqual(writeEnabled.toolNames, wantWriteEnabled) {
		t.Fatalf("write-enabled tools mismatch\n got: %#v\nwant: %#v", writeEnabled.toolNames, wantWriteEnabled)
	}
}

func TestHostHealthDTO(t *testing.T) {
	matrix := &pb.HostHealthMatrix{Entries: []*pb.HostHealthEntry{{
		Observer:            "h1",
		Target:              "h2",
		Status:              "unhealthy",
		ConsecutiveFailures: 3,
	}}}
	dto := hostHealthDTO(matrix)
	if len(dto.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(dto.Entries))
	}
	if got := dto.Entries[0]; got.Observer != "h1" || got.Target != "h2" || got.Status != "unhealthy" || got.ConsecutiveFailures != 3 {
		t.Fatalf("entry = %#v", got)
	}
}

func TestHostHealthHandlerUsesDTO(t *testing.T) {
	fake := &fakeLiteVirtClient{hostHealth: &pb.HostHealthMatrix{Entries: []*pb.HostHealthEntry{{
		Observer: "h1",
		Target:   "h2",
		Status:   "healthy",
	}}}}
	s := testServer(fake, false)
	res := s.handleHostHealth(context.Background(), nil)
	if res.IsError {
		t.Fatalf("host health failed: %#v", resultEnvelope(t, res).Error)
	}
	env := resultEnvelope(t, res)
	if _, ok := env.Data.(hostHealthOut); !ok {
		t.Fatalf("host health data type = %T, want hostHealthOut", env.Data)
	}
}

func TestAddedReadHandlersUseDTOs(t *testing.T) {
	fake := &fakeLiteVirtClient{
		network: &pb.NetworkInfo{Name: "net-a", Project: "project-a"},
		pool:    &pb.StoragePool{Name: "pool-a", Host: "host-a", Project: "project-a", Driver: "dir"},
		lb:      &pb.LoadBalancer{Name: "lb-a", Vip: "10.0.0.10/24", State: "active"},
		lbStats: &pb.LBStatsResponse{
			Name: "lb-a",
			Frontends: []*pb.LBFrontendStats{{
				ListenPort:      443,
				CurrentSessions: 2,
			}},
			Backends: []*pb.LBBackendStats{{
				Name:            "vm1",
				Status:          "UP",
				CurrentSessions: 1,
				Response_2Xx:    12,
			}},
		},
	}
	s := testServer(fake, false)

	for _, tc := range []struct {
		name string
		res  *mcp.CallToolResult
		want any
	}{
		{"get_network", s.handleGetNetwork(context.Background(), map[string]any{"name": "net-a"}), networkOut{}},
		{"get_storage_pool", s.handleGetStoragePool(context.Background(), map[string]any{"name": "pool-a"}), poolOut{}},
		{"inspect_lb", s.handleInspectLB(context.Background(), map[string]any{"name": "lb-a"}), lbOut{}},
		{"lb_stats", s.handleLBStats(context.Background(), map[string]any{"name": "lb-a"}), lbStatsOut{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.res.IsError {
				t.Fatalf("%s failed: %#v", tc.name, resultEnvelope(t, tc.res).Error)
			}
			env := resultEnvelope(t, tc.res)
			if reflect.TypeOf(env.Data) != reflect.TypeOf(tc.want) {
				t.Fatalf("%s data type = %T, want %T", tc.name, env.Data, tc.want)
			}
		})
	}
}

func TestStopVMSchemaRejectsForce(t *testing.T) {
	err := validateArgs(map[string]any{"name": "vm1", "confirm": true, "force": true}, stopVMWriteSchema())
	if err == nil {
		t.Fatal("force argument accepted for stop_vm")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
}
