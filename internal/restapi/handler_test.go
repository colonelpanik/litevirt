package restapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// mockGRPC implements pb.LiteVirtClient for testing.
type mockGRPC struct {
	// Embed the client interface so RPCs the mock doesn't exercise (e.g. the
	// firewall management calls) are satisfied without a hand-written stub.
	pb.LiteVirtClient

	pingResp        *pb.PingResponse
	listHostsResp   *pb.ListHostsResponse
	inspectHostResp *pb.Host
	listVMsResp     *pb.ListVMsResponse
	inspectVMResp   *pb.VM
	listStacksResp  *pb.ListStacksResponse
	startVMResp     *pb.VM
	stopVMResp      *pb.VM
	restartVMResp   *pb.VM

	// Host action responses
	undrainHostResp     *pb.Host
	fenceHostResp       *pb.FenceResult
	listHostDevicesResp *pb.ListHostDevicesResponse
	hostStatsResp       *pb.HostResourceStats
	configureHostResp   *pb.Host

	// VM action responses
	createVMResp *pb.VM
	updateVMResp *pb.VM
	vmStatsResp  *pb.VMStats
	execVMResp   *pb.ExecVMResponse
	setVMIPResp  *pb.VM

	// Images, Users, Status, Audit, Login
	listImagesResp    *pb.ListImagesResponse
	listUsersResp     *pb.ListUsersResponse
	clusterStatusResp *pb.ClusterStatus
	auditLogResp      *pb.ListAuditLogResponse
	loginResp         *pb.LoginResponse

	// LB & Network responses
	listLBsResp        *pb.ListLBResponse
	inspectLBResp      *pb.LoadBalancer
	createLBResp       *pb.LoadBalancer
	updateLBResp       *pb.LoadBalancer
	lbStatsResp        *pb.LBStatsResponse
	drainBackendResp   *pb.DrainBackendResponse
	disableBackendResp *pb.LoadBalancer
	enableBackendResp  *pb.LoadBalancer
	listNetworksResp   *pb.ListNetworksResponse
	getNetworkResp     *pb.NetworkInfo
	createNetworkResp  *pb.NetworkInfo

	// Track calls
	lastListVMsReq       *pb.ListVMsRequest
	lastInspectVMName    string
	lastInspectHostName  string
	lastStartVMName      string
	lastStopVMName       string
	lastStopVMReq        *pb.StopVMRequest
	lastRemoveHostReq    *pb.RemoveHostRequest
	lastRestartVMName    string
	lastDeleteVMName     string
	deleteVMCalled       bool
	lastInspectLBName    string
	lastUpdateLBReq      *pb.UpdateLBRequest
	lastDeleteLBName     string
	deleteLBCalled       bool
	lastLBStatsName      string
	lastDrainReq         *pb.DrainBackendRequest
	lastDisableReq       *pb.DisableBackendRequest
	lastEnableReq        *pb.EnableBackendRequest
	lastGetNetworkName   string
	lastDeleteNetworkReq *pb.DeleteNetworkRequest
	deleteNetworkCalled  bool
	lastCreateNetworkReq *pb.CreateNetworkRequest
	lastCreateLBReq      *pb.CreateLBRequest

	// Host action tracking
	lastDrainHostName    string
	lastUndrainHostName  string
	lastSetLabelsReq     *pb.SetHostLabelsRequest
	lastFenceHostReq     *pb.FenceHostRequest
	removeHostCalled     bool
	lastRemoveHostName   string
	lastListDevicesHost  string
	lastHostStatsName    string
	lastConfigureHostReq *pb.ConfigureHostRequest

	// VM action tracking
	lastCreateVMReq *pb.CreateVMRequest
	lastUpdateVMReq *pb.UpdateVMRequest
	lastVMStatsName string
	lastExecVMReq   *pb.ExecVMRequest
	lastSetVMIPReq  *pb.SetVMIPRequest

	// Image/User/Auth tracking
	lastDeleteImageName string
	deleteImageCalled   bool
	lastDeleteUserName  string
	deleteUserCalled    bool
	lastLoginReq        *pb.LoginRequest
	lastAuditLimit      int32

	// Snapshot tracking
	lastCreateSnapshotReq  *pb.CreateSnapshotRequest
	lastListSnapshotsReq   *pb.ListSnapshotsRequest
	lastRestoreSnapshotReq *pb.RestoreSnapshotRequest
	lastDeleteSnapshotReq  *pb.DeleteSnapshotRequest
	deleteSnapshotCalled   bool

	// Additional VM action tracking
	lastAttachDeviceReq *pb.AttachDeviceRequest
	lastDetachDeviceReq *pb.DetachDeviceRequest
	lastResizeDiskReq   *pb.ResizeDiskRequest
	lastRebuildVMReq    *pb.RebuildVMRequest

	// User/Token creation tracking
	lastCreateUserReq  *pb.CreateUserRequest
	createUserResp     *pb.User
	lastCreateTokenReq *pb.CreateTokenRequest
	createTokenResp    *pb.Token
	lastRevokeTokenID  string
	revokeTokenCalled  bool

	// Rescan tracking
	lastRescanHostName string
}

func (m *mockGRPC) Ping(ctx context.Context, in *pb.PingRequest, opts ...grpc.CallOption) (*pb.PingResponse, error) {
	return m.pingResp, nil
}
func (m *mockGRPC) ListHosts(ctx context.Context, in *pb.ListHostsRequest, opts ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return m.listHostsResp, nil
}
func (m *mockGRPC) InspectHost(ctx context.Context, in *pb.InspectHostRequest, opts ...grpc.CallOption) (*pb.Host, error) {
	m.lastInspectHostName = in.Name
	return m.inspectHostResp, nil
}
func (m *mockGRPC) ListVMs(ctx context.Context, in *pb.ListVMsRequest, opts ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	m.lastListVMsReq = in
	return m.listVMsResp, nil
}
func (m *mockGRPC) InspectVM(ctx context.Context, in *pb.InspectVMRequest, opts ...grpc.CallOption) (*pb.VM, error) {
	m.lastInspectVMName = in.Name
	return m.inspectVMResp, nil
}
func (m *mockGRPC) StartVM(ctx context.Context, in *pb.StartVMRequest, opts ...grpc.CallOption) (*pb.VM, error) {
	m.lastStartVMName = in.Name
	return m.startVMResp, nil
}
func (m *mockGRPC) StopVM(ctx context.Context, in *pb.StopVMRequest, opts ...grpc.CallOption) (*pb.VM, error) {
	m.lastStopVMName = in.Name
	m.lastStopVMReq = in
	return m.stopVMResp, nil
}
func (m *mockGRPC) RestartVM(ctx context.Context, in *pb.RestartVMRequest, opts ...grpc.CallOption) (*pb.VM, error) {
	m.lastRestartVMName = in.Name
	return m.restartVMResp, nil
}
func (m *mockGRPC) DeleteVM(ctx context.Context, in *pb.DeleteVMRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteVMName = in.Name
	m.deleteVMCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CloneVM(_ context.Context, in *pb.CloneVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Target}, nil
}
func (m *mockGRPC) ConvertToTemplate(_ context.Context, in *pb.ConvertToTemplateRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, IsTemplate: !in.Revert}, nil
}
func (m *mockGRPC) ListStacks(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.ListStacksResponse, error) {
	return m.listStacksResp, nil
}

// Stub out remaining interface methods.
func (m *mockGRPC) CreateVM(_ context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastCreateVMReq = in
	return m.createVMResp, nil
}
func (m *mockGRPC) ExecVM(_ context.Context, in *pb.ExecVMRequest, _ ...grpc.CallOption) (*pb.ExecVMResponse, error) {
	m.lastExecVMReq = in
	return m.execVMResp, nil
}
func (m *mockGRPC) DrainHost(_ context.Context, in *pb.DrainHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DrainProgress], error) {
	m.lastDrainHostName = in.Name
	return nil, nil
}
func (m *mockGRPC) UndrainHost(_ context.Context, in *pb.UndrainHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.lastUndrainHostName = in.Name
	return m.undrainHostResp, nil
}
func (m *mockGRPC) SetHostLabels(_ context.Context, in *pb.SetHostLabelsRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.lastSetLabelsReq = in
	return &pb.Host{Name: in.Name, Labels: in.Labels}, nil
}
func (m *mockGRPC) FenceHost(_ context.Context, in *pb.FenceHostRequest, _ ...grpc.CallOption) (*pb.FenceResult, error) {
	m.lastFenceHostReq = in
	return m.fenceHostResp, nil
}
func (m *mockGRPC) GetHostHealth(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.HostHealthMatrix, error) {
	return &pb.HostHealthMatrix{}, nil
}
func (m *mockGRPC) RemoveHost(_ context.Context, in *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastRemoveHostName = in.Name
	m.lastRemoveHostReq = in
	m.removeHostCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) RescanHost(_ context.Context, in *pb.RescanHostRequest, _ ...grpc.CallOption) (*pb.RescanHostResponse, error) {
	m.lastRescanHostName = in.Name
	return &pb.RescanHostResponse{}, nil
}
func (m *mockGRPC) ListHostDevices(_ context.Context, in *pb.ListHostDevicesRequest, _ ...grpc.CallOption) (*pb.ListHostDevicesResponse, error) {
	m.lastListDevicesHost = in.Name
	return m.listHostDevicesResp, nil
}
func (m *mockGRPC) ConfigureHost(_ context.Context, in *pb.ConfigureHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.lastConfigureHostReq = in
	return m.configureHostResp, nil
}
func (m *mockGRPC) ConsoleVM(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[pb.ConsoleInput, pb.ConsoleOutput], error) {
	return nil, nil
}
func (m *mockGRPC) SetVMIP(_ context.Context, in *pb.SetVMIPRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastSetVMIPReq = in
	return m.setVMIPResp, nil
}
func (m *mockGRPC) SetBootOrder(context.Context, *pb.SetBootOrderRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, nil
}
func (m *mockGRPC) RebuildVM(_ context.Context, in *pb.RebuildVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastRebuildVMReq = in
	return &pb.VM{Name: in.Name}, nil
}
func (m *mockGRPC) CutoverVM(context.Context, *pb.CutoverVMRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, nil
}
func (m *mockGRPC) AttachDevice(_ context.Context, in *pb.AttachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastAttachDeviceReq = in
	return &pb.VM{Name: in.VmName}, nil
}
func (m *mockGRPC) DetachDevice(_ context.Context, in *pb.DetachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastDetachDeviceReq = in
	return &pb.VM{Name: in.VmName}, nil
}
func (m *mockGRPC) ResizeDisk(_ context.Context, in *pb.ResizeDiskRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastResizeDiskReq = in
	return &pb.VM{Name: in.VmName}, nil
}
func (m *mockGRPC) DeployStack(context.Context, *pb.DeployStackRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	return nil, nil
}
func (m *mockGRPC) DeleteStack(context.Context, *pb.DeleteStackRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeleteProgress], error) {
	return nil, nil
}
func (m *mockGRPC) DiffStack(context.Context, *pb.DiffStackRequest, ...grpc.CallOption) (*pb.DiffStackResponse, error) {
	return nil, nil
}
func (m *mockGRPC) PullImage(context.Context, *pb.PullImageRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PullProgress], error) {
	return nil, nil
}
func (m *mockGRPC) DeleteImage(_ context.Context, in *pb.DeleteImageRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteImageName = in.Name
	m.deleteImageCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) MigrateVM(context.Context, *pb.MigrateVMRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	return nil, nil
}
func (m *mockGRPC) CreateSnapshot(_ context.Context, in *pb.CreateSnapshotRequest, _ ...grpc.CallOption) (*pb.Snapshot, error) {
	m.lastCreateSnapshotReq = in
	return &pb.Snapshot{VmName: in.VmName, Name: in.Name}, nil
}
func (m *mockGRPC) SetVMMemory(_ context.Context, in *pb.SetVMMemoryRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name}, nil
}
func (m *mockGRPC) CreateResourceMapping(_ context.Context, in *pb.CreateResourceMappingRequest, _ ...grpc.CallOption) (*pb.ResourceMapping, error) {
	return &pb.ResourceMapping{Name: in.Name, Description: in.Description}, nil
}
func (m *mockGRPC) ListResourceMappings(_ context.Context, _ *pb.ListResourceMappingsRequest, _ ...grpc.CallOption) (*pb.ListResourceMappingsResponse, error) {
	return &pb.ListResourceMappingsResponse{}, nil
}
func (m *mockGRPC) DeleteResourceMapping(_ context.Context, _ *pb.DeleteResourceMappingRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) AddMappingDevice(_ context.Context, in *pb.AddMappingDeviceRequest, _ ...grpc.CallOption) (*pb.ResourceMapping, error) {
	return &pb.ResourceMapping{Name: in.Mapping}, nil
}
func (m *mockGRPC) RemoveMappingDevice(_ context.Context, in *pb.RemoveMappingDeviceRequest, _ ...grpc.CallOption) (*pb.ResourceMapping, error) {
	return &pb.ResourceMapping{Name: in.Mapping}, nil
}
func (m *mockGRPC) ListSnapshots(_ context.Context, in *pb.ListSnapshotsRequest, _ ...grpc.CallOption) (*pb.ListSnapshotsResponse, error) {
	m.lastListSnapshotsReq = in
	return &pb.ListSnapshotsResponse{}, nil
}
func (m *mockGRPC) RestoreSnapshot(_ context.Context, in *pb.RestoreSnapshotRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastRestoreSnapshotReq = in
	return &pb.VM{Name: in.VmName}, nil
}
func (m *mockGRPC) DeleteSnapshot(_ context.Context, in *pb.DeleteSnapshotRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteSnapshotReq = in
	m.deleteSnapshotCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) ListLoadBalancers(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListLBResponse, error) {
	return m.listLBsResp, nil
}
func (m *mockGRPC) InspectLoadBalancer(_ context.Context, in *pb.InspectLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	m.lastInspectLBName = in.Name
	return m.inspectLBResp, nil
}
func (m *mockGRPC) DisableBackend(_ context.Context, in *pb.DisableBackendRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	m.lastDisableReq = in
	return m.disableBackendResp, nil
}
func (m *mockGRPC) EnableBackend(_ context.Context, in *pb.EnableBackendRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	m.lastEnableReq = in
	return m.enableBackendResp, nil
}
func (m *mockGRPC) ApplyLB(context.Context, *pb.ApplyLBRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) RemoveLB(context.Context, *pb.RemoveLBRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) CreateUser(_ context.Context, in *pb.CreateUserRequest, _ ...grpc.CallOption) (*pb.User, error) {
	m.lastCreateUserReq = in
	if m.createUserResp != nil {
		return m.createUserResp, nil
	}
	return &pb.User{Username: in.Username, Role: in.Role}, nil
}
func (m *mockGRPC) ListUsers(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListUsersResponse, error) {
	return m.listUsersResp, nil
}
func (m *mockGRPC) DeleteUser(_ context.Context, in *pb.DeleteUserRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteUserName = in.Username
	m.deleteUserCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CreateToken(_ context.Context, in *pb.CreateTokenRequest, _ ...grpc.CallOption) (*pb.Token, error) {
	m.lastCreateTokenReq = in
	if m.createTokenResp != nil {
		return m.createTokenResp, nil
	}
	return &pb.Token{Id: "tok-123", Name: in.Name}, nil
}
func (m *mockGRPC) RevokeToken(_ context.Context, in *pb.RevokeTokenRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastRevokeTokenID = in.Id
	m.revokeTokenCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) Logout(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) Whoami(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.WhoamiResponse, error) {
	return &pb.WhoamiResponse{Username: "admin", Role: "admin", Realm: "local"}, nil
}
func (m *mockGRPC) ChangePassword(context.Context, *pb.ChangePasswordRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) ListSessions(context.Context, *pb.ListSessionsRequest, ...grpc.CallOption) (*pb.ListSessionsResponse, error) {
	return &pb.ListSessionsResponse{}, nil
}
func (m *mockGRPC) RevokeSession(context.Context, *pb.RevokeSessionRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) ListTwoFactors(context.Context, *pb.ListTwoFactorsRequest, ...grpc.CallOption) (*pb.ListTwoFactorsResponse, error) {
	return &pb.ListTwoFactorsResponse{}, nil
}
func (m *mockGRPC) EnrollTOTP(context.Context, *pb.EnrollTOTPRequest, ...grpc.CallOption) (*pb.EnrollTOTPResponse, error) {
	return &pb.EnrollTOTPResponse{}, nil
}
func (m *mockGRPC) DisableTwoFactor(context.Context, *pb.DisableTwoFactorRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) MoveVolume(context.Context, *pb.MoveVolumeRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MoveVolumeProgress], error) {
	return nil, nil
}
func (m *mockGRPC) ReplicateVolume(context.Context, *pb.ReplicateVolumeRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ReplicateVolumeProgress], error) {
	return nil, nil
}
func (m *mockGRPC) MigrateStackVolumes(context.Context, *pb.MigrateStackVolumesRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StackVolumeProgress], error) {
	return nil, nil
}
func (m *mockGRPC) GetClusterStatus(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ClusterStatus, error) {
	return m.clusterStatusResp, nil
}
func (m *mockGRPC) StreamEvents(context.Context, *pb.StreamEventsRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ClusterEvent], error) {
	return nil, nil
}
func (m *mockGRPC) ImportImage(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ImportImageRequest, pb.ImportImageResponse], error) {
	return nil, nil
}
func (m *mockGRPC) PushImage(context.Context, *pb.PushImageRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PushImageProgress], error) {
	return nil, nil
}
func (m *mockGRPC) BuildImage(context.Context, *pb.BuildImageRequest, ...grpc.CallOption) (*pb.BuildImageResponse, error) {
	return nil, nil
}
func (m *mockGRPC) BackupVM(context.Context, *pb.BackupVMRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.BackupChunk], error) {
	return nil, nil
}
func (m *mockGRPC) RestoreVM(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.RestoreVMRequest, pb.VM], error) {
	return nil, nil
}
func (m *mockGRPC) ListImages(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListImagesResponse, error) {
	return m.listImagesResp, nil
}
func (m *mockGRPC) Login(_ context.Context, in *pb.LoginRequest, _ ...grpc.CallOption) (*pb.LoginResponse, error) {
	m.lastLoginReq = in
	return m.loginResp, nil
}
func (m *mockGRPC) ListRealms(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListRealmsResponse, error) {
	return &pb.ListRealmsResponse{Realms: []string{"local"}}, nil
}
func (m *mockGRPC) BindSecurityGroups(context.Context, *pb.BindSecurityGroupsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) ReloadFirewall(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.FirewallStatus, error) {
	return &pb.FirewallStatus{}, nil
}
func (m *mockGRPC) CreateContainer(context.Context, *pb.CreateContainerRequest, ...grpc.CallOption) (*pb.Container, error) {
	return &pb.Container{}, nil
}
func (m *mockGRPC) StartContainer(context.Context, *pb.StartContainerRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) StopContainer(context.Context, *pb.StopContainerRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) DeleteContainer(context.Context, *pb.DeleteContainerRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) ExecContainer(context.Context, *pb.ExecContainerRequest, ...grpc.CallOption) (*pb.ExecContainerResponse, error) {
	return &pb.ExecContainerResponse{}, nil
}
func (m *mockGRPC) ListContainers(context.Context, *pb.ListContainersRequest, ...grpc.CallOption) (*pb.ListContainersResponse, error) {
	return &pb.ListContainersResponse{}, nil
}
func (m *mockGRPC) PullOCIImage(context.Context, *pb.PullOCIImageRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) BackupSnapshot(context.Context, *pb.BackupSnapshotRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.BackupSnapshotProgress], error) {
	return nil, nil
}
func (m *mockGRPC) RestoreFromBackup(context.Context, *pb.RestoreFromBackupRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreFromBackupProgress], error) {
	return nil, nil
}
func (m *mockGRPC) RestoreLive(context.Context, *pb.RestoreLiveRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreLiveProgress], error) {
	return nil, nil
}
func (m *mockGRPC) GrantRole(context.Context, *pb.GrantRoleRequest, ...grpc.CallOption) (*pb.GrantRoleResponse, error) {
	return &pb.GrantRoleResponse{Binding: &pb.RoleBinding{}}, nil
}
func (m *mockGRPC) RevokeRole(context.Context, *pb.RevokeRoleRequest, ...grpc.CallOption) (*pb.RevokeRoleResponse, error) {
	return &pb.RevokeRoleResponse{}, nil
}
func (m *mockGRPC) ListRoleBindings(context.Context, *pb.ListRoleBindingsRequest, ...grpc.CallOption) (*pb.ListRoleBindingsResponse, error) {
	return &pb.ListRoleBindingsResponse{}, nil
}
func (m *mockGRPC) BeginWebAuthnRegistration(context.Context, *pb.BeginWebAuthnRegistrationRequest, ...grpc.CallOption) (*pb.BeginWebAuthnRegistrationResponse, error) {
	return &pb.BeginWebAuthnRegistrationResponse{}, nil
}
func (m *mockGRPC) FinishWebAuthnRegistration(context.Context, *pb.FinishWebAuthnRegistrationRequest, ...grpc.CallOption) (*pb.FinishWebAuthnRegistrationResponse, error) {
	return &pb.FinishWebAuthnRegistrationResponse{}, nil
}
func (m *mockGRPC) BeginWebAuthnLogin(context.Context, *pb.BeginWebAuthnLoginRequest, ...grpc.CallOption) (*pb.BeginWebAuthnLoginResponse, error) {
	return &pb.BeginWebAuthnLoginResponse{}, nil
}
func (m *mockGRPC) FinishWebAuthnLogin(context.Context, *pb.FinishWebAuthnLoginRequest, ...grpc.CallOption) (*pb.FinishWebAuthnLoginResponse, error) {
	return &pb.FinishWebAuthnLoginResponse{}, nil
}
func (m *mockGRPC) CreateStoragePool(context.Context, *pb.CreateStoragePoolRequest, ...grpc.CallOption) (*pb.CreateStoragePoolResponse, error) {
	return &pb.CreateStoragePoolResponse{Pool: &pb.StoragePool{}}, nil
}
func (m *mockGRPC) DeleteStoragePool(context.Context, *pb.DeleteStoragePoolRequest, ...grpc.CallOption) (*pb.DeleteStoragePoolResponse, error) {
	return &pb.DeleteStoragePoolResponse{}, nil
}
func (m *mockGRPC) GetStoragePool(context.Context, *pb.GetStoragePoolRequest, ...grpc.CallOption) (*pb.GetStoragePoolResponse, error) {
	return &pb.GetStoragePoolResponse{Pool: &pb.StoragePool{}}, nil
}
func (m *mockGRPC) GetVMStats(_ context.Context, in *pb.GetVMStatsRequest, _ ...grpc.CallOption) (*pb.VMStats, error) {
	m.lastVMStatsName = in.Name
	return m.vmStatsResp, nil
}
func (m *mockGRPC) GetHostStats(_ context.Context, in *pb.GetHostStatsRequest, _ ...grpc.CallOption) (*pb.HostResourceStats, error) {
	m.lastHostStatsName = in.Name
	return m.hostStatsResp, nil
}
func (m *mockGRPC) ListNetworks(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListNetworksResponse, error) {
	return m.listNetworksResp, nil
}
func (m *mockGRPC) CreateNetwork(_ context.Context, in *pb.CreateNetworkRequest, _ ...grpc.CallOption) (*pb.NetworkInfo, error) {
	m.lastCreateNetworkReq = in
	return m.createNetworkResp, nil
}
func (m *mockGRPC) GetNetwork(_ context.Context, in *pb.GetNetworkRequest, _ ...grpc.CallOption) (*pb.NetworkInfo, error) {
	m.lastGetNetworkName = in.Name
	return m.getNetworkResp, nil
}
func (m *mockGRPC) DeleteNetwork(_ context.Context, in *pb.DeleteNetworkRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteNetworkReq = in
	m.deleteNetworkCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) ListAuditLog(_ context.Context, in *pb.ListAuditLogRequest, _ ...grpc.CallOption) (*pb.ListAuditLogResponse, error) {
	m.lastAuditLimit = in.Limit
	return m.auditLogResp, nil
}
func (m *mockGRPC) ListVMEvents(_ context.Context, _ *pb.ListVMEventsRequest, _ ...grpc.CallOption) (*pb.ListVMEventsResponse, error) {
	return &pb.ListVMEventsResponse{}, nil
}
func (m *mockGRPC) ProxyVNC(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[pb.VNCData, pb.VNCData], error) {
	return nil, nil
}
func (m *mockGRPC) UpdateVM(_ context.Context, in *pb.UpdateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastUpdateVMReq = in
	return m.updateVMResp, nil
}
func (m *mockGRPC) SetVMLabels(_ context.Context, in *pb.SetVMLabelsRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name}, nil
}
func (m *mockGRPC) ProvisionNetwork(context.Context, *pb.ProvisionNetworkRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) SyncVTEP(context.Context, *pb.SyncVTEPRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) GetVMIPRemote(context.Context, *pb.GetVMIPRequest, ...grpc.CallOption) (*pb.GetVMIPResponse, error) {
	return nil, nil
}
func (m *mockGRPC) RefreshLB(context.Context, *pb.RefreshLBRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) UpdateFDB(context.Context, *pb.UpdateFDBRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) GetStateDigest(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return &pb.StateDigestResponse{HostName: "test-host"}, nil
}
func (m *mockGRPC) GetStateDump(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDumpResponse, error) {
	return &pb.StateDumpResponse{}, nil
}
func (m *mockGRPC) PushMutations(context.Context, *pb.ReplicateRequest, ...grpc.CallOption) (*pb.ReplicateResponse, error) {
	return &pb.ReplicateResponse{}, nil
}
func (m *mockGRPC) AckMutations(context.Context, *pb.AckRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CreateLoadBalancer(_ context.Context, in *pb.CreateLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	m.lastCreateLBReq = in
	return m.createLBResp, nil
}
func (m *mockGRPC) UpdateLoadBalancer(_ context.Context, in *pb.UpdateLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	m.lastUpdateLBReq = in
	return m.updateLBResp, nil
}
func (m *mockGRPC) DeleteLoadBalancer(_ context.Context, in *pb.DeleteLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteLBName = in.Name
	m.deleteLBCalled = true
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) DrainBackend(_ context.Context, in *pb.DrainBackendRequest, _ ...grpc.CallOption) (*pb.DrainBackendResponse, error) {
	m.lastDrainReq = in
	return m.drainBackendResp, nil
}
func (m *mockGRPC) LBStats(_ context.Context, in *pb.LBStatsRequest, _ ...grpc.CallOption) (*pb.LBStatsResponse, error) {
	m.lastLBStatsName = in.Name
	return m.lbStatsResp, nil
}
func (m *mockGRPC) EnsureCloudInit(context.Context, *pb.EnsureCloudInitRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) EnsureDisks(context.Context, *pb.EnsureDisksRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) GetVMLogs(context.Context, *pb.GetVMLogsRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.VMLogChunk], error) {
	return nil, nil
}
func (m *mockGRPC) UpgradeHost(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	return nil, nil
}
func (m *mockGRPC) PreStageUpgrade(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	return nil, nil
}
func (m *mockGRPC) FetchBinary(context.Context, *pb.FetchBinaryRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.FetchBinaryChunk], error) {
	return nil, nil
}
func (m *mockGRPC) UninstallHost(context.Context, *pb.UninstallHostRequest, ...grpc.CallOption) (*pb.UninstallHostResponse, error) {
	return &pb.UninstallHostResponse{}, nil
}
func (m *mockGRPC) ExportStack(context.Context, *pb.ExportStackRequest, ...grpc.CallOption) (*pb.ExportStackResponse, error) {
	return &pb.ExportStackResponse{}, nil
}
func (m *mockGRPC) ListStoragePools(context.Context, *pb.ListStoragePoolsRequest, ...grpc.CallOption) (*pb.ListStoragePoolsResponse, error) {
	return &pb.ListStoragePoolsResponse{}, nil
}
func (m *mockGRPC) ListStoragePoolContents(context.Context, *pb.ListStoragePoolContentsRequest, ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	return &pb.ListStoragePoolContentsResponse{}, nil
}
func (m *mockGRPC) UploadStoragePoolContent(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	return nil, nil
}
func (m *mockGRPC) DeleteStoragePoolContent(context.Context, *pb.DeleteStoragePoolContentRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	return nil, nil
}
func (m *mockGRPC) PromoteReplica(context.Context, *pb.PromoteReplicaRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PromoteReplicaProgress], error) {
	return nil, nil
}

func (m *mockGRPC) ListRebalanceProposals(context.Context, *pb.ListRebalanceProposalsRequest, ...grpc.CallOption) (*pb.ListRebalanceProposalsResponse, error) {
	return &pb.ListRebalanceProposalsResponse{}, nil
}
func (m *mockGRPC) RunRebalance(context.Context, *pb.RunRebalanceRequest, ...grpc.CallOption) (*pb.RunRebalanceResponse, error) {
	return &pb.RunRebalanceResponse{}, nil
}
func (m *mockGRPC) ApproveRebalanceProposal(context.Context, *pb.ApproveRebalanceProposalRequest, ...grpc.CallOption) (*pb.RebalanceProposal, error) {
	return &pb.RebalanceProposal{}, nil
}
func (m *mockGRPC) RejectRebalanceProposal(context.Context, *pb.RejectRebalanceProposalRequest, ...grpc.CallOption) (*pb.RebalanceProposal, error) {
	return &pb.RebalanceProposal{}, nil
}
func (m *mockGRPC) GetSpiceInfo(context.Context, *pb.GetSpiceInfoRequest, ...grpc.CallOption) (*pb.GetSpiceInfoResponse, error) {
	return &pb.GetSpiceInfoResponse{}, nil
}
func (m *mockGRPC) PreflightUpgrade(context.Context, *pb.PreflightUpgradeRequest, ...grpc.CallOption) (*pb.PreflightUpgradeResponse, error) {
	return &pb.PreflightUpgradeResponse{Ok: true}, nil
}

func newMockServer(token string) (*Server, *mockGRPC) {
	mock := &mockGRPC{
		pingResp:        &pb.PingResponse{HostName: "test-host"},
		listHostsResp:   &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "host1", Address: "10.0.0.1"}}},
		inspectHostResp: &pb.Host{Name: "host1", Address: "10.0.0.1"},
		listVMsResp:     &pb.ListVMsResponse{Vms: []*pb.VM{{Name: "vm1"}, {Name: "vm2"}}},
		inspectVMResp:   &pb.VM{Name: "vm1"},
		listStacksResp:  &pb.ListStacksResponse{},
		startVMResp:     &pb.VM{Name: "vm1"},
		stopVMResp:      &pb.VM{Name: "vm1"},
		restartVMResp:   &pb.VM{Name: "vm1"},

		// Host action responses
		undrainHostResp:     &pb.Host{Name: "node1"},
		fenceHostResp:       &pb.FenceResult{HostName: "node1", Method: "ipmi", Result: "success"},
		listHostDevicesResp: &pb.ListHostDevicesResponse{},
		hostStatsResp:       &pb.HostResourceStats{},
		configureHostResp:   &pb.Host{Name: "node1"},

		// VM action responses
		createVMResp: &pb.VM{Name: "test"},
		updateVMResp: &pb.VM{Name: "vm1"},
		vmStatsResp:  &pb.VMStats{},
		execVMResp:   &pb.ExecVMResponse{ExitCode: 0, Stdout: []byte("test-host")},
		setVMIPResp:  &pb.VM{Name: "vm1"},

		// Images, Users, Status, Audit, Login
		listImagesResp:    &pb.ListImagesResponse{},
		listUsersResp:     &pb.ListUsersResponse{},
		clusterStatusResp: &pb.ClusterStatus{},
		auditLogResp:      &pb.ListAuditLogResponse{},
		loginResp:         &pb.LoginResponse{Token: "jwt-token-here"},

		// LB & Network
		listLBsResp:        &pb.ListLBResponse{Lbs: []*pb.LoadBalancer{{Name: "lb1", Vip: "10.0.100.50"}}},
		inspectLBResp:      &pb.LoadBalancer{Name: "lb1", Vip: "10.0.100.50", Algorithm: "roundrobin"},
		createLBResp:       &pb.LoadBalancer{Name: "lb1", Vip: "10.0.100.50"},
		updateLBResp:       &pb.LoadBalancer{Name: "lb1", Vip: "10.0.100.51"},
		lbStatsResp:        &pb.LBStatsResponse{Name: "lb1"},
		drainBackendResp:   &pb.DrainBackendResponse{Status: "draining", ActiveConnections: 5},
		disableBackendResp: &pb.LoadBalancer{Name: "lb1"},
		enableBackendResp:  &pb.LoadBalancer{Name: "lb1"},
		listNetworksResp:   &pb.ListNetworksResponse{Networks: []*pb.NetworkInfo{{Name: "net1", Type: "bridge"}}},
		getNetworkResp:     &pb.NetworkInfo{Name: "net1", Type: "bridge", Subnet: "10.0.1.0/24"},
		createNetworkResp:  &pb.NetworkInfo{Name: "net1", Type: "bridge"},
	}
	s := NewServer(mock, token)
	return s, mock
}

func TestHealth_Success(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
	if body["host"] != "test-host" {
		t.Errorf("host = %q, want test-host", body["host"])
	}
}

func TestListHosts_Success(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestListHosts_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestInspectHost_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/host1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastInspectHostName != "host1" {
		t.Errorf("inspected host = %q, want host1", mock.lastInspectHostName)
	}
}

func TestListVMs_Success(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vms", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListVMs_WithFilters(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vms?stack=web&host=node1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastListVMsReq.StackName != "web" {
		t.Errorf("stack filter = %q, want web", mock.lastListVMsReq.StackName)
	}
	if mock.lastListVMsReq.HostName != "node1" {
		t.Errorf("host filter = %q, want node1", mock.lastListVMsReq.HostName)
	}
}

func TestListVMs_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vms", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestInspectVM_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vms/vm1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastInspectVMName != "vm1" {
		t.Errorf("inspected VM = %q, want vm1", mock.lastInspectVMName)
	}
}

func TestStartVM_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/start", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastStartVMName != "vm1" {
		t.Errorf("started VM = %q, want vm1", mock.lastStartVMName)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "started" {
		t.Errorf("status = %q, want started", body["status"])
	}
}

func TestStopVM_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/stop", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastStopVMName != "vm1" {
		t.Errorf("stopped VM = %q, want vm1", mock.lastStopVMName)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "stopped" {
		t.Errorf("status = %q, want stopped", body["status"])
	}
}

func TestRestartVM_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/restart", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastRestartVMName != "vm1" {
		t.Errorf("restarted VM = %q, want vm1", mock.lastRestartVMName)
	}
}

func TestDeleteVM_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vms/vm1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.deleteVMCalled {
		t.Error("DeleteVM was not called")
	}
	if mock.lastDeleteVMName != "vm1" {
		t.Errorf("deleted VM = %q, want vm1", mock.lastDeleteVMName)
	}
}

func TestListStacks_Success(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListStacks_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestVM_UnknownAction(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/nonexistent-action", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown action, got %d", rec.Code)
	}
}

func TestAuth_BearerToken_Required(t *testing.T) {
	s, _ := newMockServer("my-secret-token")

	// No token.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rec.Code)
	}

	// Wrong token.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", rec.Code)
	}

	// Correct token.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with correct token, got %d", rec.Code)
	}
}

func TestContentType_AlwaysJSON(t *testing.T) {
	s, _ := newMockServer("test-token")

	endpoints := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/health"},
		{http.MethodGet, "/api/v1/hosts"},
		{http.MethodGet, "/api/v1/vms"},
		{http.MethodGet, "/api/v1/stacks"},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)

		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("%s %s: Content-Type = %q, want application/json", ep.method, ep.path, ct)
		}
	}
}

func TestInspectHost_EmptyName(t *testing.T) {
	s, _ := newMockServer("test-token")
	// Path is /api/v1/hosts/ with no name.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty host name, got %d", rec.Code)
	}
}

// ── Load Balancer Tests ──────────────────────────────────────────────────────

func TestListLBs_Success(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/lbs", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListLBs_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/lbs", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCreateLB_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"lb1","vip":"10.0.100.50/24","algorithm":"roundrobin"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lbs", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if mock.lastCreateLBReq == nil || mock.lastCreateLBReq.Name != "lb1" {
		t.Error("CreateLoadBalancer not called with correct name")
	}
}

func TestInspectLB_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/lbs/lb1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastInspectLBName != "lb1" {
		t.Errorf("inspected LB = %q, want lb1", mock.lastInspectLBName)
	}
}

func TestUpdateLB_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"algorithm":"leastconn"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/lbs/lb1", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastUpdateLBReq == nil || mock.lastUpdateLBReq.Name != "lb1" {
		t.Error("UpdateLoadBalancer not called with correct name from path")
	}
}

func TestDeleteLB_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/lbs/lb1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.deleteLBCalled {
		t.Error("DeleteLoadBalancer was not called")
	}
	if mock.lastDeleteLBName != "lb1" {
		t.Errorf("deleted LB = %q, want lb1", mock.lastDeleteLBName)
	}
}

func TestLBStats_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/lbs/lb1/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastLBStatsName != "lb1" {
		t.Errorf("stats LB = %q, want lb1", mock.lastLBStatsName)
	}
}

func TestDrainBackend_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lbs/lb1/backends/web-0/drain", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastDrainReq == nil || mock.lastDrainReq.LbName != "lb1" || mock.lastDrainReq.Backend != "web-0" {
		t.Error("DrainBackend not called with correct params")
	}
}

func TestDisableBackend_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lbs/lb1/backends/web-0/disable", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastDisableReq == nil || mock.lastDisableReq.LbName != "lb1" || mock.lastDisableReq.Backend != "web-0" {
		t.Error("DisableBackend not called with correct params")
	}
}

func TestEnableBackend_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lbs/lb1/backends/web-0/enable", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastEnableReq == nil || mock.lastEnableReq.LbName != "lb1" || mock.lastEnableReq.Backend != "web-0" {
		t.Error("EnableBackend not called with correct params")
	}
}

func TestLB_EmptyName(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/lbs/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty LB name, got %d", rec.Code)
	}
}

// ── Network Tests ────────────────────────────────────────────────────────────

func TestListNetworks_Success(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListNetworks_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCreateNetwork_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"net1","type":"bridge","subnet":"10.0.1.0/24"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if mock.lastCreateNetworkReq == nil || mock.lastCreateNetworkReq.Name != "net1" {
		t.Error("CreateNetwork not called with correct name")
	}
}

func TestGetNetwork_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/networks/net1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastGetNetworkName != "net1" {
		t.Errorf("got network = %q, want net1", mock.lastGetNetworkName)
	}
}

func TestDeleteNetwork_Success(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/networks/net1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.deleteNetworkCalled {
		t.Error("DeleteNetwork was not called")
	}
}

func TestDeleteNetwork_Force(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/networks/net1?force=true", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if mock.lastDeleteNetworkReq == nil || !mock.lastDeleteNetworkReq.Force {
		t.Error("DeleteNetwork not called with force=true")
	}
}

func TestNetwork_EmptyName(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/networks/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty network name, got %d", rec.Code)
	}
}

// ── Host Action Tests ────────────────────────────────────────────────────────

func TestHostDrain(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/node1/drain", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	// DrainHost returns nil stream — handler writes ack JSON (status 200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastDrainHostName != "node1" {
		t.Errorf("drained host = %q, want node1", mock.lastDrainHostName)
	}
}

func TestHostUndrain(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/node1/undrain", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastUndrainHostName != "node1" {
		t.Errorf("undrained host = %q, want node1", mock.lastUndrainHostName)
	}
}

func TestHostLabels(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"node1","labels":{"env":"prod"}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/hosts/node1/labels", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastSetLabelsReq == nil {
		t.Fatal("SetHostLabels was not called")
	}
	if mock.lastSetLabelsReq.Name != "node1" {
		t.Errorf("labels host = %q, want node1", mock.lastSetLabelsReq.Name)
	}
}

func TestHostFence(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"node1","confirmed":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/node1/fence", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastFenceHostReq == nil {
		t.Fatal("FenceHost was not called")
	}
	if mock.lastFenceHostReq.Name != "node1" {
		t.Errorf("fenced host = %q, want node1", mock.lastFenceHostReq.Name)
	}
}

func TestHostRemove(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/hosts/node1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.removeHostCalled {
		t.Error("RemoveHost was not called")
	}
	if mock.lastRemoveHostName != "node1" {
		t.Errorf("removed host = %q, want node1", mock.lastRemoveHostName)
	}
}

func TestHostDevices(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/node1/devices", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastListDevicesHost != "node1" {
		t.Errorf("devices host = %q, want node1", mock.lastListDevicesHost)
	}
}

func TestHostStats(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/node1/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastHostStatsName != "node1" {
		t.Errorf("stats host = %q, want node1", mock.lastHostStatsName)
	}
}

func TestHostConfig(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"node1","fence_strategy":"ipmi"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/node1/config", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastConfigureHostReq == nil {
		t.Fatal("ConfigureHost was not called")
	}
	if mock.lastConfigureHostReq.Name != "node1" {
		t.Errorf("configured host = %q, want node1", mock.lastConfigureHostReq.Name)
	}
}

// TestHostConfig_AcceptsPutAndPost — docs advertise PUT; POST is preserved.
func TestHostConfig_AcceptsPutAndPost(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPost} {
		s, mock := newMockServer("test-token")
		req := httptest.NewRequest(method, "/api/v1/hosts/node1/config",
			strings.NewReader(`{"fence_strategy":"ipmi"}`))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s /config: status %d, want 200", method, rec.Code)
		}
		if mock.lastConfigureHostReq == nil || mock.lastConfigureHostReq.Name != "node1" {
			t.Errorf("%s /config: ConfigureHost not called with node1 (%+v)", method, mock.lastConfigureHostReq)
		}
	}
}

// TestRemoveHost_ForwardsForce — DELETE …?force=true wires RemoveHostRequest.Force.
func TestRemoveHost_ForwardsForce(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/hosts/node1?force=true", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	s.mux.ServeHTTP(httptest.NewRecorder(), req)
	if mock.lastRemoveHostReq == nil || !mock.lastRemoveHostReq.Force {
		t.Errorf("force not forwarded to RemoveHost: %+v", mock.lastRemoveHostReq)
	}
}

// TestStopVM_ForwardsForceAndTimeout — POST …/stop?force=true&timeout=30 wires both.
func TestStopVM_ForwardsForceAndTimeout(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/web-1/stop?force=true&timeout=30", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	s.mux.ServeHTTP(httptest.NewRecorder(), req)
	if mock.lastStopVMReq == nil || !mock.lastStopVMReq.Force || mock.lastStopVMReq.Timeout != 30 {
		t.Errorf("force/timeout not forwarded to StopVM: %+v", mock.lastStopVMReq)
	}
}

// TestMigrateBody_UnmarshalsStrategyAndWithStorage validates the documented
// migrate JSON (rest-api.md) maps onto MigrateVMRequest — there is no `cold` field.
func TestMigrateBody_UnmarshalsStrategyAndWithStorage(t *testing.T) {
	var req pb.MigrateVMRequest
	body := `{"target_host":"host-b","strategy":"MIGRATE_COLD","with_storage":true}`
	if err := protojson.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal documented migrate body: %v", err)
	}
	if req.TargetHost != "host-b" || req.Strategy != pb.MigrateStrategy_MIGRATE_COLD || !req.WithStorage {
		t.Errorf("migrate body decoded as %+v, want host-b / MIGRATE_COLD / withStorage=true", &req)
	}
}

// ── VM Action Tests ──────────────────────────────────────────────────────────

func TestVMCreate(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"spec":{"name":"test","image":"ubuntu","cpu":2,"memory_mib":1024}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/test", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if mock.lastCreateVMReq == nil {
		t.Fatal("CreateVM was not called")
	}
}

func TestVMUpdate(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"cpu":4}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/vms/vm1", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastUpdateVMReq == nil {
		t.Fatal("UpdateVM was not called")
	}
	if mock.lastUpdateVMReq.Name != "vm1" {
		t.Errorf("updated VM = %q, want vm1", mock.lastUpdateVMReq.Name)
	}
}

func TestVMStats(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vms/vm1/stats", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastVMStatsName != "vm1" {
		t.Errorf("stats VM = %q, want vm1", mock.lastVMStatsName)
	}
}

func TestVMExec(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"vm1","command":["hostname"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/exec", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastExecVMReq == nil {
		t.Fatal("ExecVM was not called")
	}
	if mock.lastExecVMReq.Name != "vm1" {
		t.Errorf("exec VM = %q, want vm1", mock.lastExecVMReq.Name)
	}
}

func TestVMSetIP(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"vm1","ip":"10.0.0.5"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/set-ip", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastSetVMIPReq == nil {
		t.Fatal("SetVMIP was not called")
	}
	if mock.lastSetVMIPReq.Name != "vm1" {
		t.Errorf("set-ip VM = %q, want vm1", mock.lastSetVMIPReq.Name)
	}
}

// ── Image Tests ──────────────────────────────────────────────────────────────

func TestImages_List(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/images", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestImage_Delete(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/images/ubuntu", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.deleteImageCalled {
		t.Error("DeleteImage was not called")
	}
	if mock.lastDeleteImageName != "ubuntu" {
		t.Errorf("deleted image = %q, want ubuntu", mock.lastDeleteImageName)
	}
}

// ── User Tests ───────────────────────────────────────────────────────────────

func TestUsers_List(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestUser_Delete(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/testuser", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.deleteUserCalled {
		t.Error("DeleteUser was not called")
	}
	if mock.lastDeleteUserName != "testuser" {
		t.Errorf("deleted user = %q, want testuser", mock.lastDeleteUserName)
	}
}

// ── Monitoring Tests ─────────────────────────────────────────────────────────

func TestStatus(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAudit(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=10", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastAuditLimit != 10 {
		t.Errorf("audit limit = %d, want 10", mock.lastAuditLimit)
	}
}

// ── Auth Tests ───────────────────────────────────────────────────────────────

func TestLogin(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"username":"admin","password":"pass"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastLoginReq == nil {
		t.Fatal("Login was not called")
	}
	if mock.lastLoginReq.Username != "admin" {
		t.Errorf("login username = %q, want admin", mock.lastLoginReq.Username)
	}
}

func TestLogin_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ── Host Rescan Test ─────────────────────────────────────────────────────────

func TestHostRescan(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/node1/rescan", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastRescanHostName != "node1" {
		t.Errorf("rescan host = %q, want node1", mock.lastRescanHostName)
	}
}

func TestHostHealth(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/node1/health", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHost_UnknownAction(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/node1/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown host action, got %d", rec.Code)
	}
}

// ── VM Rebuild Test ──────────────────────────────────────────────────────────

func TestVMRebuild(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"name":"vm1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/rebuild", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastRebuildVMReq == nil {
		t.Fatal("RebuildVM was not called")
	}
	if mock.lastRebuildVMReq.Name != "vm1" {
		t.Errorf("rebuild VM = %q, want vm1", mock.lastRebuildVMReq.Name)
	}
}

// ── VM Attach/Detach Tests ───────────────────────────────────────────────────

func TestVMAttach(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"vm_name":"vm1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/attach", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastAttachDeviceReq == nil {
		t.Fatal("AttachDevice was not called")
	}
	if mock.lastAttachDeviceReq.VmName != "vm1" {
		t.Errorf("attach VM = %q, want vm1", mock.lastAttachDeviceReq.VmName)
	}
}

func TestVMDetach(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"vm_name":"vm1","disk_name":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/detach", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastDetachDeviceReq == nil {
		t.Fatal("DetachDevice was not called")
	}
	if mock.lastDetachDeviceReq.VmName != "vm1" {
		t.Errorf("detach VM = %q, want vm1", mock.lastDetachDeviceReq.VmName)
	}
}

// ── VM Disk Resize Test ──────────────────────────────────────────────────────

func TestVMDiskResize(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"size":"50G"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/disks/root/resize", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastResizeDiskReq == nil {
		t.Fatal("ResizeDisk was not called")
	}
	if mock.lastResizeDiskReq.VmName != "vm1" {
		t.Errorf("resize VM = %q, want vm1", mock.lastResizeDiskReq.VmName)
	}
	if mock.lastResizeDiskReq.DiskName != "root" {
		t.Errorf("resize disk = %q, want root", mock.lastResizeDiskReq.DiskName)
	}
}

func TestVMDiskResize_BadAction(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/disks/root/shrink", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown disk action, got %d", rec.Code)
	}
}

// ── Snapshot Tests ───────────────────────────────────────────────────────────

func TestSnapshotCreate(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"vm_name":"vm1","name":"snap1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/snapshots", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if mock.lastCreateSnapshotReq == nil {
		t.Fatal("CreateSnapshot was not called")
	}
	if mock.lastCreateSnapshotReq.VmName != "vm1" {
		t.Errorf("snapshot VM = %q, want vm1", mock.lastCreateSnapshotReq.VmName)
	}
}

func TestSnapshotList(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vms/vm1/snapshots", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastListSnapshotsReq == nil {
		t.Fatal("ListSnapshots was not called")
	}
	if mock.lastListSnapshotsReq.VmName != "vm1" {
		t.Errorf("list snapshots VM = %q, want vm1", mock.lastListSnapshotsReq.VmName)
	}
}

func TestSnapshotRestore(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/snapshots/snap1/restore", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastRestoreSnapshotReq == nil {
		t.Fatal("RestoreSnapshot was not called")
	}
	if mock.lastRestoreSnapshotReq.VmName != "vm1" {
		t.Errorf("restore snapshot VM = %q, want vm1", mock.lastRestoreSnapshotReq.VmName)
	}
	if mock.lastRestoreSnapshotReq.SnapshotName != "snap1" {
		t.Errorf("restore snapshot name = %q, want snap1", mock.lastRestoreSnapshotReq.SnapshotName)
	}
}

func TestSnapshotDelete(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vms/vm1/snapshots/snap1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.deleteSnapshotCalled {
		t.Error("DeleteSnapshot was not called")
	}
	if mock.lastDeleteSnapshotReq.VmName != "vm1" {
		t.Errorf("delete snapshot VM = %q, want vm1", mock.lastDeleteSnapshotReq.VmName)
	}
	if mock.lastDeleteSnapshotReq.SnapshotName != "snap1" {
		t.Errorf("delete snapshot name = %q, want snap1", mock.lastDeleteSnapshotReq.SnapshotName)
	}
}

// ── Image Additional Tests ───────────────────────────────────────────────────

func TestImages_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/images", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestImage_EmptyName(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/images/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty image name, got %d", rec.Code)
	}
}

func TestImage_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/ubuntu", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ── User Additional Tests ────────────────────────────────────────────────────

func TestUsers_Create(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"username":"newuser","password":"secret","role":"viewer"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if mock.lastCreateUserReq == nil {
		t.Fatal("CreateUser was not called")
	}
	if mock.lastCreateUserReq.Username != "newuser" {
		t.Errorf("created user = %q, want newuser", mock.lastCreateUserReq.Username)
	}
	if mock.lastCreateUserReq.Role != "viewer" {
		t.Errorf("created user role = %q, want viewer", mock.lastCreateUserReq.Role)
	}
}

func TestUsers_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestUser_EmptyName(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty user name, got %d", rec.Code)
	}
}

func TestUser_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/testuser", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ── Token Tests ──────────────────────────────────────────────────────────────

func TestTokens_Create(t *testing.T) {
	s, mock := newMockServer("test-token")
	body := strings.NewReader(`{"username":"admin","name":"ci-token","expires":"720h"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if mock.lastCreateTokenReq == nil {
		t.Fatal("CreateToken was not called")
	}
	if mock.lastCreateTokenReq.Username != "admin" {
		t.Errorf("token username = %q, want admin", mock.lastCreateTokenReq.Username)
	}
}

func TestTokens_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestToken_Revoke(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tokens/tok-123", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !mock.revokeTokenCalled {
		t.Error("RevokeToken was not called")
	}
	if mock.lastRevokeTokenID != "tok-123" {
		t.Errorf("revoked token = %q, want tok-123", mock.lastRevokeTokenID)
	}
}

func TestToken_EmptyID(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tokens/", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty token id, got %d", rec.Code)
	}
}

func TestToken_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens/tok-123", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// ── Monitoring Additional Tests ──────────────────────────────────────────────

func TestStatus_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestAudit_MethodNotAllowed(t *testing.T) {
	s, _ := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestAudit_DefaultLimit(t *testing.T) {
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if mock.lastAuditLimit != 100 {
		t.Errorf("audit default limit = %d, want 100", mock.lastAuditLimit)
	}
}

// federation mocks.
func (m *mockGRPC) ListRegions(context.Context, *pb.ListRegionsRequest, ...grpc.CallOption) (*pb.ListRegionsResponse, error) {
	return &pb.ListRegionsResponse{}, nil
}
func (m *mockGRPC) RegionStatus(context.Context, *pb.RegionStatusRequest, ...grpc.CallOption) (*pb.RegionStatusResponse, error) {
	return &pb.RegionStatusResponse{}, nil
}
func (m *mockGRPC) CrossRegionMigrate(context.Context, *pb.CrossRegionMigrateRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	return nil, nil
}

// tenancy mocks.
func (m *mockGRPC) CreateProject(context.Context, *pb.CreateProjectRequest, ...grpc.CallOption) (*pb.Project, error) {
	return &pb.Project{}, nil
}
func (m *mockGRPC) ListProjects(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListProjectsResponse, error) {
	return &pb.ListProjectsResponse{}, nil
}
func (m *mockGRPC) GetProject(context.Context, *pb.GetProjectRequest, ...grpc.CallOption) (*pb.Project, error) {
	return &pb.Project{}, nil
}
func (m *mockGRPC) DeleteProject(context.Context, *pb.DeleteProjectRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) SetProjectQuota(context.Context, *pb.SetProjectQuotaRequest, ...grpc.CallOption) (*pb.ProjectQuota, error) {
	return &pb.ProjectQuota{}, nil
}
func (m *mockGRPC) GetProjectQuota(context.Context, *pb.GetProjectQuotaRequest, ...grpc.CallOption) (*pb.ProjectQuota, error) {
	return &pb.ProjectQuota{}, nil
}
func (m *mockGRPC) GetProjectUsage(context.Context, *pb.GetProjectUsageRequest, ...grpc.CallOption) (*pb.ProjectUsage, error) {
	return &pb.ProjectUsage{}, nil
}

// audit chain mocks.
func (m *mockGRPC) VerifyAuditChain(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.VerifyAuditChainResponse, error) {
	return &pb.VerifyAuditChainResponse{}, nil
}
func (m *mockGRPC) ExportAuditChain(context.Context, *pb.ExportAuditChainRequest, ...grpc.CallOption) (*pb.ExportAuditChainResponse, error) {
	return &pb.ExportAuditChainResponse{Json: `{"rows":[]}`}, nil
}

// anycast mocks.
func (m *mockGRPC) UpsertServiceEndpoint(context.Context, *pb.UpsertServiceEndpointRequest, ...grpc.CallOption) (*pb.ServiceEndpoint, error) {
	return &pb.ServiceEndpoint{}, nil
}
func (m *mockGRPC) ListServiceEndpoints(context.Context, *pb.ListServiceEndpointsRequest, ...grpc.CallOption) (*pb.ListServiceEndpointsResponse, error) {
	return &pb.ListServiceEndpointsResponse{}, nil
}
func (m *mockGRPC) DeleteServiceEndpoint(context.Context, *pb.DeleteServiceEndpointRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// backup-schedule mocks.
func (m *mockGRPC) CreateBackupSchedule(context.Context, *pb.CreateBackupScheduleRequest, ...grpc.CallOption) (*pb.BackupSchedule, error) {
	return &pb.BackupSchedule{}, nil
}
func (m *mockGRPC) ListBackupSchedules(context.Context, *pb.ListBackupSchedulesRequest, ...grpc.CallOption) (*pb.ListBackupSchedulesResponse, error) {
	return &pb.ListBackupSchedulesResponse{}, nil
}
func (m *mockGRPC) DeleteBackupSchedule(context.Context, *pb.DeleteBackupScheduleRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CreateReplicationSchedule(context.Context, *pb.CreateReplicationScheduleRequest, ...grpc.CallOption) (*pb.ReplicationSchedule, error) {
	return &pb.ReplicationSchedule{}, nil
}
func (m *mockGRPC) ListReplicationSchedules(context.Context, *pb.ListReplicationSchedulesRequest, ...grpc.CallOption) (*pb.ListReplicationSchedulesResponse, error) {
	return &pb.ListReplicationSchedulesResponse{}, nil
}
func (m *mockGRPC) DeleteReplicationSchedule(context.Context, *pb.DeleteReplicationScheduleRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (m *mockGRPC) CreateNotificationTarget(_ context.Context, in *pb.CreateNotificationTargetRequest, _ ...grpc.CallOption) (*pb.NotificationTarget, error) {
	return &pb.NotificationTarget{Id: "t1", Name: in.Name, Type: in.Type, Config: in.Config, Enabled: in.Enabled}, nil
}
func (m *mockGRPC) ListNotificationTargets(_ context.Context, _ *pb.ListNotificationTargetsRequest, _ ...grpc.CallOption) (*pb.ListNotificationTargetsResponse, error) {
	return &pb.ListNotificationTargetsResponse{}, nil
}
func (m *mockGRPC) DeleteNotificationTarget(_ context.Context, _ *pb.DeleteNotificationTargetRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) TestNotificationTarget(_ context.Context, _ *pb.TestNotificationTargetRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CreateNotificationRoute(_ context.Context, in *pb.CreateNotificationRouteRequest, _ ...grpc.CallOption) (*pb.NotificationRoute, error) {
	return &pb.NotificationRoute{Id: "r1", EventPattern: in.EventPattern, TargetId: in.TargetId, MinSeverity: in.MinSeverity, Enabled: in.Enabled}, nil
}
func (m *mockGRPC) ListNotificationRoutes(_ context.Context, _ *pb.ListNotificationRoutesRequest, _ ...grpc.CallOption) (*pb.ListNotificationRoutesResponse, error) {
	return &pb.ListNotificationRoutesResponse{}, nil
}
func (m *mockGRPC) DeleteNotificationRoute(_ context.Context, _ *pb.DeleteNotificationRouteRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
