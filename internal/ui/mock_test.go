package ui

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// mockGRPC implements pb.LiteVirtClient for UI handler tests.
//
// The mu mutex protects every `last*` recorder field. The handlers
// under test (notably the bulk-ops dispatcher in handle_bulk.go) fan
// out 8 concurrent goroutines hitting the same mock; without the
// mutex the race detector flags the writes — they're a real race
// even though no test asserts on the value of more than one field
// per call.
type mockGRPC struct {
	// Embed the client interface so RPCs the mock doesn't exercise (e.g. the
	// firewall management calls) are satisfied without a hand-written stub.
	pb.LiteVirtClient

	mu sync.Mutex
	// Response fields
	listHostsResp        *pb.ListHostsResponse
	inspectHostResp      *pb.Host
	inspectHostErr       error
	listVMsResp          *pb.ListVMsResponse
	inspectVMResp        *pb.VM
	inspectVMErr         error
	listStacksResp       *pb.ListStacksResponse
	listImagesResp       *pb.ListImagesResponse
	listContainersResp   *pb.ListContainersResponse
	listSchedulesResp    *pb.ListBackupSchedulesResponse
	listUsersResp        *pb.ListUsersResponse
	listNetworksResp     *pb.ListNetworksResponse
	listLBsResp          *pb.ListLBResponse
	inspectLBResp        *pb.LoadBalancer
	inspectLBErr         error
	auditLogResp         *pb.ListAuditLogResponse
	loginResp            *pb.LoginResponse
	loginErr             error
	vmStatsResp          *pb.VMStats
	vmStatsErr           error
	hostStatsResp        *pb.HostResourceStats
	hostStatsErr         error
	lbStatsResp          *pb.LBStatsResponse
	lbStatsErr           error
	fenceHostResp        *pb.FenceResult
	listHostDevicesResp  *pb.ListHostDevicesResponse
	configureHostResp    *pb.Host
	listSnapshotsResp    *pb.ListSnapshotsResponse
	createNetworkResp    *pb.NetworkInfo
	diffStackResp        *pb.DiffStackResponse
	diffStackErr         error
	clusterStatusResp    *pb.ClusterStatus
	listStoragePoolsResp *pb.ListStoragePoolsResponse
	spiceInfoResp        *pb.GetSpiceInfoResponse
	spiceInfoErr         error
	lastSetLabelsVMReq   *pb.SetVMLabelsRequest
	setLabelsVMErr       error
	poolContentsResp     *pb.ListStoragePoolContentsResponse
	poolContentsErr      error
	lastPoolContentsReq  *pb.ListStoragePoolContentsRequest
	listVMHardwareResp   *pb.ListVMHardwareResponse
	listVMHardwareErr    error
	uploadStream         *fakeUploadStream
	uploadStreamErr      error

	// Error injection for actions
	startVMErr         error
	stopVMErr          error
	restartVMErr       error
	createVMErr        error
	deleteVMErr        error
	deleteImageErr     error
	createUserErr      error
	deleteUserErr      error
	createTokenErr     error
	revokeTokenErr     error
	deleteNetworkErr   error
	deleteLBErr        error
	drainBackendErr    error
	drainHostErr       error
	undrainHostErr     error
	fenceHostErr       error
	removeHostErr      error
	setLabelsErr       error
	configureHostErr   error
	createSnapshotErr  error
	restoreSnapshotErr error
	deleteSnapshotErr  error
	attachDeviceErr    error
	detachDeviceErr    error
	resizeDiskErr      error
	updateVMErr        error

	// Call tracking
	lastInspectVMName      string
	lastInspectHostName    string
	lastStartVMName        string
	lastStopVMName         string
	lastRestartVMName      string
	lastDeleteVMName       string
	deleteVMCalled         bool
	lastCreateVMReq        *pb.CreateVMRequest
	lastUpdateVMReq        *pb.UpdateVMRequest
	lastLoginReq           *pb.LoginRequest
	lastDeleteImageName    string
	deleteImageCalled      bool
	lastCreateUserReq      *pb.CreateUserRequest
	lastDeleteUserName     string
	deleteUserCalled       bool
	lastCreateTokenReq     *pb.CreateTokenRequest
	lastRevokeTokenID      string
	revokeTokenCalled      bool
	lastCreateNetworkReq   *pb.CreateNetworkRequest
	lastDeleteNetworkReq   *pb.DeleteNetworkRequest
	deleteNetworkCalled    bool
	lastDeleteLBName       string
	deleteLBCalled         bool
	lastDrainReq           *pb.DrainBackendRequest
	lastDrainHostName      string
	lastUndrainHostName    string
	lastFenceHostReq       *pb.FenceHostRequest
	lastRemoveHostName     string
	removeHostCalled       bool
	lastSetLabelsReq       *pb.SetHostLabelsRequest
	lastConfigureHostReq   *pb.ConfigureHostRequest
	lastCreateSnapshotReq  *pb.CreateSnapshotRequest
	lastRestoreSnapshotReq *pb.RestoreSnapshotRequest
	lastDeleteSnapshotReq  *pb.DeleteSnapshotRequest
	lastAttachDeviceReq    *pb.AttachDeviceRequest
	lastDetachDeviceReq    *pb.DetachDeviceRequest
	lastResizeDiskReq      *pb.ResizeDiskRequest
	lastInspectLBName      string
	lastLBStatsName        string

	// ── UI feature recorders + injectable responses ──
	// Storage pool CRUD
	createPoolErr     error
	lastCreatePoolReq *pb.CreateStoragePoolRequest
	deletePoolErr     error
	lastDeletePoolReq *pb.DeleteStoragePoolRequest
	// Move volume
	lastMoveReq *pb.MoveVolumeRequest
	// Replicate volume
	replicateFrames  []*pb.ReplicateVolumeProgress
	replicateErr     error
	lastReplicateReq *pb.ReplicateVolumeRequest
	// Rebalance
	listRebalanceResp    *pb.ListRebalanceProposalsResponse
	lastListRebalanceReq *pb.ListRebalanceProposalsRequest
	runRebalanceResp     *pb.RunRebalanceResponse
	runRebalanceErr      error
	lastRunRebalanceReq  *pb.RunRebalanceRequest
	approveRebalanceResp *pb.RebalanceProposal
	approveRebalanceErr  error
	lastApproveID        string
	rejectRebalanceErr   error
	lastRejectReq        *pb.RejectRebalanceProposalRequest
	// Projects / tenancy
	listProjectsResp     *pb.ListProjectsResponse
	listProjectsErr      error
	createProjectErr     error
	lastCreateProjectReq *pb.CreateProjectRequest
	deleteProjectErr     error
	lastDeleteProjectReq *pb.DeleteProjectRequest
	getProjectQuotaResp  *pb.ProjectQuota
	getProjectQuotaErr   error
	getProjectUsageResp  *pb.ProjectUsage
	setProjectQuotaErr   error
	lastSetQuotaReq      *pb.SetProjectQuotaRequest
	// Audit chain
	verifyAuditResp *pb.VerifyAuditChainResponse
	verifyAuditErr  error
	exportAuditResp *pb.ExportAuditChainResponse
	exportAuditErr  error
	lastExportReq   *pb.ExportAuditChainRequest
	// Backup schedules
	createScheduleErr     error
	lastCreateScheduleReq *pb.CreateBackupScheduleRequest
	backupSnapshotErr     error
	lastBackupSnapshotReq *pb.BackupSnapshotRequest
	vmEventsResp          *pb.ListVMEventsResponse
	lastVMEventsReq       *pb.ListVMEventsRequest
	lastRestoreFromReq    *pb.RestoreFromBackupRequest
	lastRestoreLiveReq    *pb.RestoreLiveRequest
	deleteScheduleErr     error
	lastDeleteScheduleReq *pb.DeleteBackupScheduleRequest
	createReplErr         error
	lastCreateReplReq     *pb.CreateReplicationScheduleRequest
	listReplSchedulesResp *pb.ListReplicationSchedulesResponse
	lastDeleteReplReq     *pb.DeleteReplicationScheduleRequest
	lastPromoteReq        *pb.PromoteReplicaRequest
	promoteErr            error
}

// ── Core RPCs ────────────────────────────────────────────────────────────────

func (m *mockGRPC) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{HostName: "test-host"}, nil
}

func (m *mockGRPC) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	if m.listHostsResp == nil {
		return &pb.ListHostsResponse{}, nil
	}
	return m.listHostsResp, nil
}

func (m *mockGRPC) InspectHost(_ context.Context, in *pb.InspectHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.lastInspectHostName = in.Name
	if m.inspectHostErr != nil {
		return nil, m.inspectHostErr
	}
	return m.inspectHostResp, nil
}

func (m *mockGRPC) ListVMs(_ context.Context, _ *pb.ListVMsRequest, _ ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	if m.listVMsResp == nil {
		return &pb.ListVMsResponse{}, nil
	}
	return m.listVMsResp, nil
}

func (m *mockGRPC) InspectVM(_ context.Context, in *pb.InspectVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastInspectVMName = in.Name
	if m.inspectVMErr != nil {
		return nil, m.inspectVMErr
	}
	return m.inspectVMResp, nil
}

func (m *mockGRPC) StartVM(_ context.Context, in *pb.StartVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastStartVMName = in.Name
	if m.startVMErr != nil {
		return nil, m.startVMErr
	}
	return &pb.VM{Name: in.Name}, nil
}

func (m *mockGRPC) StopVM(_ context.Context, in *pb.StopVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastStopVMName = in.Name
	if m.stopVMErr != nil {
		return nil, m.stopVMErr
	}
	return &pb.VM{Name: in.Name}, nil
}

func (m *mockGRPC) RestartVM(_ context.Context, in *pb.RestartVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRestartVMName = in.Name
	if m.restartVMErr != nil {
		return nil, m.restartVMErr
	}
	return &pb.VM{Name: in.Name}, nil
}

func (m *mockGRPC) DeleteVM(_ context.Context, in *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastDeleteVMName = in.Name
	m.deleteVMCalled = true
	if m.deleteVMErr != nil {
		return nil, m.deleteVMErr
	}
	return &emptypb.Empty{}, nil
}

func (m *mockGRPC) CloneVM(_ context.Context, in *pb.CloneVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Target, State: pb.VMState_VM_STOPPED}, nil
}

func (m *mockGRPC) ConvertToTemplate(_ context.Context, in *pb.ConvertToTemplateRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, IsTemplate: !in.Revert}, nil
}

func (m *mockGRPC) CreateVM(_ context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastCreateVMReq = in
	if m.createVMErr != nil {
		return nil, m.createVMErr
	}
	return &pb.VM{Name: in.Spec.Name}, nil
}

func (m *mockGRPC) UpdateVM(_ context.Context, in *pb.UpdateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastUpdateVMReq = in
	if m.updateVMErr != nil {
		return nil, m.updateVMErr
	}
	return &pb.VM{Name: in.Name}, nil
}

func (m *mockGRPC) SetVMLabels(_ context.Context, in *pb.SetVMLabelsRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastSetLabelsVMReq = in
	if m.setLabelsVMErr != nil {
		return nil, m.setLabelsVMErr
	}
	return &pb.VM{Name: in.Name, Spec: &pb.VMSpec{Labels: in.Labels}}, nil
}

func (m *mockGRPC) ListStacks(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListStacksResponse, error) {
	if m.listStacksResp == nil {
		return &pb.ListStacksResponse{}, nil
	}
	return m.listStacksResp, nil
}

func (m *mockGRPC) ListImages(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListImagesResponse, error) {
	if m.listImagesResp == nil {
		return &pb.ListImagesResponse{}, nil
	}
	return m.listImagesResp, nil
}

func (m *mockGRPC) ListUsers(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListUsersResponse, error) {
	if m.listUsersResp == nil {
		return &pb.ListUsersResponse{}, nil
	}
	return m.listUsersResp, nil
}

func (m *mockGRPC) ListNetworks(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListNetworksResponse, error) {
	if m.listNetworksResp == nil {
		return &pb.ListNetworksResponse{}, nil
	}
	return m.listNetworksResp, nil
}

func (m *mockGRPC) ListLoadBalancers(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListLBResponse, error) {
	if m.listLBsResp == nil {
		return &pb.ListLBResponse{}, nil
	}
	return m.listLBsResp, nil
}

func (m *mockGRPC) InspectLoadBalancer(_ context.Context, in *pb.InspectLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	m.lastInspectLBName = in.Name
	if m.inspectLBErr != nil {
		return nil, m.inspectLBErr
	}
	return m.inspectLBResp, nil
}

func (m *mockGRPC) Login(_ context.Context, in *pb.LoginRequest, _ ...grpc.CallOption) (*pb.LoginResponse, error) {
	m.lastLoginReq = in
	if m.loginErr != nil {
		return nil, m.loginErr
	}
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
	if m.listContainersResp != nil {
		return m.listContainersResp, nil
	}
	return &pb.ListContainersResponse{}, nil
}
func (m *mockGRPC) PullOCIImage(context.Context, *pb.PullOCIImageRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) BackupSnapshot(_ context.Context, in *pb.BackupSnapshotRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.BackupSnapshotProgress], error) {
	m.lastBackupSnapshotReq = in
	if m.backupSnapshotErr != nil {
		return nil, m.backupSnapshotErr
	}
	return &scriptedStream[pb.BackupSnapshotProgress]{frames: []*pb.BackupSnapshotProgress{
		{Phase: pb.BackupSnapshotProgress_COPY, Status: "copying", BytesProcessed: 1 << 20, ChunksTotal: 4},
		{Phase: pb.BackupSnapshotProgress_DONE, Status: "done", ManifestTs: "2026-06-06T00:00:00Z", ChunksTotal: 4, ChunksDeduped: 2},
	}}, nil
}
func (m *mockGRPC) RestoreFromBackup(_ context.Context, in *pb.RestoreFromBackupRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreFromBackupProgress], error) {
	m.lastRestoreFromReq = in
	return &scriptedStream[pb.RestoreFromBackupProgress]{frames: []*pb.RestoreFromBackupProgress{
		{Phase: pb.RestoreFromBackupProgress_RESTORE, Status: "restoring", BytesWritten: 1 << 20, ChunksTotal: 4, ChunksDone: 2},
		{Phase: pb.RestoreFromBackupProgress_DONE, Status: "done", ChunksTotal: 4, ChunksDone: 4},
	}}, nil
}
func (m *mockGRPC) RestoreLive(_ context.Context, in *pb.RestoreLiveRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreLiveProgress], error) {
	m.lastRestoreLiveReq = in
	return &scriptedStream[pb.RestoreLiveProgress]{frames: []*pb.RestoreLiveProgress{
		{Phase: pb.RestoreLiveProgress_READY, Status: "ready", NbdUrl: "nbd://127.0.0.1:10809/export", TargetPath: in.GetTargetPath()},
		{Phase: pb.RestoreLiveProgress_DONE, Status: "localized"},
	}}, nil
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

func (m *mockGRPC) ListAuditLog(_ context.Context, in *pb.ListAuditLogRequest, _ ...grpc.CallOption) (*pb.ListAuditLogResponse, error) {
	if m.auditLogResp == nil {
		return &pb.ListAuditLogResponse{}, nil
	}
	return m.auditLogResp, nil
}

func (m *mockGRPC) ListVMEvents(_ context.Context, in *pb.ListVMEventsRequest, _ ...grpc.CallOption) (*pb.ListVMEventsResponse, error) {
	m.lastVMEventsReq = in
	if m.vmEventsResp == nil {
		return &pb.ListVMEventsResponse{}, nil
	}
	return m.vmEventsResp, nil
}

// ── Stats RPCs ───────────────────────────────────────────────────────────────

func (m *mockGRPC) GetVMStats(_ context.Context, in *pb.GetVMStatsRequest, _ ...grpc.CallOption) (*pb.VMStats, error) {
	if m.vmStatsErr != nil {
		return nil, m.vmStatsErr
	}
	return m.vmStatsResp, nil
}

func (m *mockGRPC) GetHostStats(_ context.Context, in *pb.GetHostStatsRequest, _ ...grpc.CallOption) (*pb.HostResourceStats, error) {
	if m.hostStatsErr != nil {
		return nil, m.hostStatsErr
	}
	return m.hostStatsResp, nil
}

func (m *mockGRPC) LBStats(_ context.Context, in *pb.LBStatsRequest, _ ...grpc.CallOption) (*pb.LBStatsResponse, error) {
	m.lastLBStatsName = in.Name
	if m.lbStatsErr != nil {
		return nil, m.lbStatsErr
	}
	return m.lbStatsResp, nil
}

// ── Host actions ─────────────────────────────────────────────────────────────

func (m *mockGRPC) DrainHost(_ context.Context, in *pb.DrainHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DrainProgress], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastDrainHostName = in.Name
	if m.drainHostErr != nil {
		return nil, m.drainHostErr
	}
	return &fakeStream[pb.DrainProgress]{}, nil
}

func (m *mockGRPC) UndrainHost(_ context.Context, in *pb.UndrainHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUndrainHostName = in.Name
	if m.undrainHostErr != nil {
		return nil, m.undrainHostErr
	}
	return &pb.Host{Name: in.Name}, nil
}

func (m *mockGRPC) FenceHost(_ context.Context, in *pb.FenceHostRequest, _ ...grpc.CallOption) (*pb.FenceResult, error) {
	m.lastFenceHostReq = in
	if m.fenceHostErr != nil {
		return nil, m.fenceHostErr
	}
	if m.fenceHostResp != nil {
		return m.fenceHostResp, nil
	}
	return &pb.FenceResult{Method: "ipmi", Result: "success"}, nil
}

func (m *mockGRPC) RemoveHost(_ context.Context, in *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastRemoveHostName = in.Name
	m.removeHostCalled = true
	if m.removeHostErr != nil {
		return nil, m.removeHostErr
	}
	return &emptypb.Empty{}, nil
}

func (m *mockGRPC) SetHostLabels(_ context.Context, in *pb.SetHostLabelsRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.lastSetLabelsReq = in
	if m.setLabelsErr != nil {
		return nil, m.setLabelsErr
	}
	return &pb.Host{Name: in.Name, Labels: in.Labels}, nil
}

func (m *mockGRPC) ConfigureHost(_ context.Context, in *pb.ConfigureHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.lastConfigureHostReq = in
	if m.configureHostErr != nil {
		return nil, m.configureHostErr
	}
	if m.configureHostResp != nil {
		return m.configureHostResp, nil
	}
	return &pb.Host{Name: in.Name}, nil
}

func (m *mockGRPC) GetHostHealth(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.HostHealthMatrix, error) {
	return &pb.HostHealthMatrix{}, nil
}

func (m *mockGRPC) ListHostDevices(_ context.Context, in *pb.ListHostDevicesRequest, _ ...grpc.CallOption) (*pb.ListHostDevicesResponse, error) {
	if m.listHostDevicesResp == nil {
		return &pb.ListHostDevicesResponse{}, nil
	}
	return m.listHostDevicesResp, nil
}

func (m *mockGRPC) RescanHost(context.Context, *pb.RescanHostRequest, ...grpc.CallOption) (*pb.RescanHostResponse, error) {
	return &pb.RescanHostResponse{}, nil
}

// ── Image actions ────────────────────────────────────────────────────────────

func (m *mockGRPC) DeleteImage(_ context.Context, in *pb.DeleteImageRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteImageName = in.Name
	m.deleteImageCalled = true
	if m.deleteImageErr != nil {
		return nil, m.deleteImageErr
	}
	return &emptypb.Empty{}, nil
}

func (m *mockGRPC) PullImage(context.Context, *pb.PullImageRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PullProgress], error) {
	return &fakeStream[pb.PullProgress]{}, nil
}

// ── Snapshot actions ─────────────────────────────────────────────────────────

func (m *mockGRPC) CreateSnapshot(_ context.Context, in *pb.CreateSnapshotRequest, _ ...grpc.CallOption) (*pb.Snapshot, error) {
	m.lastCreateSnapshotReq = in
	if m.createSnapshotErr != nil {
		return nil, m.createSnapshotErr
	}
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
	if m.listSnapshotsResp == nil {
		return &pb.ListSnapshotsResponse{}, nil
	}
	return m.listSnapshotsResp, nil
}

func (m *mockGRPC) RestoreSnapshot(_ context.Context, in *pb.RestoreSnapshotRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastRestoreSnapshotReq = in
	if m.restoreSnapshotErr != nil {
		return nil, m.restoreSnapshotErr
	}
	return &pb.VM{Name: in.VmName}, nil
}

func (m *mockGRPC) DeleteSnapshot(_ context.Context, in *pb.DeleteSnapshotRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteSnapshotReq = in
	if m.deleteSnapshotErr != nil {
		return nil, m.deleteSnapshotErr
	}
	return &emptypb.Empty{}, nil
}

// ── Device actions ───────────────────────────────────────────────────────────

func (m *mockGRPC) AttachDevice(_ context.Context, in *pb.AttachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastAttachDeviceReq = in
	if m.attachDeviceErr != nil {
		return nil, m.attachDeviceErr
	}
	return &pb.VM{Name: in.VmName}, nil
}

func (m *mockGRPC) DetachDevice(_ context.Context, in *pb.DetachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastDetachDeviceReq = in
	if m.detachDeviceErr != nil {
		return nil, m.detachDeviceErr
	}
	return &pb.VM{Name: in.VmName}, nil
}

// ListVMHardware backs the Hardware tab. A settable response
// field lets tests inject disk/NIC/PCI devices; a settable error simulates
// the RPC failing (e.g. VM not found) so the handler's error path is testable.
func (m *mockGRPC) ListVMHardware(_ context.Context, in *pb.ListVMHardwareRequest, _ ...grpc.CallOption) (*pb.ListVMHardwareResponse, error) {
	if m.listVMHardwareErr != nil {
		return nil, m.listVMHardwareErr
	}
	if m.listVMHardwareResp == nil {
		return &pb.ListVMHardwareResponse{}, nil
	}
	return m.listVMHardwareResp, nil
}

func (m *mockGRPC) ResizeDisk(_ context.Context, in *pb.ResizeDiskRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.lastResizeDiskReq = in
	if m.resizeDiskErr != nil {
		return nil, m.resizeDiskErr
	}
	return &pb.VM{Name: in.VmName}, nil
}

// ── Network actions ──────────────────────────────────────────────────────────

func (m *mockGRPC) CreateNetwork(_ context.Context, in *pb.CreateNetworkRequest, _ ...grpc.CallOption) (*pb.NetworkInfo, error) {
	m.lastCreateNetworkReq = in
	return m.createNetworkResp, nil
}

func (m *mockGRPC) GetNetwork(context.Context, *pb.GetNetworkRequest, ...grpc.CallOption) (*pb.NetworkInfo, error) {
	return &pb.NetworkInfo{}, nil
}

func (m *mockGRPC) DeleteNetwork(_ context.Context, in *pb.DeleteNetworkRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteNetworkReq = in
	m.deleteNetworkCalled = true
	if m.deleteNetworkErr != nil {
		return nil, m.deleteNetworkErr
	}
	return &emptypb.Empty{}, nil
}

// ── LB actions ───────────────────────────────────────────────────────────────

func (m *mockGRPC) DeleteLoadBalancer(_ context.Context, in *pb.DeleteLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteLBName = in.Name
	m.deleteLBCalled = true
	if m.deleteLBErr != nil {
		return nil, m.deleteLBErr
	}
	return &emptypb.Empty{}, nil
}

func (m *mockGRPC) DrainBackend(_ context.Context, in *pb.DrainBackendRequest, _ ...grpc.CallOption) (*pb.DrainBackendResponse, error) {
	m.lastDrainReq = in
	if m.drainBackendErr != nil {
		return nil, m.drainBackendErr
	}
	return &pb.DrainBackendResponse{}, nil
}

// ── User actions ─────────────────────────────────────────────────────────────

func (m *mockGRPC) CreateUser(_ context.Context, in *pb.CreateUserRequest, _ ...grpc.CallOption) (*pb.User, error) {
	m.lastCreateUserReq = in
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	return &pb.User{Username: in.Username, Role: in.Role}, nil
}

func (m *mockGRPC) DeleteUser(_ context.Context, in *pb.DeleteUserRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteUserName = in.Username
	m.deleteUserCalled = true
	if m.deleteUserErr != nil {
		return nil, m.deleteUserErr
	}
	return &emptypb.Empty{}, nil
}

func (m *mockGRPC) CreateToken(_ context.Context, in *pb.CreateTokenRequest, _ ...grpc.CallOption) (*pb.Token, error) {
	m.lastCreateTokenReq = in
	if m.createTokenErr != nil {
		return nil, m.createTokenErr
	}
	return &pb.Token{Id: "tok-123", Name: in.Name, Token: "secret-token"}, nil
}

func (m *mockGRPC) RevokeToken(_ context.Context, in *pb.RevokeTokenRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastRevokeTokenID = in.Id
	m.revokeTokenCalled = true
	if m.revokeTokenErr != nil {
		return nil, m.revokeTokenErr
	}
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
func (m *mockGRPC) BeginWebAuthnRegistration(context.Context, *pb.BeginWebAuthnRegistrationRequest, ...grpc.CallOption) (*pb.BeginWebAuthnRegistrationResponse, error) {
	return &pb.BeginWebAuthnRegistrationResponse{OptionsJson: []byte(`{"publicKey":{}}`)}, nil
}
func (m *mockGRPC) FinishWebAuthnRegistration(context.Context, *pb.FinishWebAuthnRegistrationRequest, ...grpc.CallOption) (*pb.FinishWebAuthnRegistrationResponse, error) {
	return &pb.FinishWebAuthnRegistrationResponse{CredentialLabel: "test-label"}, nil
}
func (m *mockGRPC) BeginWebAuthnLogin(context.Context, *pb.BeginWebAuthnLoginRequest, ...grpc.CallOption) (*pb.BeginWebAuthnLoginResponse, error) {
	return &pb.BeginWebAuthnLoginResponse{}, nil
}
func (m *mockGRPC) FinishWebAuthnLogin(context.Context, *pb.FinishWebAuthnLoginRequest, ...grpc.CallOption) (*pb.FinishWebAuthnLoginResponse, error) {
	return &pb.FinishWebAuthnLoginResponse{}, nil
}
func (m *mockGRPC) MoveVolume(_ context.Context, in *pb.MoveVolumeRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MoveVolumeProgress], error) {
	m.lastMoveReq = in
	return &fakeStream[pb.MoveVolumeProgress]{}, nil
}
func (m *mockGRPC) ReplicateVolume(_ context.Context, in *pb.ReplicateVolumeRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ReplicateVolumeProgress], error) {
	m.lastReplicateReq = in
	if m.replicateErr != nil {
		return nil, m.replicateErr
	}
	return &scriptedStream[pb.ReplicateVolumeProgress]{frames: m.replicateFrames}, nil
}
func (m *mockGRPC) MigrateStackVolumes(context.Context, *pb.MigrateStackVolumesRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StackVolumeProgress], error) {
	return nil, nil
}

// ── Stack actions ────────────────────────────────────────────────────────────

func (m *mockGRPC) DeployStack(context.Context, *pb.DeployStackRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	return &fakeStream[pb.DeployProgress]{}, nil
}

func (m *mockGRPC) DeleteStack(context.Context, *pb.DeleteStackRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeleteProgress], error) {
	return &fakeStream[pb.DeleteProgress]{}, nil
}

func (m *mockGRPC) DiffStack(_ context.Context, in *pb.DiffStackRequest, _ ...grpc.CallOption) (*pb.DiffStackResponse, error) {
	if m.diffStackErr != nil {
		return nil, m.diffStackErr
	}
	if m.diffStackResp != nil {
		return m.diffStackResp, nil
	}
	return &pb.DiffStackResponse{}, nil
}

// ── Stubs for RPCs not used by UI ────────────────────────────────────────────

func (m *mockGRPC) ExecVM(context.Context, *pb.ExecVMRequest, ...grpc.CallOption) (*pb.ExecVMResponse, error) {
	return nil, nil
}
func (m *mockGRPC) ConsoleVM(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[pb.ConsoleInput, pb.ConsoleOutput], error) {
	return nil, nil
}
func (m *mockGRPC) SetVMIP(context.Context, *pb.SetVMIPRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, nil
}
func (m *mockGRPC) SetBootOrder(context.Context, *pb.SetBootOrderRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, nil
}
func (m *mockGRPC) RebuildVM(context.Context, *pb.RebuildVMRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, nil
}
func (m *mockGRPC) CutoverVM(context.Context, *pb.CutoverVMRequest, ...grpc.CallOption) (*pb.VM, error) {
	return nil, nil
}
func (m *mockGRPC) MigrateVM(context.Context, *pb.MigrateVMRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	return nil, nil
}
func (m *mockGRPC) StreamEvents(context.Context, *pb.StreamEventsRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ClusterEvent], error) {
	return nil, nil
}
func (m *mockGRPC) ImportImage(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ImportImageRequest, pb.ImportImageResponse], error) {
	return nil, nil
}

// fakeUploadStream records the client-streamed upload for assertions.
type fakeUploadStream struct {
	grpc.ClientStream
	first  *pb.UploadStoragePoolContentRequest
	chunks [][]byte
}

func (f *fakeUploadStream) Send(r *pb.UploadStoragePoolContentRequest) error {
	if f.first == nil {
		f.first = r
	} else {
		f.chunks = append(f.chunks, r.Chunk)
	}
	return nil
}
func (f *fakeUploadStream) CloseAndRecv() (*pb.UploadStoragePoolContentResponse, error) {
	return &pb.UploadStoragePoolContentResponse{Path: "/pool/" + f.first.GetFilename()}, nil
}

func (m *mockGRPC) UploadStoragePoolContent(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	if m.uploadStreamErr != nil {
		return nil, m.uploadStreamErr
	}
	if m.uploadStream == nil {
		m.uploadStream = &fakeUploadStream{}
	}
	return m.uploadStream, nil
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
func (m *mockGRPC) ProxyVNC(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[pb.VNCData, pb.VNCData], error) {
	return nil, nil
}
func (m *mockGRPC) GetClusterStatus(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ClusterStatus, error) {
	if m.clusterStatusResp != nil {
		return m.clusterStatusResp, nil
	}
	return &pb.ClusterStatus{}, nil
}
func (m *mockGRPC) ListStoragePools(context.Context, *pb.ListStoragePoolsRequest, ...grpc.CallOption) (*pb.ListStoragePoolsResponse, error) {
	if m.listStoragePoolsResp != nil {
		return m.listStoragePoolsResp, nil
	}
	return &pb.ListStoragePoolsResponse{}, nil
}

func (m *mockGRPC) ListStoragePoolContents(_ context.Context, in *pb.ListStoragePoolContentsRequest, _ ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	m.lastPoolContentsReq = in
	if m.poolContentsErr != nil {
		return nil, m.poolContentsErr
	}
	if m.poolContentsResp != nil {
		return m.poolContentsResp, nil
	}
	return &pb.ListStoragePoolContentsResponse{}, nil
}
func (m *mockGRPC) DeleteStoragePoolContent(context.Context, *pb.DeleteStoragePoolContentRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) CreateStoragePool(_ context.Context, in *pb.CreateStoragePoolRequest, _ ...grpc.CallOption) (*pb.CreateStoragePoolResponse, error) {
	m.lastCreatePoolReq = in
	if m.createPoolErr != nil {
		return nil, m.createPoolErr
	}
	return &pb.CreateStoragePoolResponse{Pool: &pb.StoragePool{Name: in.Name, Driver: in.Driver, Host: in.Host}}, nil
}
func (m *mockGRPC) DeleteStoragePool(_ context.Context, in *pb.DeleteStoragePoolRequest, _ ...grpc.CallOption) (*pb.DeleteStoragePoolResponse, error) {
	m.lastDeletePoolReq = in
	if m.deletePoolErr != nil {
		return nil, m.deletePoolErr
	}
	return &pb.DeleteStoragePoolResponse{}, nil
}
func (m *mockGRPC) GetStoragePool(context.Context, *pb.GetStoragePoolRequest, ...grpc.CallOption) (*pb.GetStoragePoolResponse, error) {
	return &pb.GetStoragePoolResponse{Pool: &pb.StoragePool{}}, nil
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
	return &pb.StateDigestResponse{}, nil
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
func (m *mockGRPC) CreateLoadBalancer(context.Context, *pb.CreateLBRequest, ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return nil, nil
}
func (m *mockGRPC) UpdateLoadBalancer(context.Context, *pb.UpdateLBRequest, ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return nil, nil
}
func (m *mockGRPC) DisableBackend(context.Context, *pb.DisableBackendRequest, ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return nil, nil
}
func (m *mockGRPC) EnableBackend(context.Context, *pb.EnableBackendRequest, ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return nil, nil
}
func (m *mockGRPC) ApplyLB(context.Context, *pb.ApplyLBRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
}
func (m *mockGRPC) RemoveLB(context.Context, *pb.RemoveLBRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, nil
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

func (m *mockGRPC) ListRebalanceProposals(_ context.Context, in *pb.ListRebalanceProposalsRequest, _ ...grpc.CallOption) (*pb.ListRebalanceProposalsResponse, error) {
	m.lastListRebalanceReq = in
	if m.listRebalanceResp != nil {
		return m.listRebalanceResp, nil
	}
	return &pb.ListRebalanceProposalsResponse{}, nil
}
func (m *mockGRPC) RunRebalance(_ context.Context, in *pb.RunRebalanceRequest, _ ...grpc.CallOption) (*pb.RunRebalanceResponse, error) {
	m.lastRunRebalanceReq = in
	if m.runRebalanceErr != nil {
		return nil, m.runRebalanceErr
	}
	if m.runRebalanceResp != nil {
		return m.runRebalanceResp, nil
	}
	return &pb.RunRebalanceResponse{}, nil
}
func (m *mockGRPC) ApproveRebalanceProposal(_ context.Context, in *pb.ApproveRebalanceProposalRequest, _ ...grpc.CallOption) (*pb.RebalanceProposal, error) {
	m.lastApproveID = in.Id
	if m.approveRebalanceErr != nil {
		return nil, m.approveRebalanceErr
	}
	if m.approveRebalanceResp != nil {
		return m.approveRebalanceResp, nil
	}
	return &pb.RebalanceProposal{Id: in.Id}, nil
}
func (m *mockGRPC) RejectRebalanceProposal(_ context.Context, in *pb.RejectRebalanceProposalRequest, _ ...grpc.CallOption) (*pb.RebalanceProposal, error) {
	m.lastRejectReq = in
	if m.rejectRebalanceErr != nil {
		return nil, m.rejectRebalanceErr
	}
	return &pb.RebalanceProposal{Id: in.Id, Detail: in.Reason}, nil
}
func (m *mockGRPC) GetSpiceInfo(context.Context, *pb.GetSpiceInfoRequest, ...grpc.CallOption) (*pb.GetSpiceInfoResponse, error) {
	if m.spiceInfoErr != nil {
		return nil, m.spiceInfoErr
	}
	if m.spiceInfoResp != nil {
		return m.spiceInfoResp, nil
	}
	return &pb.GetSpiceInfoResponse{}, nil
}
func (m *mockGRPC) PreflightUpgrade(context.Context, *pb.PreflightUpgradeRequest, ...grpc.CallOption) (*pb.PreflightUpgradeResponse, error) {
	return &pb.PreflightUpgradeResponse{Ok: true}, nil
}

// ── fakeStream ───────────────────────────────────────────────────────────────

// fakeStream implements grpc.ServerStreamingClient, returning io.EOF immediately.
type fakeStream[T any] struct {
	grpc.ClientStream
}

func (f *fakeStream[T]) Recv() (*T, error) {
	return nil, io.EOF
}

func (f *fakeStream[T]) Header() (metadata.MD, error) { return nil, nil }
func (f *fakeStream[T]) Trailer() metadata.MD         { return nil }
func (f *fakeStream[T]) CloseSend() error             { return nil }
func (f *fakeStream[T]) Context() context.Context     { return context.Background() }

// scriptedStream replays a fixed slice of frames, then io.EOF. Used to drive the
// streaming RPC handlers (e.g. ReplicateVolume) through their progress loops.
type scriptedStream[T any] struct {
	grpc.ClientStream
	frames []*T
	i      int
}

func (s *scriptedStream[T]) Recv() (*T, error) {
	if s.i >= len(s.frames) {
		return nil, io.EOF
	}
	f := s.frames[s.i]
	s.i++
	return f, nil
}

func (s *scriptedStream[T]) Header() (metadata.MD, error) { return nil, nil }
func (s *scriptedStream[T]) Trailer() metadata.MD         { return nil }
func (s *scriptedStream[T]) CloseSend() error             { return nil }
func (s *scriptedStream[T]) Context() context.Context     { return context.Background() }

// ── Test helpers ─────────────────────────────────────────────────────────────

// newTestUIServer creates a Server with the given mock, validating template parsing.
func newTestUIServer(t *testing.T, mock *mockGRPC) *Server {
	t.Helper()
	s, err := NewServer(mock, "test-cluster")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// withAuth adds a valid session cookie to the request.
func withAuth(r *http.Request) *http.Request {
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-token"})
	return r
}

// serveRequest sends a request through the server's handler and returns the response.
func serveRequest(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// newDefaultMock creates a mockGRPC with sensible default responses for common list endpoints.
func newDefaultMock() *mockGRPC {
	return &mockGRPC{
		listHostsResp: &pb.ListHostsResponse{
			Hosts: []*pb.Host{{Name: "host1", State: pb.HostState_HOST_ACTIVE, CpuTotal: 16, CpuUsed: 8, MemTotalMib: 32768, MemUsedMib: 16384}},
		},
		listVMsResp: &pb.ListVMsResponse{
			Vms: []*pb.VM{{Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1"}, {Name: "vm2", State: pb.VMState_VM_STOPPED}},
		},
		inspectHostResp:     &pb.Host{Name: "host1", State: pb.HostState_HOST_ACTIVE, CpuTotal: 16, CpuUsed: 8, MemTotalMib: 32768, MemUsedMib: 16384},
		inspectVMResp:       &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1", Spec: &pb.VMSpec{}},
		listStacksResp:      &pb.ListStacksResponse{Stacks: []*pb.StackSummary{{Name: "mystack"}}},
		listImagesResp:      &pb.ListImagesResponse{Images: []*pb.Image{{Name: "ubuntu", Status: "ready"}}},
		listUsersResp:       &pb.ListUsersResponse{Users: []*pb.User{{Username: "admin", Role: "admin"}}},
		listNetworksResp:    &pb.ListNetworksResponse{Networks: []*pb.NetworkInfo{{Name: "br0"}}},
		listLBsResp:         &pb.ListLBResponse{Lbs: []*pb.LoadBalancer{{Name: "lb1"}}},
		inspectLBResp:       &pb.LoadBalancer{Name: "lb1"},
		auditLogResp:        &pb.ListAuditLogResponse{},
		loginResp:           &pb.LoginResponse{Token: "session-token-123"},
		vmStatsResp:         &pb.VMStats{},
		hostStatsResp:       &pb.HostResourceStats{},
		lbStatsResp:         &pb.LBStatsResponse{},
		fenceHostResp:       &pb.FenceResult{Method: "ipmi", Result: "success"},
		listHostDevicesResp: &pb.ListHostDevicesResponse{},
		listSnapshotsResp:   &pb.ListSnapshotsResponse{},
		diffStackResp:       &pb.DiffStackResponse{},
	}
}

// assertStatus checks the response status code.
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("status = %d, want %d; body = %s", w.Code, want, truncBody(w))
	}
}

// assertRedirect checks for a redirect to the given URL.
func assertRedirect(t *testing.T, w *httptest.ResponseRecorder, wantURL string) {
	t.Helper()
	loc := w.Header().Get("Location")
	if loc == "" {
		loc = w.Header().Get("HX-Redirect")
	}
	if loc != wantURL {
		t.Errorf("redirect = %q, want %q (status=%d)", loc, wantURL, w.Code)
	}
}

// assertContains checks that the response body contains a substring.
func assertContains(t *testing.T, w *httptest.ResponseRecorder, substr string) {
	t.Helper()
	body := w.Body.String()
	for i := 0; i <= len(body)-len(substr); i++ {
		if body[i:i+len(substr)] == substr {
			return
		}
	}
	t.Errorf("response body does not contain %q (len=%d)", substr, len(body))
}

// assertHXRedirect checks for an HX-Redirect header.
func assertHXRedirect(t *testing.T, w *httptest.ResponseRecorder, wantURL string) {
	t.Helper()
	loc := w.Header().Get("HX-Redirect")
	if loc != wantURL {
		t.Errorf("HX-Redirect = %q, want %q", loc, wantURL)
	}
}

// truncBody returns the first 200 bytes of the response body for error messages.
func truncBody(w *httptest.ResponseRecorder) string {
	body := w.Body.String()
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
}

// mustReq creates an HTTP request or fails the test.
func mustReq(t *testing.T, method, path string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%s %s): %v", method, path, err)
	}
	return r
}

// doPOSTForm submits an application/x-www-form-urlencoded POST through the
// server's handler (with a valid auth cookie) and returns the response.
func doPOSTForm(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("http.NewRequest(POST %s): %v", path, err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return serveRequest(s, withAuth(r))
}

// doGET issues an authenticated GET through the server's handler and returns
// the response body as a string.
func doGET(t *testing.T, s *Server, path string) string {
	t.Helper()
	return serveRequest(s, withAuth(mustReq(t, "GET", path))).Body.String()
}

// errorf is a helper for tests that need a formatted error.
var errSimulated = fmt.Errorf("simulated error")

// federation mocks.
func (m *mockGRPC) ListRegions(context.Context, *pb.ListRegionsRequest, ...grpc.CallOption) (*pb.ListRegionsResponse, error) {
	return &pb.ListRegionsResponse{}, nil
}
func (m *mockGRPC) RegionStatus(context.Context, *pb.RegionStatusRequest, ...grpc.CallOption) (*pb.RegionStatusResponse, error) {
	return &pb.RegionStatusResponse{}, nil
}
func (m *mockGRPC) CrossRegionMigrate(context.Context, *pb.CrossRegionMigrateRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	return nil, fmt.Errorf("not implemented in mock")
}

// tenancy mocks.
func (m *mockGRPC) CreateProject(_ context.Context, in *pb.CreateProjectRequest, _ ...grpc.CallOption) (*pb.Project, error) {
	m.lastCreateProjectReq = in
	if m.createProjectErr != nil {
		return nil, m.createProjectErr
	}
	return &pb.Project{Name: in.Name, Display: in.Display, ParentName: in.ParentName}, nil
}
func (m *mockGRPC) ListProjects(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ListProjectsResponse, error) {
	if m.listProjectsErr != nil {
		return nil, m.listProjectsErr
	}
	if m.listProjectsResp != nil {
		return m.listProjectsResp, nil
	}
	return &pb.ListProjectsResponse{}, nil
}
func (m *mockGRPC) GetProject(context.Context, *pb.GetProjectRequest, ...grpc.CallOption) (*pb.Project, error) {
	return &pb.Project{}, nil
}
func (m *mockGRPC) DeleteProject(_ context.Context, in *pb.DeleteProjectRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteProjectReq = in
	if m.deleteProjectErr != nil {
		return nil, m.deleteProjectErr
	}
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) SetProjectQuota(_ context.Context, in *pb.SetProjectQuotaRequest, _ ...grpc.CallOption) (*pb.ProjectQuota, error) {
	m.lastSetQuotaReq = in
	if m.setProjectQuotaErr != nil {
		return nil, m.setProjectQuotaErr
	}
	return in.Quota, nil
}
func (m *mockGRPC) GetProjectQuota(_ context.Context, in *pb.GetProjectQuotaRequest, _ ...grpc.CallOption) (*pb.ProjectQuota, error) {
	if m.getProjectQuotaErr != nil {
		return nil, m.getProjectQuotaErr
	}
	if m.getProjectQuotaResp != nil {
		return m.getProjectQuotaResp, nil
	}
	return &pb.ProjectQuota{ProjectName: in.ProjectName}, nil
}
func (m *mockGRPC) GetProjectUsage(_ context.Context, in *pb.GetProjectUsageRequest, _ ...grpc.CallOption) (*pb.ProjectUsage, error) {
	if m.getProjectUsageResp != nil {
		return m.getProjectUsageResp, nil
	}
	return &pb.ProjectUsage{ProjectName: in.ProjectName}, nil
}

// audit chain mocks.
func (m *mockGRPC) VerifyAuditChain(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.VerifyAuditChainResponse, error) {
	if m.verifyAuditErr != nil {
		return nil, m.verifyAuditErr
	}
	if m.verifyAuditResp != nil {
		return m.verifyAuditResp, nil
	}
	return &pb.VerifyAuditChainResponse{}, nil
}
func (m *mockGRPC) ExportAuditChain(_ context.Context, in *pb.ExportAuditChainRequest, _ ...grpc.CallOption) (*pb.ExportAuditChainResponse, error) {
	m.lastExportReq = in
	if m.exportAuditErr != nil {
		return nil, m.exportAuditErr
	}
	if m.exportAuditResp != nil {
		return m.exportAuditResp, nil
	}
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
func (m *mockGRPC) CreateBackupSchedule(_ context.Context, in *pb.CreateBackupScheduleRequest, _ ...grpc.CallOption) (*pb.BackupSchedule, error) {
	m.lastCreateScheduleReq = in
	if m.createScheduleErr != nil {
		return nil, m.createScheduleErr
	}
	return &pb.BackupSchedule{VmName: in.VmName, Repo: in.Repo, Cron: in.Cron}, nil
}
func (m *mockGRPC) ListBackupSchedules(context.Context, *pb.ListBackupSchedulesRequest, ...grpc.CallOption) (*pb.ListBackupSchedulesResponse, error) {
	if m.listSchedulesResp != nil {
		return m.listSchedulesResp, nil
	}
	return &pb.ListBackupSchedulesResponse{}, nil
}
func (m *mockGRPC) CreateReplicationSchedule(_ context.Context, in *pb.CreateReplicationScheduleRequest, _ ...grpc.CallOption) (*pb.ReplicationSchedule, error) {
	m.lastCreateReplReq = in
	if m.createReplErr != nil {
		return nil, m.createReplErr
	}
	return &pb.ReplicationSchedule{VmName: in.VmName, Cron: in.Cron, TargetPool: in.TargetPool, TargetHost: in.TargetHost, KeepReplicas: in.KeepReplicas, Enabled: in.Enabled, Scope: in.Scope}, nil
}
func (m *mockGRPC) ListReplicationSchedules(context.Context, *pb.ListReplicationSchedulesRequest, ...grpc.CallOption) (*pb.ListReplicationSchedulesResponse, error) {
	if m.listReplSchedulesResp != nil {
		return m.listReplSchedulesResp, nil
	}
	return &pb.ListReplicationSchedulesResponse{}, nil
}
func (m *mockGRPC) DeleteReplicationSchedule(_ context.Context, in *pb.DeleteReplicationScheduleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteReplReq = in
	return &emptypb.Empty{}, nil
}
func (m *mockGRPC) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	return nil, nil
}
func (m *mockGRPC) PromoteReplica(_ context.Context, in *pb.PromoteReplicaRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PromoteReplicaProgress], error) {
	m.lastPromoteReq = in
	if m.promoteErr != nil {
		return nil, m.promoteErr
	}
	return &scriptedStream[pb.PromoteReplicaProgress]{frames: []*pb.PromoteReplicaProgress{
		{Phase: pb.PromoteReplicaProgress_DONE, VmName: in.GetVmName(), Host: "host-b", Status: "promotion complete"},
	}}, nil
}
func (m *mockGRPC) DeleteBackupSchedule(_ context.Context, in *pb.DeleteBackupScheduleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.lastDeleteScheduleReq = in
	if m.deleteScheduleErr != nil {
		return nil, m.deleteScheduleErr
	}
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
