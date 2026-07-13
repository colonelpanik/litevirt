package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// fakeStream is a server-stream that yields io.EOF immediately, so commands
// with a Recv loop run cleanly in tests. Only Recv is exercised by the CLI.
type fakeStream[T any] struct{ grpc.ClientStream }

func (f *fakeStream[T]) Recv() (*T, error)            { return nil, io.EOF }
func (f *fakeStream[T]) Header() (metadata.MD, error) { return nil, nil }
func (f *fakeStream[T]) Trailer() metadata.MD         { return nil }
func (f *fakeStream[T]) CloseSend() error             { return nil }
func (f *fakeStream[T]) Context() context.Context     { return context.Background() }

// ── Mock gRPC client ────────────────────────────────────────────────────────

type mockClient struct {
	// Embed the client interface so RPCs the mock doesn't exercise (e.g. the
	// firewall management calls) are satisfied without a hand-written stub.
	pb.LiteVirtClient

	// Canned responses
	vms       []*pb.VM
	hosts     []*pb.Host
	images    []*pb.Image
	snapshots []*pb.Snapshot
	users     []*pb.User
	devices   []*pb.PCIDevice
	status    *pb.ClusterStatus

	// Track mutations
	createdVM     *pb.VMSpec
	startedVM     string
	stoppedVM     string
	restartedVM   string
	deletedVM     string
	deletedImage  string
	createdSnap   *pb.CreateSnapshotRequest
	restoredSnap  *pb.RestoreSnapshotRequest
	deletedSnap   *pb.DeleteSnapshotRequest
	deletedUser   string
	fencedHost    string
	undrainedHost string
	removedHost   string
	rescannedHost string
}

func newMockClient() *mockClient {
	return &mockClient{
		hosts: []*pb.Host{
			{
				Name: "host-a", Address: "10.0.50.10",
				State:   pb.HostState_HOST_ACTIVE,
				CpuUsed: 4, CpuTotal: 16,
				MemUsedMib: 8192, MemTotalMib: 65536,
				VmCount: 2,
			},
			{
				Name: "host-b", Address: "10.0.50.11",
				State:   pb.HostState_HOST_ACTIVE,
				CpuUsed: 2, CpuTotal: 16,
				MemUsedMib: 4096, MemTotalMib: 65536,
				VmCount: 1,
			},
		},
		vms: []*pb.VM{
			{
				Name: "web-1", HostName: "host-a",
				State:     pb.VMState_VM_RUNNING,
				CpuActual: 2, MemActualMib: 4096,
				VncAddress: "10.0.50.10:5900",
				Interfaces: []*pb.VMInterface{{NetworkName: "default", Mac: "52:54:00:aa:bb:cc", Ip: "10.0.50.100"}},
				Disks:      []*pb.VMDisk{{Name: "root", SizeBytes: 21474836480, StorageType: "local"}},
			},
			{
				Name: "web-2", HostName: "host-a",
				State:     pb.VMState_VM_STOPPED,
				CpuActual: 4, MemActualMib: 8192,
				Interfaces: []*pb.VMInterface{{NetworkName: "default", Mac: "52:54:00:dd:ee:ff"}},
			},
			{
				Name: "db-1", HostName: "host-b",
				State:     pb.VMState_VM_RUNNING,
				CpuActual: 8, MemActualMib: 16384,
				Interfaces: []*pb.VMInterface{{NetworkName: "default", Mac: "52:54:00:11:22:33", Ip: "10.0.50.101"}},
			},
		},
		images: []*pb.Image{
			{Name: "ubuntu-24.04", Format: "qcow2", SizeBytes: 629380096, Hosts: []string{"host-a", "host-b"}},
			{Name: "debian-12", Format: "qcow2", SizeBytes: 524288000, Hosts: []string{"host-a"}},
		},
		snapshots: []*pb.Snapshot{
			{Id: "snap-001", Name: "before-upgrade", VmName: "web-1", State: "completed",
				SizeBytes: 1073741824, CreatedAt: timestamppb.Now()},
		},
		users: []*pb.User{
			{Username: "admin", Role: "admin", CreatedAt: timestamppb.Now()},
			{Username: "deploy-bot", Role: "operator", CreatedAt: timestamppb.Now()},
		},
		devices: []*pb.PCIDevice{
			{Address: "0000:41:00.0", Type: "gpu", VendorId: "10de", DeviceId: "2204", Driver: "vfio-pci", IommuGroup: 42},
		},
		status: &pb.ClusterStatus{
			HostsTotal: 2, HostsActive: 2,
			VmsTotal: 3, VmsRunning: 2,
		},
	}
}

// ── Host RPCs ──

func (m *mockClient) ListHosts(_ context.Context, _ *pb.ListHostsRequest, _ ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: m.hosts}, nil
}
func (m *mockClient) InspectHost(_ context.Context, in *pb.InspectHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	for _, h := range m.hosts {
		if h.Name == in.Name {
			return h, nil
		}
	}
	return m.hosts[0], nil
}
func (m *mockClient) DrainHost(_ context.Context, _ *pb.DrainHostRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DrainProgress], error) {
	return &fakeStream[pb.DrainProgress]{}, nil
}
func (m *mockClient) UndrainHost(_ context.Context, in *pb.UndrainHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	m.undrainedHost = in.Name
	return &pb.Host{Name: in.Name, State: pb.HostState_HOST_ACTIVE}, nil
}
func (m *mockClient) SetHostLabels(_ context.Context, in *pb.SetHostLabelsRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	return &pb.Host{Name: in.Name, Labels: in.Labels}, nil
}
func (m *mockClient) FenceHost(_ context.Context, in *pb.FenceHostRequest, _ ...grpc.CallOption) (*pb.FenceResult, error) {
	m.fencedHost = in.Name
	return &pb.FenceResult{HostName: in.Name, Method: "ipmi", Result: "success", Detail: "power cycled"}, nil
}
func (m *mockClient) GetHostHealth(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.HostHealthMatrix, error) {
	return &pb.HostHealthMatrix{}, nil
}
func (m *mockClient) RemoveHost(_ context.Context, in *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.removedHost = in.Name
	return &emptypb.Empty{}, nil
}
func (m *mockClient) RescanHost(_ context.Context, in *pb.RescanHostRequest, _ ...grpc.CallOption) (*pb.RescanHostResponse, error) {
	m.rescannedHost = in.Name
	return &pb.RescanHostResponse{Added: 1, Removed: 0, Total: 5}, nil
}
func (m *mockClient) ListHostDevices(_ context.Context, _ *pb.ListHostDevicesRequest, _ ...grpc.CallOption) (*pb.ListHostDevicesResponse, error) {
	return &pb.ListHostDevicesResponse{Devices: m.devices}, nil
}
func (m *mockClient) ConfigureHost(_ context.Context, in *pb.ConfigureHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	return &pb.Host{Name: in.Name, State: pb.HostState_HOST_ACTIVE}, nil
}

// ── VM RPCs ──

func (m *mockClient) CreateVM(_ context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.createdVM = in.Spec
	return &pb.VM{Name: in.Spec.Name, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) ListVMs(_ context.Context, in *pb.ListVMsRequest, _ ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	var filtered []*pb.VM
	for _, vm := range m.vms {
		if in.HostName != "" && vm.HostName != in.HostName {
			continue
		}
		filtered = append(filtered, vm)
	}
	return &pb.ListVMsResponse{Vms: filtered}, nil
}
func (m *mockClient) InspectVM(_ context.Context, in *pb.InspectVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	for _, vm := range m.vms {
		if vm.Name == in.Name {
			return vm, nil
		}
	}
	return m.vms[0], nil
}
func (m *mockClient) StartVM(_ context.Context, in *pb.StartVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.startedVM = in.Name
	return &pb.VM{Name: in.Name, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) StopVM(_ context.Context, in *pb.StopVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.stoppedVM = in.Name
	return &pb.VM{Name: in.Name, HostName: "host-a", State: pb.VMState_VM_STOPPED}, nil
}
func (m *mockClient) RestartVM(_ context.Context, in *pb.RestartVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.restartedVM = in.Name
	return &pb.VM{Name: in.Name, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) DeleteVM(_ context.Context, in *pb.DeleteVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.deletedVM = in.Name
	return &emptypb.Empty{}, nil
}
func (m *mockClient) CloneVM(_ context.Context, in *pb.CloneVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Target, State: pb.VMState_VM_STOPPED}, nil
}
func (m *mockClient) ConvertToTemplate(_ context.Context, in *pb.ConvertToTemplateRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, IsTemplate: !in.Revert}, nil
}
func (m *mockClient) Whoami(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.WhoamiResponse, error) {
	return &pb.WhoamiResponse{Username: "admin", Role: "admin", Realm: "local"}, nil
}
func (m *mockClient) ChangePassword(_ context.Context, _ *pb.ChangePasswordRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ExecVM(_ context.Context, in *pb.ExecVMRequest, _ ...grpc.CallOption) (*pb.ExecVMResponse, error) {
	return &pb.ExecVMResponse{Stdout: []byte("hello from " + in.Name + "\n")}, nil
}
func (m *mockClient) ConsoleVM(_ context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[pb.ConsoleInput, pb.ConsoleOutput], error) {
	return nil, nil
}
func (m *mockClient) SetVMIP(_ context.Context, in *pb.SetVMIPRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, State: pb.VMState_VM_STOPPED}, nil
}
func (m *mockClient) SetBootOrder(_ context.Context, in *pb.SetBootOrderRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, State: pb.VMState_VM_STOPPED}, nil
}
func (m *mockClient) RebuildVM(_ context.Context, in *pb.RebuildVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) CutoverVM(_ context.Context, in *pb.CutoverVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.VmName, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) AttachDevice(_ context.Context, in *pb.AttachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.VmName, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) DetachDevice(_ context.Context, in *pb.DetachDeviceRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.VmName, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}
func (m *mockClient) ResizeDisk(_ context.Context, in *pb.ResizeDiskRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.VmName, HostName: "host-a", State: pb.VMState_VM_RUNNING}, nil
}

// ── Stack RPCs ──

func (m *mockClient) DeployStack(_ context.Context, _ *pb.DeployStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	return &fakeStream[pb.DeployProgress]{}, nil
}
func (m *mockClient) DeleteStack(_ context.Context, _ *pb.DeleteStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeleteProgress], error) {
	return &fakeStream[pb.DeleteProgress]{}, nil
}
func (m *mockClient) ListStacks(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListStacksResponse, error) {
	return &pb.ListStacksResponse{}, nil
}
func (m *mockClient) DiffStack(_ context.Context, _ *pb.DiffStackRequest, _ ...grpc.CallOption) (*pb.DiffStackResponse, error) {
	return &pb.DiffStackResponse{}, nil
}

// ── Migration ──

func (m *mockClient) MigrateVM(_ context.Context, _ *pb.MigrateVMRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	return &fakeStream[pb.MigrateProgress]{}, nil
}

// ── Images ──

func (m *mockClient) PullImage(_ context.Context, _ *pb.PullImageRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PullProgress], error) {
	return &fakeStream[pb.PullProgress]{}, nil
}
func (m *mockClient) ListImages(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListImagesResponse, error) {
	return &pb.ListImagesResponse{Images: m.images}, nil
}
func (m *mockClient) DeleteImage(_ context.Context, in *pb.DeleteImageRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.deletedImage = in.Name
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ImportImage(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ImportImageRequest, pb.ImportImageResponse], error) {
	return nil, nil
}
func (m *mockClient) PushImage(_ context.Context, _ *pb.PushImageRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PushImageProgress], error) {
	return &fakeStream[pb.PushImageProgress]{}, nil
}
func (m *mockClient) BuildImage(_ context.Context, in *pb.BuildImageRequest, _ ...grpc.CallOption) (*pb.BuildImageResponse, error) {
	return &pb.BuildImageResponse{Name: in.ImageName, SizeBytes: 1073741824}, nil
}

// ── Backup ──

func (m *mockClient) BackupVM(_ context.Context, _ *pb.BackupVMRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.BackupChunk], error) {
	return &fakeStream[pb.BackupChunk]{}, nil
}
func (m *mockClient) RestoreVM(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.RestoreVMRequest, pb.VM], error) {
	return nil, nil
}

// ── Snapshots ──

func (m *mockClient) CreateSnapshot(_ context.Context, in *pb.CreateSnapshotRequest, _ ...grpc.CallOption) (*pb.Snapshot, error) {
	m.createdSnap = in
	return &pb.Snapshot{Name: in.Name, VmName: in.VmName, State: "completed"}, nil
}
func (m *mockClient) SetVMMemory(_ context.Context, in *pb.SetVMMemoryRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name}, nil
}
func (m *mockClient) CreateResourceMapping(_ context.Context, in *pb.CreateResourceMappingRequest, _ ...grpc.CallOption) (*pb.ResourceMapping, error) {
	return &pb.ResourceMapping{Name: in.Name, Description: in.Description}, nil
}
func (m *mockClient) ListResourceMappings(_ context.Context, _ *pb.ListResourceMappingsRequest, _ ...grpc.CallOption) (*pb.ListResourceMappingsResponse, error) {
	return &pb.ListResourceMappingsResponse{}, nil
}
func (m *mockClient) DeleteResourceMapping(_ context.Context, _ *pb.DeleteResourceMappingRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) AddMappingDevice(_ context.Context, in *pb.AddMappingDeviceRequest, _ ...grpc.CallOption) (*pb.ResourceMapping, error) {
	return &pb.ResourceMapping{Name: in.Mapping}, nil
}
func (m *mockClient) RemoveMappingDevice(_ context.Context, in *pb.RemoveMappingDeviceRequest, _ ...grpc.CallOption) (*pb.ResourceMapping, error) {
	return &pb.ResourceMapping{Name: in.Mapping}, nil
}
func (m *mockClient) ListSnapshots(_ context.Context, in *pb.ListSnapshotsRequest, _ ...grpc.CallOption) (*pb.ListSnapshotsResponse, error) {
	return &pb.ListSnapshotsResponse{Snapshots: m.snapshots}, nil
}
func (m *mockClient) RestoreSnapshot(_ context.Context, in *pb.RestoreSnapshotRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.restoredSnap = in
	return &pb.VM{Name: in.VmName, HostName: "host-a", State: pb.VMState_VM_STOPPED}, nil
}
func (m *mockClient) DeleteSnapshot(_ context.Context, in *pb.DeleteSnapshotRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.deletedSnap = in
	return &emptypb.Empty{}, nil
}

// ── Load Balancers ──

func (m *mockClient) ListLoadBalancers(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListLBResponse, error) {
	return &pb.ListLBResponse{}, nil
}
func (m *mockClient) InspectLoadBalancer(_ context.Context, _ *pb.InspectLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return &pb.LoadBalancer{}, nil
}
func (m *mockClient) DisableBackend(_ context.Context, _ *pb.DisableBackendRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return &pb.LoadBalancer{}, nil
}
func (m *mockClient) EnableBackend(_ context.Context, _ *pb.EnableBackendRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return &pb.LoadBalancer{}, nil
}
func (m *mockClient) ApplyLB(_ context.Context, _ *pb.ApplyLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) RemoveLB(_ context.Context, _ *pb.RemoveLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// ── Users & Auth ──

func (m *mockClient) Login(_ context.Context, _ *pb.LoginRequest, _ ...grpc.CallOption) (*pb.LoginResponse, error) {
	return &pb.LoginResponse{Token: "tok-abc", Username: "admin", Role: "admin"}, nil
}
func (m *mockClient) ListRealms(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListRealmsResponse, error) {
	return &pb.ListRealmsResponse{Realms: []string{"local"}}, nil
}
func (m *mockClient) BindSecurityGroups(_ context.Context, _ *pb.BindSecurityGroupsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ReloadFirewall(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.FirewallStatus, error) {
	return &pb.FirewallStatus{}, nil
}
func (m *mockClient) CreateContainer(_ context.Context, in *pb.CreateContainerRequest, _ ...grpc.CallOption) (*pb.Container, error) {
	host := in.HostName
	if host == "" {
		host = "host-a"
	}
	return &pb.Container{Name: in.Name, HostName: host, State: "stopped"}, nil
}
func (m *mockClient) StartContainer(_ context.Context, _ *pb.StartContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) StopContainer(_ context.Context, _ *pb.StopContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) DeleteContainer(_ context.Context, _ *pb.DeleteContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ExecContainer(_ context.Context, _ *pb.ExecContainerRequest, _ ...grpc.CallOption) (*pb.ExecContainerResponse, error) {
	return &pb.ExecContainerResponse{}, nil
}
func (m *mockClient) ListContainers(_ context.Context, _ *pb.ListContainersRequest, _ ...grpc.CallOption) (*pb.ListContainersResponse, error) {
	return &pb.ListContainersResponse{Containers: []*pb.Container{
		{HostName: "host-a", Name: "ct-1", State: "running", Image: "alpine:3.19", CpuLimit: 1, MemoryMib: 512},
	}}, nil
}
func (m *mockClient) PullOCIImage(_ context.Context, _ *pb.PullOCIImageRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) BackupSnapshot(_ context.Context, _ *pb.BackupSnapshotRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.BackupSnapshotProgress], error) {
	return &fakeStream[pb.BackupSnapshotProgress]{}, nil
}
func (m *mockClient) RestoreFromBackup(_ context.Context, _ *pb.RestoreFromBackupRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreFromBackupProgress], error) {
	return &fakeStream[pb.RestoreFromBackupProgress]{}, nil
}
func (m *mockClient) RestoreLive(_ context.Context, _ *pb.RestoreLiveRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.RestoreLiveProgress], error) {
	return &fakeStream[pb.RestoreLiveProgress]{}, nil
}
func (m *mockClient) GrantRole(_ context.Context, _ *pb.GrantRoleRequest, _ ...grpc.CallOption) (*pb.GrantRoleResponse, error) {
	return &pb.GrantRoleResponse{Binding: &pb.RoleBinding{}}, nil
}
func (m *mockClient) RevokeRole(_ context.Context, _ *pb.RevokeRoleRequest, _ ...grpc.CallOption) (*pb.RevokeRoleResponse, error) {
	return &pb.RevokeRoleResponse{}, nil
}
func (m *mockClient) ListRoleBindings(_ context.Context, _ *pb.ListRoleBindingsRequest, _ ...grpc.CallOption) (*pb.ListRoleBindingsResponse, error) {
	return &pb.ListRoleBindingsResponse{}, nil
}
func (m *mockClient) BeginWebAuthnRegistration(_ context.Context, _ *pb.BeginWebAuthnRegistrationRequest, _ ...grpc.CallOption) (*pb.BeginWebAuthnRegistrationResponse, error) {
	return &pb.BeginWebAuthnRegistrationResponse{}, nil
}
func (m *mockClient) FinishWebAuthnRegistration(_ context.Context, _ *pb.FinishWebAuthnRegistrationRequest, _ ...grpc.CallOption) (*pb.FinishWebAuthnRegistrationResponse, error) {
	return &pb.FinishWebAuthnRegistrationResponse{}, nil
}
func (m *mockClient) BeginWebAuthnLogin(_ context.Context, _ *pb.BeginWebAuthnLoginRequest, _ ...grpc.CallOption) (*pb.BeginWebAuthnLoginResponse, error) {
	return &pb.BeginWebAuthnLoginResponse{}, nil
}
func (m *mockClient) FinishWebAuthnLogin(_ context.Context, _ *pb.FinishWebAuthnLoginRequest, _ ...grpc.CallOption) (*pb.FinishWebAuthnLoginResponse, error) {
	return &pb.FinishWebAuthnLoginResponse{}, nil
}
func (m *mockClient) CreateUser(_ context.Context, in *pb.CreateUserRequest, _ ...grpc.CallOption) (*pb.User, error) {
	return &pb.User{Username: in.Username, Role: in.Role}, nil
}
func (m *mockClient) ListUsers(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListUsersResponse, error) {
	return &pb.ListUsersResponse{Users: m.users}, nil
}
func (m *mockClient) DeleteUser(_ context.Context, in *pb.DeleteUserRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	m.deletedUser = in.Username
	return &emptypb.Empty{}, nil
}
func (m *mockClient) CreateToken(_ context.Context, in *pb.CreateTokenRequest, _ ...grpc.CallOption) (*pb.Token, error) {
	return &pb.Token{Id: "tok-001", Token: "secret-token-value"}, nil
}
func (m *mockClient) RevokeToken(_ context.Context, _ *pb.RevokeTokenRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) Logout(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ListSessions(_ context.Context, _ *pb.ListSessionsRequest, _ ...grpc.CallOption) (*pb.ListSessionsResponse, error) {
	return &pb.ListSessionsResponse{}, nil
}
func (m *mockClient) RevokeSession(_ context.Context, _ *pb.RevokeSessionRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ListTwoFactors(_ context.Context, _ *pb.ListTwoFactorsRequest, _ ...grpc.CallOption) (*pb.ListTwoFactorsResponse, error) {
	return &pb.ListTwoFactorsResponse{}, nil
}
func (m *mockClient) EnrollTOTP(_ context.Context, _ *pb.EnrollTOTPRequest, _ ...grpc.CallOption) (*pb.EnrollTOTPResponse, error) {
	return &pb.EnrollTOTPResponse{}, nil
}
func (m *mockClient) DisableTwoFactor(_ context.Context, _ *pb.DisableTwoFactorRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) MoveVolume(_ context.Context, _ *pb.MoveVolumeRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MoveVolumeProgress], error) {
	return nil, nil
}
func (m *mockClient) ReplicateVolume(_ context.Context, _ *pb.ReplicateVolumeRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ReplicateVolumeProgress], error) {
	return nil, nil
}
func (m *mockClient) MigrateStackVolumes(_ context.Context, _ *pb.MigrateStackVolumesRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StackVolumeProgress], error) {
	return &fakeStream[pb.StackVolumeProgress]{}, nil
}

// ── Stats ──

func (m *mockClient) GetVMStats(_ context.Context, _ *pb.GetVMStatsRequest, _ ...grpc.CallOption) (*pb.VMStats, error) {
	return &pb.VMStats{}, nil
}
func (m *mockClient) GetHostStats(_ context.Context, _ *pb.GetHostStatsRequest, _ ...grpc.CallOption) (*pb.HostResourceStats, error) {
	return &pb.HostResourceStats{}, nil
}

// ── Monitoring ──

func (m *mockClient) GetClusterStatus(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ClusterStatus, error) {
	return m.status, nil
}
func (m *mockClient) StreamEvents(_ context.Context, _ *pb.StreamEventsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.ClusterEvent], error) {
	return &fakeStream[pb.ClusterEvent]{}, nil
}

// ── Internal ──

func (m *mockClient) Ping(_ context.Context, _ *pb.PingRequest, _ ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{}, nil
}

// ── Networks ──

func (m *mockClient) CreateNetwork(_ context.Context, _ *pb.CreateNetworkRequest, _ ...grpc.CallOption) (*pb.NetworkInfo, error) {
	return &pb.NetworkInfo{}, nil
}
func (m *mockClient) GetNetwork(_ context.Context, _ *pb.GetNetworkRequest, _ ...grpc.CallOption) (*pb.NetworkInfo, error) {
	return &pb.NetworkInfo{}, nil
}
func (m *mockClient) DeleteNetwork(_ context.Context, _ *pb.DeleteNetworkRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) ListNetworks(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListNetworksResponse, error) {
	return &pb.ListNetworksResponse{}, nil
}
func (m *mockClient) ListAuditLog(_ context.Context, _ *pb.ListAuditLogRequest, _ ...grpc.CallOption) (*pb.ListAuditLogResponse, error) {
	return &pb.ListAuditLogResponse{}, nil
}
func (m *mockClient) ListVMEvents(_ context.Context, _ *pb.ListVMEventsRequest, _ ...grpc.CallOption) (*pb.ListVMEventsResponse, error) {
	return &pb.ListVMEventsResponse{}, nil
}
func (m *mockClient) ProxyVNC(_ context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[pb.VNCData, pb.VNCData], error) {
	return nil, nil
}
func (m *mockClient) UpdateVM(_ context.Context, in *pb.UpdateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name, State: pb.VMState_VM_STOPPED}, nil
}
func (m *mockClient) SetVMLabels(_ context.Context, in *pb.SetVMLabelsRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: in.Name}, nil
}

// ── Internal: Network Sync ──

func (m *mockClient) ProvisionNetwork(_ context.Context, _ *pb.ProvisionNetworkRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) SyncVTEP(_ context.Context, _ *pb.SyncVTEPRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) GetVMIPRemote(_ context.Context, _ *pb.GetVMIPRequest, _ ...grpc.CallOption) (*pb.GetVMIPResponse, error) {
	return &pb.GetVMIPResponse{}, nil
}
func (m *mockClient) RefreshLB(_ context.Context, _ *pb.RefreshLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) UpdateFDB(_ context.Context, _ *pb.UpdateFDBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) GetStateDigest(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return &pb.StateDigestResponse{HostName: "test-host"}, nil
}
func (m *mockClient) GetClusterStateDigest(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ClusterStateDigestResponse, error) {
	return &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{{HostName: "test-host"}}}, nil
}
func (m *mockClient) TriggerAntiEntropy(_ context.Context, _ *pb.TriggerAntiEntropyRequest, _ ...grpc.CallOption) (*pb.TriggerAntiEntropyResponse, error) {
	return &pb.TriggerAntiEntropyResponse{Triggered: []string{"test-host"}}, nil
}
func (m *mockClient) GetStateDump(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.StateDumpResponse, error) {
	return &pb.StateDumpResponse{}, nil
}
func (m *mockClient) PushMutations(_ context.Context, _ *pb.ReplicateRequest, _ ...grpc.CallOption) (*pb.ReplicateResponse, error) {
	return &pb.ReplicateResponse{}, nil
}
func (m *mockClient) AckMutations(_ context.Context, _ *pb.AckRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) CreateLoadBalancer(_ context.Context, _ *pb.CreateLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return &pb.LoadBalancer{}, nil
}
func (m *mockClient) UpdateLoadBalancer(_ context.Context, _ *pb.UpdateLBRequest, _ ...grpc.CallOption) (*pb.LoadBalancer, error) {
	return &pb.LoadBalancer{}, nil
}
func (m *mockClient) DeleteLoadBalancer(_ context.Context, _ *pb.DeleteLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) DrainBackend(_ context.Context, _ *pb.DrainBackendRequest, _ ...grpc.CallOption) (*pb.DrainBackendResponse, error) {
	return &pb.DrainBackendResponse{}, nil
}
func (m *mockClient) LBStats(_ context.Context, _ *pb.LBStatsRequest, _ ...grpc.CallOption) (*pb.LBStatsResponse, error) {
	return &pb.LBStatsResponse{}, nil
}
func (m *mockClient) EnsureCloudInit(_ context.Context, _ *pb.EnsureCloudInitRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) EnsureDisks(_ context.Context, _ *pb.EnsureDisksRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) CleanupMigrationArtifacts(_ context.Context, _ *pb.CleanupMigrationArtifactsRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) GetVMLogs(_ context.Context, _ *pb.GetVMLogsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.VMLogChunk], error) {
	return &fakeStream[pb.VMLogChunk]{}, nil
}
func (m *mockClient) UpgradeHost(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	return nil, nil
}
func (m *mockClient) PreStageUpgrade(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	return nil, nil
}
func (m *mockClient) FetchBinary(_ context.Context, _ *pb.FetchBinaryRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.FetchBinaryChunk], error) {
	return &fakeStream[pb.FetchBinaryChunk]{}, nil
}
func (m *mockClient) UninstallHost(_ context.Context, _ *pb.UninstallHostRequest, _ ...grpc.CallOption) (*pb.UninstallHostResponse, error) {
	return &pb.UninstallHostResponse{HostName: "test", Status: "ok"}, nil
}
func (m *mockClient) ExportStack(_ context.Context, in *pb.ExportStackRequest, _ ...grpc.CallOption) (*pb.ExportStackResponse, error) {
	return &pb.ExportStackResponse{Name: in.Name, ComposeYaml: "name: " + in.Name + "\n"}, nil
}
func (m *mockClient) ListStoragePools(_ context.Context, _ *pb.ListStoragePoolsRequest, _ ...grpc.CallOption) (*pb.ListStoragePoolsResponse, error) {
	return &pb.ListStoragePoolsResponse{}, nil
}
func (m *mockClient) ListStoragePoolContents(_ context.Context, _ *pb.ListStoragePoolContentsRequest, _ ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	return &pb.ListStoragePoolContentsResponse{}, nil
}
func (m *mockClient) UploadStoragePoolContent(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UploadStoragePoolContentRequest, pb.UploadStoragePoolContentResponse], error) {
	return nil, nil
}
func (m *mockClient) DeleteStoragePoolContent(_ context.Context, _ *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) PushReplicaIncrement(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	return nil, nil
}
func (m *mockClient) PromoteReplica(_ context.Context, _ *pb.PromoteReplicaRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PromoteReplicaProgress], error) {
	return &fakeStream[pb.PromoteReplicaProgress]{}, nil
}
func (m *mockClient) CreateStoragePool(_ context.Context, _ *pb.CreateStoragePoolRequest, _ ...grpc.CallOption) (*pb.CreateStoragePoolResponse, error) {
	return &pb.CreateStoragePoolResponse{Pool: &pb.StoragePool{}}, nil
}
func (m *mockClient) DeleteStoragePool(_ context.Context, _ *pb.DeleteStoragePoolRequest, _ ...grpc.CallOption) (*pb.DeleteStoragePoolResponse, error) {
	return &pb.DeleteStoragePoolResponse{}, nil
}
func (m *mockClient) GetStoragePool(_ context.Context, _ *pb.GetStoragePoolRequest, _ ...grpc.CallOption) (*pb.GetStoragePoolResponse, error) {
	return &pb.GetStoragePoolResponse{Pool: &pb.StoragePool{}}, nil
}

func (m *mockClient) ListRebalanceProposals(_ context.Context, _ *pb.ListRebalanceProposalsRequest, _ ...grpc.CallOption) (*pb.ListRebalanceProposalsResponse, error) {
	return &pb.ListRebalanceProposalsResponse{}, nil
}
func (m *mockClient) RunRebalance(_ context.Context, _ *pb.RunRebalanceRequest, _ ...grpc.CallOption) (*pb.RunRebalanceResponse, error) {
	return &pb.RunRebalanceResponse{}, nil
}
func (m *mockClient) ApproveRebalanceProposal(_ context.Context, _ *pb.ApproveRebalanceProposalRequest, _ ...grpc.CallOption) (*pb.RebalanceProposal, error) {
	return &pb.RebalanceProposal{}, nil
}
func (m *mockClient) RejectRebalanceProposal(_ context.Context, _ *pb.RejectRebalanceProposalRequest, _ ...grpc.CallOption) (*pb.RebalanceProposal, error) {
	return &pb.RebalanceProposal{}, nil
}
func (m *mockClient) GetSpiceInfo(_ context.Context, _ *pb.GetSpiceInfoRequest, _ ...grpc.CallOption) (*pb.GetSpiceInfoResponse, error) {
	return &pb.GetSpiceInfoResponse{}, nil
}
func (m *mockClient) PreflightUpgrade(_ context.Context, _ *pb.PreflightUpgradeRequest, _ ...grpc.CallOption) (*pb.PreflightUpgradeResponse, error) {
	return &pb.PreflightUpgradeResponse{Ok: true}, nil
}

// federation mocks.
func (m *mockClient) ListRegions(_ context.Context, _ *pb.ListRegionsRequest, _ ...grpc.CallOption) (*pb.ListRegionsResponse, error) {
	return &pb.ListRegionsResponse{}, nil
}
func (m *mockClient) RegionStatus(_ context.Context, _ *pb.RegionStatusRequest, _ ...grpc.CallOption) (*pb.RegionStatusResponse, error) {
	return &pb.RegionStatusResponse{}, nil
}
func (m *mockClient) CrossRegionMigrate(_ context.Context, _ *pb.CrossRegionMigrateRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.MigrateProgress], error) {
	return &fakeStream[pb.MigrateProgress]{}, nil
}

// tenancy mocks.
func (m *mockClient) CreateProject(_ context.Context, _ *pb.CreateProjectRequest, _ ...grpc.CallOption) (*pb.Project, error) {
	return &pb.Project{}, nil
}
func (m *mockClient) ListProjects(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.ListProjectsResponse, error) {
	return &pb.ListProjectsResponse{}, nil
}
func (m *mockClient) GetProject(_ context.Context, _ *pb.GetProjectRequest, _ ...grpc.CallOption) (*pb.Project, error) {
	return &pb.Project{}, nil
}
func (m *mockClient) DeleteProject(_ context.Context, _ *pb.DeleteProjectRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) SetProjectQuota(_ context.Context, _ *pb.SetProjectQuotaRequest, _ ...grpc.CallOption) (*pb.ProjectQuota, error) {
	return &pb.ProjectQuota{}, nil
}
func (m *mockClient) GetProjectQuota(_ context.Context, _ *pb.GetProjectQuotaRequest, _ ...grpc.CallOption) (*pb.ProjectQuota, error) {
	return &pb.ProjectQuota{}, nil
}
func (m *mockClient) GetProjectUsage(_ context.Context, _ *pb.GetProjectUsageRequest, _ ...grpc.CallOption) (*pb.ProjectUsage, error) {
	return &pb.ProjectUsage{}, nil
}

// audit chain mocks.
func (m *mockClient) VerifyAuditChain(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.VerifyAuditChainResponse, error) {
	return &pb.VerifyAuditChainResponse{}, nil
}
func (m *mockClient) ExportAuditChain(_ context.Context, _ *pb.ExportAuditChainRequest, _ ...grpc.CallOption) (*pb.ExportAuditChainResponse, error) {
	return &pb.ExportAuditChainResponse{Json: `{"rows":[]}`}, nil
}

// anycast mocks.
func (m *mockClient) UpsertServiceEndpoint(_ context.Context, _ *pb.UpsertServiceEndpointRequest, _ ...grpc.CallOption) (*pb.ServiceEndpoint, error) {
	return &pb.ServiceEndpoint{}, nil
}
func (m *mockClient) ListServiceEndpoints(_ context.Context, _ *pb.ListServiceEndpointsRequest, _ ...grpc.CallOption) (*pb.ListServiceEndpointsResponse, error) {
	return &pb.ListServiceEndpointsResponse{}, nil
}
func (m *mockClient) DeleteServiceEndpoint(_ context.Context, _ *pb.DeleteServiceEndpointRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// backup-schedule mocks.
func (m *mockClient) CreateBackupSchedule(_ context.Context, _ *pb.CreateBackupScheduleRequest, _ ...grpc.CallOption) (*pb.BackupSchedule, error) {
	return &pb.BackupSchedule{}, nil
}
func (m *mockClient) ListBackupSchedules(_ context.Context, _ *pb.ListBackupSchedulesRequest, _ ...grpc.CallOption) (*pb.ListBackupSchedulesResponse, error) {
	return &pb.ListBackupSchedulesResponse{}, nil
}
func (m *mockClient) DeleteBackupSchedule(_ context.Context, _ *pb.DeleteBackupScheduleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) CreateReplicationSchedule(_ context.Context, _ *pb.CreateReplicationScheduleRequest, _ ...grpc.CallOption) (*pb.ReplicationSchedule, error) {
	return &pb.ReplicationSchedule{}, nil
}
func (m *mockClient) ListReplicationSchedules(_ context.Context, _ *pb.ListReplicationSchedulesRequest, _ ...grpc.CallOption) (*pb.ListReplicationSchedulesResponse, error) {
	return &pb.ListReplicationSchedulesResponse{}, nil
}
func (m *mockClient) DeleteReplicationSchedule(_ context.Context, _ *pb.DeleteReplicationScheduleRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// ── Test helpers ────────────────────────────────────────────────────────────

// runCmd builds the root cobra command, injects the mock client, executes the
// given args, and returns captured stdout + stderr + error.
func runCmd(t *testing.T, mock *mockClient, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	// Override cli.Connect to return our mock.
	origConnect := cli.Connect
	cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
		return mock, func() {}, nil
	}
	t.Cleanup(func() { cli.Connect = origConnect })

	// Use the real root command so the harness exercises exactly what ships.
	root := newRootCmd()
	root.SetArgs(args)

	// Capture os.Stdout since commands use fmt.Printf, not cmd.OutOrStdout().
	origStdout := os.Stdout
	origStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	err = root.Execute()

	wOut.Close()
	wErr.Close()
	os.Stdout = origStdout
	os.Stderr = origStderr

	var outBuf, errBuf bytes.Buffer
	outBuf.ReadFrom(rOut)
	errBuf.ReadFrom(rErr)
	return outBuf.String(), errBuf.String(), err
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected output to contain %q, got:\n%s", substr, s)
	}
}

func assertNotContains(t *testing.T, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("expected output NOT to contain %q, got:\n%s", substr, s)
	}
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestE2E_Version(t *testing.T) {
	mock := newMockClient()
	out, _, err := runCmd(t, mock, "version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, out, "litevirt")
}

func TestE2E_VMLifecycle(t *testing.T) {
	mock := newMockClient()

	// Create VM
	out, _, err := runCmd(t, mock, "run", "--name", "test-vm", "--image", "ubuntu-24.04", "--cpu", "2", "--memory", "4096")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	assertContains(t, out, "test-vm")
	assertContains(t, out, "created")
	if mock.createdVM == nil {
		t.Fatal("expected CreateVM to be called")
	}
	if mock.createdVM.Name != "test-vm" {
		t.Errorf("expected name=test-vm, got %s", mock.createdVM.Name)
	}
	if mock.createdVM.Image != "ubuntu-24.04" {
		t.Errorf("expected image=ubuntu-24.04, got %s", mock.createdVM.Image)
	}
	if mock.createdVM.Cpu != 2 {
		t.Errorf("expected cpu=2, got %d", mock.createdVM.Cpu)
	}
	if mock.createdVM.MemoryMib != 4096 {
		t.Errorf("expected memory=4096, got %d", mock.createdVM.MemoryMib)
	}

	// List VMs
	out, _, err = runCmd(t, mock, "ls")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	assertContains(t, out, "web-1")
	assertContains(t, out, "web-2")
	assertContains(t, out, "db-1")
	assertContains(t, out, "host-a")
	assertContains(t, out, "host-b")
	assertContains(t, out, "10.0.50.100")

	// List VMs filtered by host
	out, _, err = runCmd(t, mock, "ls", "--host", "host-b")
	if err != nil {
		t.Fatalf("ls --host: %v", err)
	}
	assertContains(t, out, "db-1")
	assertNotContains(t, out, "web-1")

	// Inspect VM
	out, _, err = runCmd(t, mock, "inspect", "web-1")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	assertContains(t, out, "web-1")

	// Stop VM
	out, _, err = runCmd(t, mock, "stop", "web-1")
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	assertContains(t, out, "web-1")
	assertContains(t, out, "stopped")
	if mock.stoppedVM != "web-1" {
		t.Errorf("expected stop web-1, got %s", mock.stoppedVM)
	}

	// Start VM
	out, _, err = runCmd(t, mock, "start", "web-2")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	assertContains(t, out, "web-2")
	assertContains(t, out, "started")
	if mock.startedVM != "web-2" {
		t.Errorf("expected start web-2, got %s", mock.startedVM)
	}

	// Restart VM
	out, _, err = runCmd(t, mock, "restart", "web-1")
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	assertContains(t, out, "web-1")
	assertContains(t, out, "restarted")
	if mock.restartedVM != "web-1" {
		t.Errorf("expected restart web-1, got %s", mock.restartedVM)
	}

	// Exec in VM
	out, _, err = runCmd(t, mock, "exec", "web-1", "hostname")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	assertContains(t, out, "hello from web-1")

	// Delete VM
	out, _, err = runCmd(t, mock, "rm", "web-1")
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	assertContains(t, out, "web-1")
	assertContains(t, out, "deleted")
	if mock.deletedVM != "web-1" {
		t.Errorf("expected delete web-1, got %s", mock.deletedVM)
	}
}

func TestE2E_HostOperations(t *testing.T) {
	mock := newMockClient()

	// List hosts
	out, _, err := runCmd(t, mock, "host", "ls")
	if err != nil {
		t.Fatalf("host ls: %v", err)
	}
	assertContains(t, out, "host-a")
	assertContains(t, out, "host-b")
	assertContains(t, out, "10.0.50.10")
	assertContains(t, out, "10.0.50.11")

	// Inspect host
	out, _, err = runCmd(t, mock, "host", "inspect", "host-a")
	if err != nil {
		t.Fatalf("host inspect: %v", err)
	}
	assertContains(t, out, "host-a")

	// Undrain host
	out, _, err = runCmd(t, mock, "host", "undrain", "host-a")
	if err != nil {
		t.Fatalf("host undrain: %v", err)
	}
	assertContains(t, out, "host-a")
	if mock.undrainedHost != "host-a" {
		t.Errorf("expected undrain host-a, got %s", mock.undrainedHost)
	}

	// Fence host
	out, _, err = runCmd(t, mock, "host", "fence", "host-b", "--confirmed")
	if err != nil {
		t.Fatalf("host fence: %v", err)
	}
	assertContains(t, out, "host-b")
	assertContains(t, out, "ipmi")
	if mock.fencedHost != "host-b" {
		t.Errorf("expected fence host-b, got %s", mock.fencedHost)
	}

	// Remove host
	out, _, err = runCmd(t, mock, "host", "rm", "host-b")
	if err != nil {
		t.Fatalf("host rm: %v", err)
	}
	assertContains(t, out, "host-b")
	assertContains(t, out, "removed")
	if mock.removedHost != "host-b" {
		t.Errorf("expected remove host-b, got %s", mock.removedHost)
	}

	// Rescan host
	out, _, err = runCmd(t, mock, "host", "rescan", "host-a")
	if err != nil {
		t.Fatalf("host rescan: %v", err)
	}
	assertContains(t, out, "1 added")
	assertContains(t, out, "5 total")

	// List devices
	out, _, err = runCmd(t, mock, "host", "devices", "host-a")
	if err != nil {
		t.Fatalf("host devices: %v", err)
	}
	assertContains(t, out, "0000:41:00.0")
	assertContains(t, out, "gpu")
	assertContains(t, out, "10de")
}

func TestE2E_ImageOperations(t *testing.T) {
	mock := newMockClient()

	// List images
	out, _, err := runCmd(t, mock, "image", "ls")
	if err != nil {
		t.Fatalf("image ls: %v", err)
	}
	assertContains(t, out, "ubuntu-24.04")
	assertContains(t, out, "debian-12")
	assertContains(t, out, "qcow2")

	// Delete image
	out, _, err = runCmd(t, mock, "image", "rm", "debian-12")
	if err != nil {
		t.Fatalf("image rm: %v", err)
	}
	assertContains(t, out, "debian-12")
	assertContains(t, out, "deleted")
	if mock.deletedImage != "debian-12" {
		t.Errorf("expected delete debian-12, got %s", mock.deletedImage)
	}

	// Build image
	out, _, err = runCmd(t, mock, "image", "build", "web-1", "--name", "golden-web")
	if err != nil {
		t.Fatalf("image build: %v", err)
	}
	assertContains(t, out, "golden-web")
	assertContains(t, out, "built")
}

func TestE2E_SnapshotOperations(t *testing.T) {
	mock := newMockClient()

	// Create snapshot
	out, _, err := runCmd(t, mock, "snapshot", "create", "web-1", "pre-deploy")
	if err != nil {
		t.Fatalf("snapshot create: %v", err)
	}
	assertContains(t, out, "pre-deploy")
	assertContains(t, out, "web-1")
	if mock.createdSnap == nil || mock.createdSnap.Name != "pre-deploy" {
		t.Errorf("expected snapshot create pre-deploy")
	}
	if mock.createdSnap.VmName != "web-1" {
		t.Errorf("expected snapshot for web-1, got %s", mock.createdSnap.VmName)
	}

	// List snapshots
	out, _, err = runCmd(t, mock, "snapshot", "ls", "web-1")
	if err != nil {
		t.Fatalf("snapshot ls: %v", err)
	}
	assertContains(t, out, "before-upgrade")
	assertContains(t, out, "snap-001")

	// Restore snapshot
	out, _, err = runCmd(t, mock, "snapshot", "restore", "web-1", "before-upgrade")
	if err != nil {
		t.Fatalf("snapshot restore: %v", err)
	}
	assertContains(t, out, "web-1")
	assertContains(t, out, "restored")
	if mock.restoredSnap == nil || mock.restoredSnap.SnapshotName != "before-upgrade" {
		t.Errorf("expected restore before-upgrade")
	}

	// Delete snapshot
	out, _, err = runCmd(t, mock, "snapshot", "rm", "web-1", "before-upgrade")
	if err != nil {
		t.Fatalf("snapshot rm: %v", err)
	}
	assertContains(t, out, "before-upgrade")
	assertContains(t, out, "deleted")
	if mock.deletedSnap == nil || mock.deletedSnap.SnapshotName != "before-upgrade" {
		t.Errorf("expected delete before-upgrade")
	}
}

func TestE2E_UserOperations(t *testing.T) {
	mock := newMockClient()

	// List users
	out, _, err := runCmd(t, mock, "user", "ls")
	if err != nil {
		t.Fatalf("user ls: %v", err)
	}
	assertContains(t, out, "admin")
	assertContains(t, out, "deploy-bot")
	assertContains(t, out, "operator")

	// Delete user
	out, _, err = runCmd(t, mock, "user", "delete", "deploy-bot")
	if err != nil {
		t.Fatalf("user delete: %v", err)
	}
	assertContains(t, out, "deploy-bot")
	if mock.deletedUser != "deploy-bot" {
		t.Errorf("expected delete deploy-bot, got %s", mock.deletedUser)
	}

	// Create token
	out, _, err = runCmd(t, mock, "user", "token-create", "admin", "ci-bot")
	if err != nil {
		t.Fatalf("token-create: %v", err)
	}
	assertContains(t, out, "tok-001")
	assertContains(t, out, "secret-token-value")

	// Revoke token
	out, _, err = runCmd(t, mock, "user", "token-revoke", "tok-001")
	if err != nil {
		t.Fatalf("token-revoke: %v", err)
	}
	assertContains(t, out, "tok-001")
	assertContains(t, out, "revoked")
}

func TestE2E_ClusterStatus(t *testing.T) {
	mock := newMockClient()

	out, _, err := runCmd(t, mock, "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	// Status outputs JSON (encoding/json uses proto field names)
	assertContains(t, out, "hosts_total")
	assertContains(t, out, "vms_running")
}

func TestE2E_Whoami_NotLoggedIn(t *testing.T) {
	mock := newMockClient()

	// Set config dir to temp so no credentials file exists
	t.Setenv("LV_CONFIG_DIR", t.TempDir())

	out, _, err := runCmd(t, mock, "whoami")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	assertContains(t, out, "Not logged in")
}

func TestE2E_Logout(t *testing.T) {
	mock := newMockClient()

	t.Setenv("LV_CONFIG_DIR", t.TempDir())

	out, _, err := runCmd(t, mock, "logout")
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	assertContains(t, out, "Logged out")
}

func TestE2E_VMCreateWithPlacement(t *testing.T) {
	mock := newMockClient()

	_, _, err := runCmd(t, mock, "run", "--name", "placed-vm", "--image", "ubuntu-24.04", "--host", "host-b")
	if err != nil {
		t.Fatalf("run with placement: %v", err)
	}
	if mock.createdVM.Placement == nil || mock.createdVM.Placement.Host != "host-b" {
		t.Error("expected placement on host-b")
	}
}

func TestE2E_VMCreateWithDiskSize(t *testing.T) {
	mock := newMockClient()

	_, _, err := runCmd(t, mock, "run", "--name", "big-vm", "--image", "ubuntu-24.04", "--disk", "100G")
	if err != nil {
		t.Fatalf("run with disk: %v", err)
	}
	if len(mock.createdVM.Disks) != 1 || mock.createdVM.Disks[0].Size != "100G" {
		t.Errorf("expected disk size 100G, got %v", mock.createdVM.Disks)
	}
}

func TestE2E_StopForce(t *testing.T) {
	mock := newMockClient()

	out, _, err := runCmd(t, mock, "stop", "--force", "web-1")
	if err != nil {
		t.Fatalf("stop --force: %v", err)
	}
	assertContains(t, out, "stopped")
	if mock.stoppedVM != "web-1" {
		t.Errorf("expected stop web-1, got %s", mock.stoppedVM)
	}
}

func TestE2E_MissingRequiredArgs(t *testing.T) {
	mock := newMockClient()

	// run without --name should fail
	_, _, err := runCmd(t, mock, "run")
	if err == nil {
		t.Error("expected error for run without --name")
	}

	// start without vm name should fail
	_, _, err = runCmd(t, mock, "start")
	if err == nil {
		t.Error("expected error for start without args")
	}

	// inspect without vm name should fail
	_, _, err = runCmd(t, mock, "inspect")
	if err == nil {
		t.Error("expected error for inspect without args")
	}

	// snapshot create without enough args
	_, _, err = runCmd(t, mock, "snapshot", "create", "web-1")
	if err == nil {
		t.Error("expected error for snapshot create with only 1 arg")
	}

	// image rm without name
	_, _, err = runCmd(t, mock, "image", "rm")
	if err == nil {
		t.Error("expected error for image rm without args")
	}
}

func TestE2E_HotplugOperations(t *testing.T) {
	mock := newMockClient()

	// Attach disk
	out, _, err := runCmd(t, mock, "attach-disk", "web-1", "data", "--size", "50G")
	if err != nil {
		t.Fatalf("attach-disk: %v", err)
	}
	assertContains(t, out, "data")
	assertContains(t, out, "web-1")

	// Detach disk
	out, _, err = runCmd(t, mock, "detach-disk", "web-1", "data")
	if err != nil {
		t.Fatalf("detach-disk: %v", err)
	}
	assertContains(t, out, "data")
	assertContains(t, out, "web-1")

	// Attach NIC
	out, _, err = runCmd(t, mock, "attach-nic", "web-1", "mgmt")
	if err != nil {
		t.Fatalf("attach-nic: %v", err)
	}
	assertContains(t, out, "web-1")
	assertContains(t, out, "mgmt")

	// Detach NIC
	out, _, err = runCmd(t, mock, "detach-nic", "web-1", "52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatalf("detach-nic: %v", err)
	}
	assertContains(t, out, "web-1")

	// Attach PCI device
	out, _, err = runCmd(t, mock, "attach-pci", "web-1", "--type", "gpu", "--vendor", "10de")
	if err != nil {
		t.Fatalf("attach-pci: %v", err)
	}
	assertContains(t, out, "web-1")

	// Detach PCI device
	out, _, err = runCmd(t, mock, "detach-pci", "web-1", "0000:41:00.0")
	if err != nil {
		t.Fatalf("detach-pci: %v", err)
	}
	assertContains(t, out, "web-1")
}

func (m *mockClient) CreateNotificationTarget(_ context.Context, in *pb.CreateNotificationTargetRequest, _ ...grpc.CallOption) (*pb.NotificationTarget, error) {
	return &pb.NotificationTarget{Id: "t1", Name: in.Name, Type: in.Type, Config: in.Config, Enabled: in.Enabled}, nil
}
func (m *mockClient) ListNotificationTargets(_ context.Context, _ *pb.ListNotificationTargetsRequest, _ ...grpc.CallOption) (*pb.ListNotificationTargetsResponse, error) {
	return &pb.ListNotificationTargetsResponse{}, nil
}
func (m *mockClient) DeleteNotificationTarget(_ context.Context, _ *pb.DeleteNotificationTargetRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) TestNotificationTarget(_ context.Context, _ *pb.TestNotificationTargetRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (m *mockClient) CreateNotificationRoute(_ context.Context, in *pb.CreateNotificationRouteRequest, _ ...grpc.CallOption) (*pb.NotificationRoute, error) {
	return &pb.NotificationRoute{Id: "r1", EventPattern: in.EventPattern, TargetId: in.TargetId, MinSeverity: in.MinSeverity, Enabled: in.Enabled}, nil
}
func (m *mockClient) ListNotificationRoutes(_ context.Context, _ *pb.ListNotificationRoutesRequest, _ ...grpc.CallOption) (*pb.ListNotificationRoutesResponse, error) {
	return &pb.ListNotificationRoutesResponse{}, nil
}
func (m *mockClient) DeleteNotificationRoute(_ context.Context, _ *pb.DeleteNotificationRouteRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
