package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// Task 4 registers and advertises this token. Keeping the decision site here
// makes this build mixed-version safe before that registration exists: the
// capability cannot latch yet, so legacy forwarding remains active.
const capacityAdmissionCapability = "capacity_admission_v1"

const createVMForwardHopMetadata = "x-litevirt-create-hop"

type resolvedCreateVMDecision struct {
	resolvedHost string
}

func createVMForwardHop(ctx context.Context) (int, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, nil
	}
	values := md.Get(createVMForwardHopMetadata)
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, status.Error(codes.InvalidArgument, "create forward hop metadata must have one value")
	}
	hop, err := strconv.Atoi(values[0])
	if err != nil || hop < 0 {
		return 0, status.Error(codes.InvalidArgument, "invalid create forward hop metadata")
	}
	return hop, nil
}

func validateCreateVMForwardHop(ctx context.Context) error {
	hop, err := createVMForwardHop(ctx)
	if err != nil {
		return err
	}
	if hop > 1 {
		return status.Error(codes.FailedPrecondition, "CreateVM forward hop limit exceeded")
	}
	return nil
}

func (s *Server) createVMPlacementRequest(ctx context.Context, spec *pb.VMSpec, allowOvercommit bool) placement.Request {
	req := placement.Request{
		VMName:       spec.Name,
		CPUNeeded:    int(spec.Cpu),
		MemMiBNeeded: int(spec.MemoryMib),
		Capacity:     s.capacity,
	}
	// An explicitly authorized capacity bypass remains a bypass while every
	// other hard constraint still runs.
	if allowOvercommit {
		req.CPUNeeded = 0
		req.MemMiBNeeded = 0
	}
	if p := spec.Placement; p != nil {
		req.PinHost = p.Host
		req.AntiAffinity = p.AntiAffinity
		req.Affinity = p.Affinity
		req.RequireLabels = p.Require
		req.PreferLabels = p.Prefer
		req.Spread = p.Spread
		if policy := placement.Policy(p.Policy); policy.Valid() {
			req.Policy = policy
		}
		if p.MaxPerNode > 0 {
			req.MaxPerNode = int(p.MaxPerNode)
			req.VMBaseName = vmBaseName(spec.Name)
		}
	}
	addCapabilityLabels(&req, spec)
	for _, dev := range spec.Devices {
		req.Devices = append(req.Devices, placement.DeviceRequest{
			Type: dev.Type, Count: int(dev.Count), Vendor: dev.Vendor,
			Address: dev.Address, Sriov: dev.Sriov, Parent: dev.Parent,
		})
	}
	for _, nic := range spec.Network {
		if nic.Name == "" {
			continue
		}
		network, _ := corrosion.GetNetwork(ctx, s.db, nic.Name)
		networkType := "bridge"
		if network != nil {
			networkType = network.Type
		}
		req.Networks = append(req.Networks, placement.NetworkReq{
			Name: nic.Name, Type: networkType,
		})
	}
	return req
}

func (s *Server) capacityPolicyFingerprint(ctx context.Context) (string, error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", fmt.Errorf("list hosts: %w", err)
	}
	return corrosion.CapacityPolicyFingerprint(s.capacity, corrosion.HostCapacityOverrides(hosts))
}

func (s *Server) capacityAdmissionLatched() bool {
	return s.gate != nil && s.gate.Latched(capacityAdmissionCapability)
}

func (s *Server) forwardCreateVM(ctx context.Context, req *pb.CreateVMRequest, targetHost string) (*pb.VM, error) {
	hop, err := createVMForwardHop(ctx)
	if err != nil {
		return nil, err
	}
	nextHop := hop + 1
	if nextHop > 1 {
		return nil, status.Error(codes.FailedPrecondition, "CreateVM forward hop limit exceeded")
	}

	slog.Info("forwarding CreateVM to target host", "vm", req.GetSpec().GetName(), "target", targetHost)
	client, closePeer, err := s.dialPeer(ctx, targetHost)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", targetHost, err)
	}
	defer closePeer()

	// The entry node owns the idempotency claim. The owner executes without
	// re-entering that claim, regardless of which mixed-version path is used.
	forwarded := proto.Clone(req).(*pb.CreateVMRequest)
	forwarded.IdempotencyKey = ""
	outCtx := metadata.AppendToOutgoingContext(ctx, createVMForwardHopMetadata, strconv.Itoa(nextHop))

	if !s.capacityAdmissionLatched() {
		return client.CreateVM(outCtx, forwarded)
	}

	fingerprint, err := s.capacityPolicyFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "capacity-policy fingerprint: %v", err)
	}
	out, err := client.ExecuteCreateVM(outCtx, &pb.ExecuteCreateVMRequest{
		Request:              forwarded,
		ResolvedHost:         targetHost,
		PlacementFingerprint: fingerprint,
		HopCount:             uint32(nextHop),
	})
	if status.Code(err) == codes.Unimplemented {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %s does not implement required capacity-admission executor", targetHost)
	}
	return out, err
}

// ExecuteCreateVM is the internal owner-side create endpoint. It authenticates
// the peer, validates the entry node's resolved decision against current policy
// and hard constraints, then executes locally without global rescoring or
// recursive forwarding.
func (s *Server) ExecuteCreateVM(ctx context.Context, envelope *pb.ExecuteCreateVMRequest) (*pb.VM, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if envelope == nil || envelope.Request == nil || envelope.Request.Spec == nil {
		return nil, status.Error(codes.InvalidArgument, "create execution request and spec are required")
	}
	if envelope.ResolvedHost == "" {
		return nil, status.Error(codes.InvalidArgument, "resolved host is required")
	}
	if envelope.ResolvedHost != s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"resolved host %q does not match executor %q", envelope.ResolvedHost, s.hostName)
	}
	if pin := envelope.Request.Spec.GetPlacement().GetHost(); pin != "" && pin != envelope.ResolvedHost {
		return nil, status.Errorf(codes.FailedPrecondition,
			"request pin %q does not match resolved host %q", pin, envelope.ResolvedHost)
	}
	if envelope.HopCount > 1 {
		return nil, status.Error(codes.FailedPrecondition, "create execution hop limit exceeded")
	}
	if envelope.PlacementFingerprint == "" {
		return nil, status.Error(codes.InvalidArgument, "placement fingerprint is required")
	}

	currentFingerprint, err := s.capacityPolicyFingerprint(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "capacity-policy fingerprint: %v", err)
	}
	if envelope.PlacementFingerprint != currentFingerprint {
		return nil, status.Error(codes.FailedPrecondition, "capacity policy changed after placement; retry create")
	}

	spec, err := normalizeCreateVMSpec(envelope.Request.Spec)
	if err != nil {
		return nil, err
	}
	if spec.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name required")
	}
	placementReq := s.createVMPlacementRequest(ctx, spec, envelope.Request.AllowOvercommit)
	if err := placement.ValidatePinned(ctx, s.db, placementReq, envelope.ResolvedHost); err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "resolved placement is no longer eligible: %v", err)
	}

	localRequest := proto.Clone(envelope.Request).(*pb.CreateVMRequest)
	localRequest.Spec = spec
	return s.createVM(ctx, localRequest, &resolvedCreateVMDecision{resolvedHost: envelope.ResolvedHost})
}
