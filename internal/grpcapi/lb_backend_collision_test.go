package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestCreateLoadBalancer_RejectsDuplicateBackendNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *pb.CreateLBRequest
	}{
		{
			name: "explicit_duplicate",
			req: &pb.CreateLBRequest{
				Name:  "dup-explicit-lb",
				Vip:   "10.0.100.51/24",
				Ports: []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
				Backends: []*pb.LBBackendAddress{
					{Name: "web", Address: "10.0.1.10"},
					{Name: "web", Address: "10.0.1.11"},
				},
				Hosts: []string{"other-host"},
			},
		},
		{
			name: "explicit_vm_collision",
			req: &pb.CreateLBRequest{
				Name:       "dup-vm-lb",
				Vip:        "10.0.100.52/24",
				Ports:      []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
				Backends:   []*pb.LBBackendAddress{{Name: "web-1", Address: "10.0.1.10"}},
				VmBackends: []string{"web-1"},
				Hosts:      []string{"other-host"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerCov(t)
			ctx := adminCtx()
			createLBTable(t, ctx, s.db)
			insertLBBackendCollisionVM(t, ctx, s, "web-1", "10.0.1.20")

			_, err := s.CreateLoadBalancer(ctx, tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("CreateLoadBalancer code = %v, want InvalidArgument; err = %v", status.Code(err), err)
			}
			if backends, err := corrosion.ListLBBackends(ctx, s.db, tc.req.Name); err != nil || len(backends) != 0 {
				t.Fatalf("backends after rejected create = %+v, err=%v; want none", backends, err)
			}
		})
	}
}

func TestUpdateLoadBalancer_RejectsBackendNameCollision(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "web-lb", VIP: "10.0.100.53/24", Algorithm: "roundrobin",
		Ports: `[{"listen":80,"target":8080}]`, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
		LBName: "web-lb", Name: "web-1", Address: "10.0.1.10", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}
	insertLBBackendCollisionVM(t, ctx, s, "web-1", "10.0.1.20")

	_, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{
		Name:          "web-lb",
		AddVmBackends: []string{"web-1"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("UpdateLoadBalancer code = %v, want InvalidArgument; err = %v", status.Code(err), err)
	}

	backends, err := corrosion.ListLBBackends(ctx, s.db, "web-lb")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(backends) != 1 || backends[0].Name != "web-1" || backends[0].Address != "10.0.1.10" || backends[0].IsVM {
		t.Fatalf("existing backend mutated after rejected update: %+v", backends)
	}
}

func TestUpdateLoadBalancer_CanReplaceBackendWithSameName(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "replace-lb", VIP: "10.0.100.54/24", Algorithm: "roundrobin",
		Hosts: `["lb-host-1"]`, // durable holder — not the legacy no-holder shape
		Ports: `[{"listen":80,"target":8080}]`, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
		LBName: "replace-lb", Name: "web", Address: "10.0.1.10", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}

	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{
		Name:           "replace-lb",
		RemoveBackends: []string{"web"},
		AddBackends:    []*pb.LBBackendAddress{{Name: "web", Address: "10.0.1.11"}},
	}); err != nil {
		t.Fatalf("UpdateLoadBalancer replace same backend name: %v", err)
	}

	backends, err := corrosion.ListLBBackends(ctx, s.db, "replace-lb")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(backends) != 1 || backends[0].Name != "web" || backends[0].Address != "10.0.1.11" {
		t.Fatalf("replacement backend = %+v, want web at 10.0.1.11", backends)
	}
}

func insertLBBackendCollisionVM(t *testing.T, ctx context.Context, s *Server, name, ip string) {
	t.Helper()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: name, HostName: s.hostName, State: "running", Spec: "{}"},
		[]corrosion.InterfaceRecord{{
			VMName: name, NetworkName: "default", Ordinal: 0,
			MAC: "52:54:00:aa:bb:cc", IP: ip,
		}},
		nil,
	); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}
