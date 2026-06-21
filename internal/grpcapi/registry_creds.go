package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Registry credentials (v23): per-user and global OCI/Docker registry logins
// used to authenticate `lv ct pull` / PullOCIImage against private registries.
//
// Authz model:
//   - Per-user CRUD (global=false) is gated only on "authenticated". Ownership
//     is structural: the server derives owner from callerUsername(ctx), so a
//     caller can never address another user's row (mirrors account.go /
//     twofactor.go self-owned resources).
//   - Global CRUD and `ls --all` require the registry.cred.global perm
//     (operator fallback), matching the modern image.pull gate on PullOCIImage.

// toPbRegistryCredential maps to the wire type. The secret is dropped by
// construction — pb.RegistryCredential has no secret field — so List is
// redacted and cannot leak a credential.
func toPbRegistryCredential(rc corrosion.RegistryCredential) *pb.RegistryCredential {
	return &pb.RegistryCredential{
		Scope: rc.Scope, Owner: rc.Owner, Registry: rc.Registry,
		Username: rc.Username, CreatedAt: rc.CreatedAt, UpdatedAt: rc.UpdatedAt,
	}
}

func (s *Server) SetRegistryCredential(ctx context.Context, req *pb.SetRegistryCredentialRequest) (*pb.RegistryCredential, error) {
	scope, owner := corrosion.RegistryScopeUser, callerUsername(ctx)
	if req.Global {
		if err := s.RequirePerm(ctx, "/", "registry.cred.global", "operator"); err != nil {
			return nil, err
		}
		scope, owner = corrosion.RegistryScopeGlobal, ""
	} else if owner == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated principal")
	}
	registry := lxc.NormalizeRegistry(req.Registry)
	if registry == "" {
		return nil, status.Error(codes.InvalidArgument, "a registry host is required (a local oci: reference cannot hold credentials)")
	}
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}
	rc := corrosion.RegistryCredential{
		ID: newID(), Scope: scope, Owner: owner, Registry: registry,
		Username: req.Username, Secret: req.Password,
	}
	if err := corrosion.UpsertRegistryCredential(ctx, s.db, rc); err != nil {
		return nil, status.Errorf(codes.Internal, "set registry credential: %v", err)
	}
	slog.Info("registry credential set", "scope", scope, "owner", owner, "registry", registry, "username", req.Username)
	return toPbRegistryCredential(rc), nil
}

func (s *Server) ListRegistryCredentials(ctx context.Context, req *pb.ListRegistryCredentialsRequest) (*pb.ListRegistryCredentialsResponse, error) {
	caller := callerUsername(ctx)
	if caller == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated principal")
	}
	var (
		rows []corrosion.RegistryCredential
		err  error
	)
	switch {
	case req.All:
		if err := s.RequirePerm(ctx, "/", "registry.cred.global", "operator"); err != nil {
			return nil, err
		}
		rows, err = corrosion.ListAllRegistryCredentials(ctx, s.db)
	case req.Global:
		// Global rows are not secret-bearing on the wire (redacted) and are
		// cluster-wide config; any authenticated user may view them. Fetch the
		// global set with an owner that matches nothing.
		rows, err = corrosion.ListRegistryCredentials(ctx, s.db, "", true)
	default:
		rows, err = corrosion.ListRegistryCredentials(ctx, s.db, caller, true)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list registry credentials: %v", err)
	}
	resp := &pb.ListRegistryCredentialsResponse{}
	for _, rc := range rows {
		resp.Credentials = append(resp.Credentials, toPbRegistryCredential(rc))
	}
	return resp, nil
}

func (s *Server) DeleteRegistryCredential(ctx context.Context, req *pb.DeleteRegistryCredentialRequest) (*emptypb.Empty, error) {
	scope, owner := corrosion.RegistryScopeUser, callerUsername(ctx)
	if req.Global {
		if err := s.RequirePerm(ctx, "/", "registry.cred.global", "operator"); err != nil {
			return nil, err
		}
		scope, owner = corrosion.RegistryScopeGlobal, ""
	} else if owner == "" {
		return nil, status.Error(codes.Unauthenticated, "no authenticated principal")
	}
	registry := lxc.NormalizeRegistry(req.Registry)
	if registry == "" {
		return nil, status.Error(codes.InvalidArgument, "a registry host is required")
	}
	ok, err := corrosion.DeleteRegistryCredential(ctx, s.db, scope, owner, registry)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete registry credential: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no credential for registry %q", registry)
	}
	return &emptypb.Empty{}, nil
}
