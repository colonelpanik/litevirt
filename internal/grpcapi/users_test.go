package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestCreateUser_EmptyUsername(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateUser(ctx, &pb.CreateUserRequest{Password: "secret"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestCreateUser_EmptyPassword(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateUser(ctx, &pb.CreateUserRequest{Username: "alice"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestCreateUser_Success(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	user, err := s.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "alice",
		Password: "supersecret",
		Role:     "operator",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("Username = %q, want alice", user.Username)
	}
	if user.Role != "operator" {
		t.Errorf("Role = %q, want operator", user.Role)
	}
}

func TestCreateUser_DefaultRole(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	user, err := s.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "bob",
		Password: "pass123",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Role != "viewer" {
		t.Errorf("Role = %q, want viewer (default)", user.Role)
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "charlie",
		Password: "pass",
	})

	_, err := s.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "charlie",
		Password: "pass2",
	})
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

func TestListUsers_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListUsers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.Users) != 0 {
		t.Errorf("expected 0 users, got %d", len(resp.Users))
	}
}

func TestListUsers_WithUsers(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "u1", Password: "p1"})
	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "u2", Password: "p2"})

	resp, err := s.ListUsers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(resp.Users))
	}
}

func TestDeleteUser(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "u1", Password: "p1"})

	_, err := s.DeleteUser(ctx, &pb.DeleteUserRequest{Username: "u1"})
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
}

func TestCreateToken_EmptyUsername(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateToken(ctx, &pb.CreateTokenRequest{Name: "ci"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestCreateToken_EmptyName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateToken(ctx, &pb.CreateTokenRequest{Username: "alice"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestCreateToken_UserNotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateToken(ctx, &pb.CreateTokenRequest{Username: "ghost", Name: "ci"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestCreateToken_Success(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "alice", Password: "p"})

	tok, err := s.CreateToken(ctx, &pb.CreateTokenRequest{Username: "alice", Name: "ci"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.Token == "" {
		t.Error("expected non-empty token")
	}
	if tok.Username != "alice" {
		t.Errorf("Username = %q, want alice", tok.Username)
	}
	if tok.Name != "ci" {
		t.Errorf("Name = %q, want ci", tok.Name)
	}
}

func TestRevokeToken(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Revoking a non-existent token should not error (idempotent).
	_, err := s.RevokeToken(ctx, &pb.RevokeTokenRequest{Id: "nonexistent"})
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()
	if id1 == id2 {
		t.Error("generateID returned same value twice")
	}
	if len(id1) != 16 {
		t.Errorf("length = %d, want 16", len(id1))
	}
}
