package grpcapi

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func seedLocalUser(t *testing.T, s *Server, username, role, password string) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err := corrosion.InsertUser(context.Background(), s.db, username, role, string(hash)); err != nil {
		t.Fatalf("InsertUser(%s): %v", username, err)
	}
}

func pwOK(t *testing.T, s *Server, username, password string) bool {
	t.Helper()
	u, err := corrosion.GetUser(context.Background(), s.db, username)
	if err != nil || u == nil {
		t.Fatalf("GetUser(%s): %v", username, err)
	}
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}

func TestChangePassword_SelfVerifiesOldPassword(t *testing.T) {
	s := testServer(t)
	seedLocalUser(t, s, "bob", "operator", "old-pw")

	// Wrong old password is rejected.
	_, err := s.ChangePassword(userCtx("bob", "operator"),
		&pb.ChangePasswordRequest{OldPassword: "nope", NewPassword: "new-pw"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong old password: want PermissionDenied, got %v", err)
	}
	if !pwOK(t, s, "bob", "old-pw") {
		t.Error("password should be unchanged after a failed change")
	}

	// Correct old password succeeds and rotates the hash.
	if _, err := s.ChangePassword(userCtx("bob", "operator"),
		&pb.ChangePasswordRequest{OldPassword: "old-pw", NewPassword: "new-pw"}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if !pwOK(t, s, "bob", "new-pw") || pwOK(t, s, "bob", "old-pw") {
		t.Error("password was not rotated to the new value")
	}
}

func TestChangePassword_AdminResetVsNonAdmin(t *testing.T) {
	s := testServer(t)
	seedLocalUser(t, s, "carol", "viewer", "carol-pw")

	// A non-admin cannot change someone else's password.
	_, err := s.ChangePassword(viewerCtx(),
		&pb.ChangePasswordRequest{Username: "carol", NewPassword: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin reset: want PermissionDenied, got %v", err)
	}

	// An admin resets another user's password without the old one.
	if _, err := s.ChangePassword(adminCtx(),
		&pb.ChangePasswordRequest{Username: "carol", NewPassword: "reset-pw"}); err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	if !pwOK(t, s, "carol", "reset-pw") {
		t.Error("admin reset did not take effect")
	}
}

func TestStoragePoolCreate_RequiresOperator(t *testing.T) {
	s := testServer(t)
	_, err := s.CreateStoragePool(viewerCtx(),
		&pb.CreateStoragePoolRequest{Name: "p1", Driver: "local"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer CreateStoragePool: want PermissionDenied, got %v", err)
	}
	_, err = s.DeleteStoragePool(viewerCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer DeleteStoragePool: want PermissionDenied, got %v", err)
	}
}
