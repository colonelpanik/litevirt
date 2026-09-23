package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedAdminRow puts a live user row in the server's database. adminCtx() only
// supplies a caller identity to the interceptor-less handler call; it does not
// create a row, and these tests are about what rows exist.
func seedAdminRow(t *testing.T, s *Server, username, role string) {
	t.Helper()
	if err := corrosion.InsertUser(context.Background(), s.db, username, role, "$2a$10$stub"); err != nil {
		t.Fatalf("seed user %q: %v", username, err)
	}
}

func liveUser(t *testing.T, s *Server, username string) *corrosion.UserRecord {
	t.Helper()
	u, err := corrosion.GetUser(context.Background(), s.db, username)
	if err != nil {
		t.Fatalf("read back user %q: %v", username, err)
	}
	return u
}

// Deleting the last admin leaves a cluster nobody can administer. Recovery then
// depends on `lv user reset-admin`, which (since #227) deliberately refuses to
// mint a missing admin, so there is no way back through the API at all.
func TestDeleteUser_RefusesTheLastLiveAdmin(t *testing.T) {
	s := testServer(t)
	seedAdminRow(t, s, "admin", "admin")

	_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "admin"})
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Fatalf("code = %v (err %v), want FailedPrecondition", c, err)
	}
	if u := liveUser(t, s, "admin"); u == nil {
		t.Error("the refused delete tombstoned the last admin anyway")
	}
}

func TestDeleteUser_AllowsAnAdminWhileAnotherRemains(t *testing.T) {
	s := testServer(t)
	seedAdminRow(t, s, "admin", "admin")
	seedAdminRow(t, s, "root", "admin")

	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "admin"}); err != nil {
		t.Fatalf("DeleteUser with a second admin present: %v", err)
	}
	if u := liveUser(t, s, "admin"); u != nil {
		t.Error("the user survived a delete that should have succeeded")
	}
}

func TestDeleteUser_AllowsANonAdmin(t *testing.T) {
	s := testServer(t)
	seedAdminRow(t, s, "admin", "admin")
	seedAdminRow(t, s, "viewer", "viewer")

	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "viewer"}); err != nil {
		t.Fatalf("DeleteUser on a viewer: %v", err)
	}
	if u := liveUser(t, s, "viewer"); u != nil {
		t.Error("the viewer survived its own delete")
	}
}

// The guard has to ask who is LIVE, not who has a row. A tombstoned admin is
// still a row — InsertUser reactivates one rather than inserting afresh — so a
// tombstone-blind guard would read it as a successor and release the last
// account that can actually log in.
func TestDeleteUser_ATombstonedAdminDoesNotAuthoriseTheLastDelete(t *testing.T) {
	s := testServer(t)
	seedAdminRow(t, s, "admin", "admin")
	seedAdminRow(t, s, "retired", "admin")
	if _, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "retired"}); err != nil {
		t.Fatalf("delete the second admin: %v", err)
	}

	_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "admin"})
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Fatalf("code = %v (err %v), want FailedPrecondition — "+
			"the only other admin is tombstoned", c, err)
	}
	if u := liveUser(t, s, "admin"); u == nil {
		t.Error("the refused delete tombstoned the last admin anyway")
	}
}

// An unreadable database must not read as "this user is not an admin". The
// distinguishing evidence is which operation the error names: a swallowed
// lookup error lets the guard fall through and the failure surfaces from the
// delete instead.
func TestDeleteUser_AFailedLookupIsNotANonAdmin(t *testing.T) {
	s := testServer(t)
	seedAdminRow(t, s, "admin", "admin")
	s.db.Close()

	_, err := s.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Username: "admin"})
	if err == nil {
		t.Fatal("DeleteUser succeeded although no user lookup could run")
	}
	if !strings.Contains(err.Error(), "look up user") {
		t.Errorf("error = %v\nwant one naming the failed lookup; a failed read was "+
			"treated as an answer and the guard was skipped", err)
	}
}
