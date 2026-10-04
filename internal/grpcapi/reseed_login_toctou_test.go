package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// reseedRacingRealm runs a whole reseed cycle inside Authenticate, then answers
// the way the real LocalRealm would after that reseed emptied user_2fa: no
// enrolled factors, so no second factor required.
//
// That is the real ordering, not an invention. LocalRealm.Authenticate reads the
// user, spends a deliberately-slow bcrypt on the password, and only THEN reads
// user_2fa — so a reseed that starts after the request was admitted has an
// entire bcrypt to run in, and the factor read lands on the far side of the
// discard.
type reseedRacingRealm struct {
	db      *corrosion.Client
	ran     bool
	finish  bool // also FINISH the reseed, so the marker is clear again by the mint
	subject string
}

func (r *reseedRacingRealm) Name() string { return "local" }

func (r *reseedRacingRealm) SyncGroups(context.Context) error { return nil }

func (r *reseedRacingRealm) Authenticate(ctx context.Context, _ auth.Credentials) (*auth.Principal, error) {
	if !r.ran {
		r.ran = true
		if _, err := r.db.BeginReseed(ctx, "peer1"); err != nil {
			return nil, err
		}
		// The discard empties the sensitive tables, user_2fa among them.
		if err := r.db.Execute(ctx, `DELETE FROM user_2fa`); err != nil {
			return nil, err
		}
		if r.finish {
			if err := r.db.FinishReseed(ctx, 1); err != nil {
				return nil, err
			}
		}
	}
	// What the real realm returns once user_2fa is empty: len(factors) == 0, so
	// Requires2FA is never set, and the enrolled account is password-only.
	return &auth.Principal{Subject: r.subject, Realm: "local"}, nil
}

func toctouServer(t *testing.T, finish bool) (*Server, *reseedRacingRealm) {
	t.Helper()
	s := gateTestServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertUser(ctx, s.db, "alice", "admin", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	realm := &reseedRacingRealm{db: s.db, finish: finish, subject: "alice"}
	reg := auth.NewRegistry()
	reg.Register(realm)
	s.realmRegistry = reg
	return s, realm
}

// The gate is checked once, in the interceptor, before the handler runs. It
// stops new logins; it cannot drain one already inside. A request admitted just
// before a reseed finishes its credential check on the far side of the discard
// and must not be granted a session.
func TestLogin_AReseedDuringTheCredentialCheckGrantsNoSession(t *testing.T) {
	s, realm := toctouServer(t, false)

	resp, err := s.UnaryAuthInterceptor(adminCtx(), &pb.LoginRequest{
		Username: "alice", Password: "correct-horse",
	}, &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Login"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.Login(ctx, req.(*pb.LoginRequest))
		})

	if !realm.ran {
		t.Fatal("the racing reseed never ran; the test proves nothing")
	}
	if err == nil {
		if lr, ok := resp.(*pb.LoginResponse); ok && lr.Token != "" {
			t.Fatal("a session was minted for an enrolled account while a reseed had emptied " +
				"user_2fa mid-check — the second factor was never required")
		}
	}
}

// The harder case the generation exists for: the reseed starts AND FINISHES
// inside the credential check, so the marker is clear again by the time the
// session would be minted. A second boolean read of the marker sees nothing.
func TestLogin_AReseedThatAlsoFinishedMidCheckGrantsNoSession(t *testing.T) {
	s, realm := toctouServer(t, true)

	resp, err := s.UnaryAuthInterceptor(adminCtx(), &pb.LoginRequest{
		Username: "alice", Password: "correct-horse",
	}, &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Login"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.Login(ctx, req.(*pb.LoginRequest))
		})

	if !realm.ran {
		t.Fatal("the racing reseed never ran; the test proves nothing")
	}
	if incomplete, _, ierr := s.db.ReseedIncomplete(adminCtx()); ierr != nil || incomplete {
		t.Fatalf("precondition: the marker must be CLEAR by the mint (incomplete=%v err=%v) — "+
			"otherwise this test is the easy case, not the one the generation is for",
			incomplete, ierr)
	}
	if err == nil {
		if lr, ok := resp.(*pb.LoginResponse); ok && lr.Token != "" {
			t.Fatal("a session was minted although an entire reseed started and finished while " +
				"these credentials were being checked — re-reading the marker cannot see it, " +
				"which is why a monotone generation is needed")
		}
	}
}
