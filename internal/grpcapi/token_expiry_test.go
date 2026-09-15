package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A token's expiry is enforced by ONE thing: the SQL string comparison
// `t.expires_at > ?` against a bare RFC3339 now. Nothing parsed the value on the
// way in, so any string that sorts above a timestamp was a token that never
// expired — and the CLI reported success while `token-ls` displayed the bogus
// expiry as if it meant something. A security control that fails open on a typo.
//
// The read side already reasons carefully about this comparison (users.go: "Bare
// RFC3339 cutoff ... Compare like-with-like"); what was missing is any guarantee
// that the stored value is in that format at all.
func TestCreateToken_RejectsAnUnparseableExpiry(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "bot", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	for _, bad := range []string{
		"30d",                  // the plausible typo: sorts above any "2..." timestamp
		"never",                // sorts above too
		"2026-13-45T99:99:99Z", // shaped like a timestamp, is not one
		"tomorrow",
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{
				Username: "bot", Name: "ci-" + bad, Expires: bad,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("CreateToken(--expires %q) = %v (code %s), want InvalidArgument — "+
					"an unparseable expiry yields a token that never expires", bad, err, status.Code(err))
			}
		})
	}
}

// An offset-bearing RFC3339 value parses, but comparing it as a STRING against a
// UTC cutoff is wrong by the offset in whichever direction it points. Storing it
// normalised to UTC is what makes the comparison the read side performs valid.
func TestCreateToken_NormalisesAnOffsetExpiryToUTC(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "bot", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	// 2026-01-01T00:00:00+02:00 is 2025-12-31T22:00:00Z.
	if _, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{
		Username: "bot", Name: "offset", Expires: "2026-01-01T00:00:00+02:00",
	}); err != nil {
		t.Fatalf("CreateToken with a valid offset expiry: %v", err)
	}

	rows, err := s.db.Query(ctx, `SELECT expires_at FROM tokens WHERE name = ?`, "offset")
	if err != nil || len(rows) == 0 {
		t.Fatalf("read back token: %v (rows=%d)", err, len(rows))
	}
	got := rows[0].String("expires_at")
	want := "2025-12-31T22:00:00Z"
	if got != want {
		t.Errorf("stored expires_at = %q, want %q — a string compare against a UTC "+
			"cutoff is wrong by the offset otherwise", got, want)
	}
}

// The ordinary path: a plain UTC expiry is accepted and stored as given.
func TestCreateToken_AcceptsAPlainUTCExpiry(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "bot", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	exp := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	if _, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{
		Username: "bot", Name: "ok", Expires: exp,
	}); err != nil {
		t.Fatalf("CreateToken with a valid expiry was rejected: %v", err)
	}
}

// No expiry at all stays legal — a non-expiring token is a deliberate choice.
func TestCreateToken_AllowsAnEmptyExpiry(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "bot", "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if _, err := s.CreateToken(adminCtx(), &pb.CreateTokenRequest{
		Username: "bot", Name: "forever",
	}); err != nil {
		t.Fatalf("CreateToken with no expiry was rejected: %v", err)
	}
}
