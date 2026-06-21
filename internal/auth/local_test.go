package auth

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestLocalRealm_Authenticate(t *testing.T) {
	ctx := context.Background()
	db := newAuthTestDB(t)
	realm := NewLocalRealm(db)

	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), BcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := corrosion.InsertUser(ctx, db, "alice", "operator", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	t.Run("valid", func(t *testing.T) {
		p, err := realm.Authenticate(ctx, Credentials{Username: "alice", Password: "hunter2"})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if p.Subject != "alice" {
			t.Errorf("Subject = %q, want alice", p.Subject)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, err := realm.Authenticate(ctx, Credentials{Username: "alice", Password: "nope"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	// The missing-user path must run the dummy bcrypt compare (no panic) and
	// return the SAME error as a wrong password — no enumeration signal.
	t.Run("missing user", func(t *testing.T) {
		_, err := realm.Authenticate(ctx, Credentials{Username: "ghost", Password: "whatever"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials for missing user, got %v", err)
		}
	})

	t.Run("empty creds", func(t *testing.T) {
		_, err := realm.Authenticate(ctx, Credentials{})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials for empty creds, got %v", err)
		}
	})
}
