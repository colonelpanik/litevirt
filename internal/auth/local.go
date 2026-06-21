package auth

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// dummyBcryptHash is a valid bcrypt hash (at BcryptCost) compared against when
// the requested user doesn't exist, so the "no such user" path spends the same
// CPU as the "wrong password" path. Without it, a missing user returns almost
// instantly while a real user incurs a full bcrypt comparison — a timing
// oracle for username enumeration. Computed once, lazily.
var dummyBcryptHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("litevirt-nonexistent-user"), BcryptCost)
	if err != nil { // BcryptCost is a sane constant; this never fails in practice
		return []byte("$2a$10$0000000000000000000000000000000000000000000000000000")
	}
	return h
})

// LocalRealm authenticates against the `users` table with bcrypt-hashed
// passwords. It is always present and is the bootstrap realm (the cluster's
// first admin lives here before OIDC/LDAP land).
type LocalRealm struct {
	db *corrosion.Client
}

// NewLocalRealm constructs the local realm.
func NewLocalRealm(db *corrosion.Client) *LocalRealm {
	return &LocalRealm{db: db}
}

// Name returns "local".
func (r *LocalRealm) Name() string { return "local" }

// Authenticate validates username + password against bcrypt(password_hash).
//
// Returns ErrInvalidCredentials on bad password OR missing user — never
// distinguishes between the two to avoid user-enumeration attacks.
//
// If the user has 2FA enrolled (rows in user_2fa), the returned Principal's
// Requires2FA flag is set; the caller (login handler) issues a partial
// response and waits for the 2FA stage.
func (r *LocalRealm) Authenticate(ctx context.Context, creds Credentials) (*Principal, error) {
	if creds.Username == "" || creds.Password == "" {
		return nil, ErrInvalidCredentials
	}
	user, err := corrosion.GetUser(ctx, r.db, creds.Username)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user == nil {
		// Spend a comparable amount of time as the real path so response
		// latency doesn't reveal whether the username exists.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash(), []byte(creds.Password))
		return nil, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash), []byte(creds.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	p := &Principal{
		Subject: user.Username,
		Realm:   r.Name(),
		Groups:  []string{user.Role}, // legacy admin/operator/viewer treated as a group
	}

	// 2FA gate: if the user has any enrolled factor, require it.
	factors, err := corrosion.ListUser2FA(ctx, r.db, user.Username)
	if err == nil && len(factors) > 0 {
		p.Requires2FA = true
	}

	return p, nil
}

// SyncGroups is a no-op for the local realm.
func (r *LocalRealm) SyncGroups(ctx context.Context) error { return nil }
