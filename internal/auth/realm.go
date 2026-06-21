// Package auth implements litevirt's pluggable authentication and
// authorization. introduces:
//
//   - Realm interface: pluggable authentication backends (local, OIDC, LDAP).
//   - Permission engine: path-based RBAC with propagation flags (Proxmox-shaped).
//   - Sessions: opaque IDs replace JWT-only auth so revoke is immediate.
//   - 2FA: TOTP and WebAuthn behind a uniform challenge interface.
//   - Token scoping: per-token permission subset (intersection with user).
//
// Existing admin/operator/viewer role checks remain functional during the
// transition. RequirePerm consults role_bindings first; if none apply, it
// falls back to the legacy roleLevel comparison.
package auth

import (
	"context"
	"errors"
	"fmt"
)

// Credentials is the realm-agnostic input to Authenticate. Different realms
// consume different fields; unused fields are ignored.
type Credentials struct {
	Username        string // local, ldap
	Password        string // local, ldap
	OIDCCode        string // OIDC code-flow callback code
	OIDCState       string
	OIDCRedirectURI string
}

// Principal is the realm-agnostic result of authentication. The
// permission engine consumes Subject + Realm + Groups to compute effective
// permissions.
type Principal struct {
	// Subject is the user identifier within the realm. For local: the
	// username. For OIDC: the `sub` claim. For LDAP: the bound DN's
	// short name (`sAMAccountName` / `uid` / etc.).
	Subject string

	// Realm is the realm name (e.g. "local", "oidc:corp-okta", "ldap:corp-ad").
	// Used in role-binding principals and audit logs.
	Realm string

	// Groups are realm-specific group identifiers (LDAP group DNs, OIDC
	// `groups` claim values, etc.). Each becomes a `group:<g>@<realm>`
	// principal eligible for role bindings.
	Groups []string

	// Display fields, all best-effort. Empty if the realm doesn't expose them.
	Email string
	Name  string

	// Claims are realm-extra fields (OIDC custom claims, LDAP attributes)
	// preserved for audit logging.
	Claims map[string]string

	// Requires2FA is set by realms that don't enforce 2FA themselves
	// (e.g. local) when the local user has 2FA enrolled. The login handler
	// then issues a `stage=2fa_required` partial response.
	Requires2FA bool
}

// PrincipalID returns the canonical "user:..." string used as a role-binding
// principal value.
func (p *Principal) PrincipalID() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("user:%s@%s", p.Subject, p.Realm)
}

// GroupPrincipalIDs returns the "group:..." principal strings for this
// principal's groups, formatted to match role_bindings.principal column.
func (p *Principal) GroupPrincipalIDs() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.Groups))
	for i, g := range p.Groups {
		out[i] = fmt.Sprintf("group:%s@%s", g, p.Realm)
	}
	return out
}

// Realm is one authentication backend. New backends implement this
// interface and register with the Registry.
type Realm interface {
	// Name uniquely identifies the realm in cluster config and audit
	// logs. Values: "local", "oidc:<provider>", "ldap:<server>".
	Name() string

	// Authenticate verifies credentials. Returns (Principal, nil) on
	// success, (nil, ErrInvalidCredentials) on bad creds, or
	// (nil, other-error) on transport / config failure. Implementations
	// are NOT responsible for 2FA — that's a separate stage handled by
	// the login interceptor.
	Authenticate(ctx context.Context, creds Credentials) (*Principal, error)

	// SyncGroups refreshes any cached group → role mapping from the
	// realm's source-of-truth. Local has nothing to sync. OIDC/LDAP
	// pull memberships periodically (default 5 min).
	SyncGroups(ctx context.Context) error
}

// ErrInvalidCredentials is returned when a realm rejects the supplied
// username/password (or equivalent). Distinct from transport errors so
// the login handler doesn't log "wrong password" as 5xx.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrRealmUnavailable is returned when a realm's backend is unreachable
// (OIDC issuer down, LDAP timeout). The login handler may fall back to
// cached group memberships if the realm config allows it.
var ErrRealmUnavailable = errors.New("realm backend unavailable")

// Registry holds the active realms keyed by name. Built by the daemon
// from /etc/litevirt/auth.yaml at startup; hot-reloadable.
type Registry struct {
	realms map[string]Realm
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{realms: map[string]Realm{}} }

// Register installs a realm. Replaces an existing entry of the same name.
func (r *Registry) Register(realm Realm) {
	if realm == nil {
		return
	}
	r.realms[realm.Name()] = realm
}

// Get returns the realm by name, or nil if not registered.
func (r *Registry) Get(name string) Realm {
	if r == nil {
		return nil
	}
	return r.realms[name]
}

// Names lists registered realm names — used by the login UI to populate
// the realm picker.
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.realms))
	for name := range r.realms {
		out = append(out, name)
	}
	return out
}

// SyncAll refreshes every registered realm's group cache. Errors are
// returned per-realm; one realm being down does not abort the others.
func (r *Registry) SyncAll(ctx context.Context) map[string]error {
	if r == nil {
		return nil
	}
	out := map[string]error{}
	for name, realm := range r.realms {
		if err := realm.SyncGroups(ctx); err != nil {
			out[name] = err
		}
	}
	return out
}
