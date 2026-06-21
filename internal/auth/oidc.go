package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// OIDCConfig describes one OIDC provider. Multiple realms may coexist
// (one per IdP). The realm name is "oidc:<short-name>" (e.g. "oidc:corp-okta")
// so role-bindings reference a specific provider.
type OIDCConfig struct {
	// ShortName ends up as the realm name suffix: "oidc:<ShortName>".
	ShortName string

	// IssuerURL is the OIDC discovery URL root (e.g. "https://accounts.google.com").
	IssuerURL string

	// ClientID / ClientSecret were issued by the IdP for this litevirt cluster.
	ClientID     string
	ClientSecret string

	// RedirectURL is litevirt's UI callback URL the IdP must whitelist.
	RedirectURL string

	// Scopes always includes "openid"; "profile email groups" are added so
	// SyncGroups can populate Principal.Groups.
	Scopes []string

	// GroupsClaim is the claim name carrying group memberships. Defaults
	// to "groups" (Okta, Auth0, Keycloak, Azure AD with proper config).
	GroupsClaim string

	// EmailClaim defaults to "email".
	EmailClaim string

	// NameClaim defaults to "name" for the human-friendly display name.
	NameClaim string

	// SubjectClaim defaults to "sub" — the stable per-user IdP identifier.
	// Override only if an IdP issues unstable subs.
	SubjectClaim string

	// HTTPClient is optional; when nil, oauth2 uses the default. Tests
	// inject an httptest-backed client so the OIDC realm talks to a
	// mock provider over an in-process listener.
	HTTPClient ContextClient
}

// ContextClient is a minimal interface so tests can swap the http client
// without depending directly on net/http.
type ContextClient interface {
	WithContext(ctx context.Context) context.Context
}

// OIDCRealm authenticates users against an OIDC provider via the
// authorization-code flow. ID tokens are validated using the provider's
// JWKS (auto-fetched from IssuerURL/.well-known/openid-configuration).
type OIDCRealm struct {
	cfg          OIDCConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauthCfg     *oauth2.Config
	groupsClaim  string
	emailClaim   string
	nameClaim    string
	subjectClaim string

	mu          sync.Mutex
	stateStore  map[string]oidcFlow // in-flight auth-code flows; cleaned on use or expiry
	stateExpiry time.Duration
}

// oidcFlow is the server-side state for one in-flight authorization-code
// exchange. It is held in-memory on the node that issued AuthURL — the IdP
// redirects the browser back to the same node, so cluster consensus isn't
// needed.
//
//   - expiry binds the CSRF state to a short window.
//   - verifier is the PKCE code_verifier; its S256 challenge went to the IdP
//     in AuthURL, and the verifier is replayed at the token endpoint so an
//     intercepted authorization code is useless without it (RFC 7636).
//   - nonce must echo back in the ID token's `nonce` claim, binding the token
//     to this login and defeating ID-token replay/injection (OIDC core §3.1.2).
type oidcFlow struct {
	expiry   time.Time
	verifier string
	nonce    string
}

// NewOIDCRealm initialises a realm by fetching the provider's discovery
// document. Returns ErrRealmUnavailable if the IdP is unreachable —
// callers may register the realm anyway and retry on reload.
func NewOIDCRealm(ctx context.Context, cfg OIDCConfig) (*OIDCRealm, error) {
	if cfg.ShortName == "" {
		return nil, fmt.Errorf("oidc: ShortName required")
	}
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: IssuerURL and ClientID required")
	}
	if cfg.HTTPClient != nil {
		ctx = cfg.HTTPClient.WithContext(ctx)
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRealmUnavailable, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}
	r := &OIDCRealm{
		cfg:          cfg,
		provider:     provider,
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		groupsClaim:  defaultStr(cfg.GroupsClaim, "groups"),
		emailClaim:   defaultStr(cfg.EmailClaim, "email"),
		nameClaim:    defaultStr(cfg.NameClaim, "name"),
		subjectClaim: defaultStr(cfg.SubjectClaim, "sub"),
		stateStore:   map[string]oidcFlow{},
		stateExpiry:  10 * time.Minute,
		oauthCfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
	}
	return r, nil
}

// Name returns "oidc:<ShortName>".
func (r *OIDCRealm) Name() string { return "oidc:" + r.cfg.ShortName }

// AuthURL returns the URL the UI should redirect the user to. The caller's
// `state` is the CSRF token the callback must present back. AuthURL also mints
// a PKCE code_verifier and a nonce, stashes both alongside the state, and
// sends the S256 challenge + nonce to the IdP so Authenticate can later prove
// the code wasn't intercepted and the ID token isn't a replay.
func (r *OIDCRealm) AuthURL(state string) string {
	verifier := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier() // reused as a high-entropy random nonce
	r.rememberFlow(state, verifier, nonce)
	return r.oauthCfg.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	)
}

// Authenticate consumes an OIDC code-flow callback. Credentials must carry
// OIDCCode and OIDCState; OIDCRedirectURI may override the configured
// RedirectURL when the UI is served behind a different ingress path.
//
// Returns ErrInvalidCredentials when state or ID-token verification fails;
// ErrRealmUnavailable on transient IdP errors (token endpoint down).
func (r *OIDCRealm) Authenticate(ctx context.Context, creds Credentials) (*Principal, error) {
	if creds.OIDCCode == "" || creds.OIDCState == "" {
		return nil, ErrInvalidCredentials
	}
	flow, ok := r.consumeFlow(creds.OIDCState)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if r.cfg.HTTPClient != nil {
		ctx = r.cfg.HTTPClient.WithContext(ctx)
	}

	cfg := *r.oauthCfg
	if creds.OIDCRedirectURI != "" {
		cfg.RedirectURL = creds.OIDCRedirectURI
	}
	// Replay the PKCE verifier so the IdP can confirm this caller is the same
	// one that initiated the flow — an intercepted code alone won't exchange.
	tok, err := cfg.Exchange(ctx, creds.OIDCCode, oauth2.VerifierOption(flow.verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: token exchange: %v", ErrRealmUnavailable, err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("%w: no id_token in token response", ErrRealmUnavailable)
	}
	idTok, err := r.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("%w: id-token verify: %v", ErrInvalidCredentials, err)
	}
	// The ID token must carry back the exact nonce we issued for this flow.
	// A mismatch (or a token minted for a different login) is a replay/
	// injection attempt.
	if idTok.Nonce != flow.nonce {
		return nil, fmt.Errorf("%w: id-token nonce mismatch", ErrInvalidCredentials)
	}

	var claims map[string]interface{}
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	subject := stringClaim(claims, r.subjectClaim)
	if subject == "" {
		return nil, fmt.Errorf("%w: missing %q claim", ErrInvalidCredentials, r.subjectClaim)
	}

	p := &Principal{
		Subject: subject,
		Realm:   r.Name(),
		Email:   stringClaim(claims, r.emailClaim),
		Name:    stringClaim(claims, r.nameClaim),
		Groups:  stringSliceClaim(claims, r.groupsClaim),
		Claims:  flattenClaims(claims),
	}
	return p, nil
}

// SyncGroups is a no-op — OIDC group memberships arrive as ID-token
// claims at login time, not via a separate sync API. Reserved for future
// use if we add a back-channel claim-refresh.
func (r *OIDCRealm) SyncGroups(ctx context.Context) error { return nil }

// EnsureUserShadow creates a row in the local users table for an OIDC
// principal so existing handlers (RBAC, audit) can reference the user
// by username. The shadow row has password_hash="" so password login is
// impossible — the user can ONLY arrive via the realm.
//
// Idempotent: subsequent calls update display fields without touching
// the password.
func EnsureUserShadow(ctx context.Context, db *corrosion.Client, p *Principal, defaultRole string) error {
	if p == nil || p.Subject == "" {
		return errors.New("nil principal")
	}
	existing, err := corrosion.GetUser(ctx, db, p.Subject)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	role := defaultRole
	if role == "" {
		role = "viewer"
	}
	return corrosion.InsertUser(ctx, db, p.Subject, role, "")
}

// rememberFlow stores the per-login PKCE verifier + nonce under the CSRF
// state with a 10-minute expiry so the callback can validate it. Held
// in-memory; cluster-wide consensus is not needed because the auth-code flow
// always returns to the node that issued AuthURL.
func (r *OIDCRealm) rememberFlow(state, verifier, nonce string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for s, f := range r.stateStore {
		if now.After(f.expiry) {
			delete(r.stateStore, s)
		}
	}
	r.stateStore[state] = oidcFlow{
		expiry:   now.Add(r.stateExpiry),
		verifier: verifier,
		nonce:    nonce,
	}
}

// consumeFlow removes and validates a flow by its state token. Returns
// ok=false if the state is unknown or expired — both are treated as CSRF/
// replay failures.
func (r *OIDCRealm) consumeFlow(state string) (oidcFlow, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.stateStore[state]
	if !ok {
		return oidcFlow{}, false
	}
	delete(r.stateStore, state)
	if time.Now().After(f.expiry) {
		return oidcFlow{}, false
	}
	return f, true
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func stringClaim(c map[string]interface{}, key string) string {
	if v, ok := c[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func stringSliceClaim(c map[string]interface{}, key string) []string {
	v, ok := c[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		// Some IdPs return groups as a comma-separated string.
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

func flattenClaims(c map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, v := range c {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
