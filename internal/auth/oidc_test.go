package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ── Mock OIDC provider ─────────────────────────────────────────────────────
//
// A minimal IdP good enough to drive the realm:
//   GET  /.well-known/openid-configuration  → discovery doc
//   GET  /jwks                              → JWKS (one RSA key)
//   POST /token                             → exchanges fixed code for ID token
//
// The provider is single-use per test (one expected code, one issued ID token).
// Discovery, JWKS verification, and the token endpoint all run over an
// httptest.Server so no network I/O is involved.

type mockOIDC struct {
	server   *httptest.Server
	signer   *rsa.PrivateKey
	keyID    string
	issuer   string
	clientID string
	clientSecret string

	// Pre-stamped values the test expects to round-trip.
	expectedCode string
	subject      string
	email        string
	groups       []string
	nonce        string // if set, echoed into the id_token's `nonce` claim
}

func newMockOIDC(t *testing.T, clientID, clientSecret, expectedCode, subject string, groups []string) *mockOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	m := &mockOIDC{
		signer:       key,
		keyID:        "test-key",
		clientID:     clientID,
		clientSecret: clientSecret,
		expectedCode: expectedCode,
		subject:      subject,
		email:        subject + "@example.test",
		groups:       groups,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "auth endpoint unused in test", http.StatusNotImplemented)
	})
	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

// httpClientForCtx returns a context-injecting wrapper that lets the
// realm reach the mock without hitting the network. We rely on the mock
// being plain HTTP (httptest.NewServer), so the default transport works
// — the wrapper exists for parity with HTTPS-issuer fixtures.
type ctxClient struct{ inner *http.Client }

func (c *ctxClient) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2HTTPClientKey{}, c.inner)
}

// oauth2HTTPClientKey mirrors oauth2's internal context key so go-oidc and
// golang.org/x/oauth2 both pick up the override. The actual key is opaque,
// but oauth2 looks up by interface{}; we use a private type so test code
// alone can inject. In practice we don't need this for the in-process
// mock — keeping the hook present documents the seam.
type oauth2HTTPClientKey struct{}

func (m *mockOIDC) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]interface{}{
		"issuer":                 m.issuer,
		"authorization_endpoint": m.issuer + "/auth",
		"token_endpoint":         m.issuer + "/token",
		"jwks_uri":               m.issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (m *mockOIDC) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := m.signer.Public().(*rsa.PublicKey)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": m.keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{jwk}})
}

func (m *mockOIDC) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if got := r.PostForm.Get("code"); got != m.expectedCode {
		http.Error(w, "bad code: "+got, http.StatusBadRequest)
		return
	}
	// Validate basic-auth or POST client credentials.
	user, pass, ok := r.BasicAuth()
	if !ok {
		user = r.PostForm.Get("client_id")
		pass = r.PostForm.Get("client_secret")
	}
	if user != m.clientID || pass != m.clientSecret {
		http.Error(w, "bad client", http.StatusUnauthorized)
		return
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	claims := map[string]interface{}{
		"iss":    m.issuer,
		"aud":    m.clientID,
		"sub":    m.subject,
		"email":  m.email,
		"name":   strings.Title(m.subject),
		"groups": m.groups,
		"iat":    now.Unix(),
		"exp":    now.Add(5 * time.Minute).Unix(),
	}
	if m.nonce != "" {
		claims["nonce"] = m.nonce
	}
	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "fake-access",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

// httpClient gives the realm a transport that talks to the mock.
// httptest.NewServer is plain HTTP, so the default transport already works —
// we only need to relax TLS verification when the test upgrades to TLS.
func (m *mockOIDC) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// TestOIDCRealm_AuthCodeFlow_HappyPath drives Discovery → AuthURL →
// callback → token exchange → ID-token verification end-to-end against
// the mock IdP, asserting we end up with the expected Principal.
func TestOIDCRealm_AuthCodeFlow_HappyPath(t *testing.T) {
	const (
		clientID     = "litevirt-test"
		clientSecret = "shh"
		code         = "abc123"
		subject      = "alice"
	)
	mock := newMockOIDC(t, clientID, clientSecret, code, subject, []string{"engineers", "ops"})

	ctx := context.Background()
	realm, err := NewOIDCRealm(ctx, OIDCConfig{
		ShortName:    "test",
		IssuerURL:    mock.issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://litevirt.test/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCRealm: %v", err)
	}
	if got := realm.Name(); got != "oidc:test" {
		t.Errorf("realm name = %q, want oidc:test", got)
	}

	// Drive the flow: AuthURL stamps state; callback presents that state.
	state := "csrf-token-1"
	authURL := realm.AuthURL(state)
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if got := u.Query().Get("state"); got != state {
		t.Errorf("state in auth URL = %q, want %q", got, state)
	}
	// AuthURL must now drive PKCE (S256 challenge) and a nonce.
	if got := u.Query().Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if u.Query().Get("code_challenge") == "" {
		t.Error("expected a PKCE code_challenge in the auth URL")
	}
	nonce := u.Query().Get("nonce")
	if nonce == "" {
		t.Fatal("expected a nonce in the auth URL")
	}
	// The IdP echoes the nonce back in the ID token; the realm verifies it.
	mock.nonce = nonce

	p, err := realm.Authenticate(ctx, Credentials{
		OIDCCode:  code,
		OIDCState: state,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != subject {
		t.Errorf("Subject = %q, want %q", p.Subject, subject)
	}
	if p.Realm != "oidc:test" {
		t.Errorf("Realm = %q, want oidc:test", p.Realm)
	}
	if p.Email != subject+"@example.test" {
		t.Errorf("Email = %q", p.Email)
	}
	wantGroups := map[string]bool{"engineers": true, "ops": true}
	if len(p.Groups) != len(wantGroups) {
		t.Errorf("Groups = %v, want %v", p.Groups, wantGroups)
	}
	for _, g := range p.Groups {
		if !wantGroups[g] {
			t.Errorf("unexpected group %q", g)
		}
	}
	gids := p.GroupPrincipalIDs()
	wantGIDs := map[string]bool{"group:engineers@oidc:test": true, "group:ops@oidc:test": true}
	for _, g := range gids {
		if !wantGIDs[g] {
			t.Errorf("unexpected group principal id %q", g)
		}
	}
	if pid := p.PrincipalID(); pid != "user:alice@oidc:test" {
		t.Errorf("PrincipalID = %q", pid)
	}
}

// TestOIDCRealm_StateMismatchRejected verifies CSRF state binding.
func TestOIDCRealm_StateMismatchRejected(t *testing.T) {
	mock := newMockOIDC(t, "cid", "cs", "code", "alice", nil)
	realm, err := NewOIDCRealm(context.Background(), OIDCConfig{
		ShortName: "t", IssuerURL: mock.issuer, ClientID: "cid", ClientSecret: "cs",
		RedirectURL: "http://x/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCRealm: %v", err)
	}
	_ = realm.AuthURL("real-state")
	_, err = realm.Authenticate(context.Background(), Credentials{
		OIDCCode: "code", OIDCState: "wrong-state",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for state mismatch, got %v", err)
	}
}

// TestOIDCRealm_BadCodeRejected verifies the IdP's rejection surfaces as
// ErrRealmUnavailable (transient at the token endpoint, not necessarily a
// caller-side credential issue).
func TestOIDCRealm_BadCodeRejected(t *testing.T) {
	mock := newMockOIDC(t, "cid", "cs", "good-code", "alice", nil)
	realm, err := NewOIDCRealm(context.Background(), OIDCConfig{
		ShortName: "t", IssuerURL: mock.issuer, ClientID: "cid", ClientSecret: "cs",
		RedirectURL: "http://x/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCRealm: %v", err)
	}
	state := "s"
	_ = realm.AuthURL(state)
	_, err = realm.Authenticate(context.Background(), Credentials{
		OIDCCode: "bad-code", OIDCState: state,
	})
	if err == nil || !errors.Is(err, ErrRealmUnavailable) {
		t.Fatalf("expected ErrRealmUnavailable wrapping token error, got %v", err)
	}
}

// TestOIDCRealm_StateExpired verifies state tokens expire so a long-stalled
// callback can't be replayed forever.
func TestOIDCRealm_StateExpired(t *testing.T) {
	mock := newMockOIDC(t, "cid", "cs", "c", "alice", nil)
	realm, err := NewOIDCRealm(context.Background(), OIDCConfig{
		ShortName: "t", IssuerURL: mock.issuer, ClientID: "cid", ClientSecret: "cs",
		RedirectURL: "http://x/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCRealm: %v", err)
	}
	realm.stateExpiry = -time.Second // immediately expired
	state := "s"
	realm.rememberFlow(state, "verifier", "nonce")
	if _, ok := realm.consumeFlow(state); ok {
		t.Fatal("expected expired state to be rejected")
	}
}

// TestOIDCRealm_Discovery_Unreachable surfaces transport failures as
// ErrRealmUnavailable at construction time.
func TestOIDCRealm_Discovery_Unreachable(t *testing.T) {
	_, err := NewOIDCRealm(context.Background(), OIDCConfig{
		ShortName: "t", IssuerURL: "http://127.0.0.1:1", ClientID: "cid",
		RedirectURL: "http://x/cb",
	})
	if err == nil || !errors.Is(err, ErrRealmUnavailable) {
		t.Fatalf("expected ErrRealmUnavailable, got %v", err)
	}
}

// keep imports in use even if a code path is dropped later
var _ = fmt.Sprintf
