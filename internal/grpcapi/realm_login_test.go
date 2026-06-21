package grpcapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// mockOIDCServer is a minimal OIDC IdP for these handler tests.
// Mirrors the helper in internal/auth/oidc_test.go but lives here so
// the gRPC-handler test doesn't have to go cross-package.
type mockOIDCServer struct {
	server   *httptest.Server
	signer   *rsa.PrivateKey
	keyID    string
	issuer   string
	clientID string
	clientSecret string
	expectedCode string
	subject  string
	groups   []string
	nonce    string // if set, echoed into the id_token's `nonce` claim
}

func (m *mockOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]interface{}{
		"issuer":                                m.issuer,
		"authorization_endpoint":                m.issuer + "/auth",
		"token_endpoint":                        m.issuer + "/token",
		"jwks_uri":                              m.issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (m *mockOIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := m.signer.Public().(*rsa.PublicKey)
	jwk := map[string]interface{}{
		"kty": "RSA", "kid": m.keyID, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{jwk}})
}

func (m *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if got := r.PostForm.Get("code"); got != m.expectedCode {
		http.Error(w, "bad code", http.StatusBadRequest)
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		user = r.PostForm.Get("client_id")
		pass = r.PostForm.Get("client_secret")
	}
	if user != m.clientID || pass != m.clientSecret {
		http.Error(w, "bad client", http.StatusUnauthorized)
		return
	}
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	now := time.Now()
	claims := map[string]interface{}{
		"iss": m.issuer, "aud": m.clientID, "sub": m.subject,
		"email": m.subject + "@example.test",
		"name":  strings.Title(m.subject),
		"groups": m.groups,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if m.nonce != "" {
		claims["nonce"] = m.nonce
	}
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "fake", "token_type": "Bearer", "expires_in": 300,
		"id_token": idToken,
	})
}

func startMockOIDC(t *testing.T, clientID, clientSecret, code, subject string, groups []string) *mockOIDCServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	m := &mockOIDCServer{
		signer: key, keyID: "k1",
		clientID: clientID, clientSecret: clientSecret,
		expectedCode: code, subject: subject, groups: groups,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/token", m.handleToken)
	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

// TestLogin_ViaRegistry_LocalRealm is the regression test for the
// dispatch path: registry-wired Server still handles the local realm
// just like the legacy hardcoded path did.
func TestLogin_ViaRegistry_LocalRealm(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "operator", "hunter2")

	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	s.SetRealmRegistry(reg)

	resp, err := s.Login(context.Background(), &pb.LoginRequest{
		Username: "alice", Password: "hunter2",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !strings.HasPrefix(resp.Token, SessionTokenPrefix) {
		t.Fatalf("expected session token, got %q", resp.Token)
	}
}

// TestLogin_ViaRegistry_OIDC_HappyPath drives Login through the
// registry against a mock OIDC IdP. Closes the loop the audit
// flagged: a real OIDC config must actually authenticate end-to-end.
func TestLogin_ViaRegistry_OIDC_HappyPath(t *testing.T) {
	const (
		clientID     = "lv-test"
		clientSecret = "shh"
		code         = "auth-code-1"
		subject      = "alice"
	)
	mock := startMockOIDC(t, clientID, clientSecret, code, subject, []string{"engineers"})

	s := testServer(t)
	realm, err := auth.NewOIDCRealm(context.Background(), auth.OIDCConfig{
		ShortName:    "test",
		IssuerURL:    mock.issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://litevirt.test/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDCRealm: %v", err)
	}
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	reg.Register(realm)
	s.SetRealmRegistry(reg)

	// Pre-stamp the CSRF state so the realm accepts the callback, and feed the
	// issued nonce to the mock so its ID token echoes it back (the realm now
	// verifies the nonce as part of the OIDC hardening).
	state := "csrf-token-1"
	authURL := realm.AuthURL(state)
	if u, err := url.Parse(authURL); err == nil {
		mock.nonce = u.Query().Get("nonce")
	}

	resp, err := s.Login(context.Background(), &pb.LoginRequest{
		Realm:     "oidc:test",
		OidcCode:  code,
		OidcState: state,
	})
	if err != nil {
		t.Fatalf("Login (OIDC): %v", err)
	}
	if !strings.HasPrefix(resp.Token, SessionTokenPrefix) {
		t.Fatalf("expected session bearer, got %q", resp.Token)
	}
	if resp.Username != subject {
		t.Errorf("Username = %q, want %q", resp.Username, subject)
	}

	// EnsureUserShadow should have created a local users row so
	// subsequent RBAC checks have a stable subject.
	got, err := corrosion.GetUser(context.Background(), s.db, subject)
	if err != nil || got == nil {
		t.Errorf("expected shadow user row for %q, got %+v err=%v", subject, got, err)
	}
}

// TestLogin_ViaRegistry_UnknownRealm is the operator-typo regression.
func TestLogin_ViaRegistry_UnknownRealm(t *testing.T) {
	s := testServer(t)
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	s.SetRealmRegistry(reg)

	_, err := s.Login(context.Background(), &pb.LoginRequest{
		Realm: "oidc:does-not-exist", Username: "x", Password: "y",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented for unknown realm, got %v", err)
	}
}

// TestListRealms_ReturnsRegistryNames covers the discovery RPC the UI
// calls to populate the realm dropdown.
func TestListRealms_ReturnsRegistryNames(t *testing.T) {
	s := testServer(t)
	reg := auth.NewRegistry()
	reg.Register(auth.NewLocalRealm(s.db))
	s.SetRealmRegistry(reg)

	resp, err := s.ListRealms(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListRealms: %v", err)
	}
	if len(resp.Realms) != 1 || resp.Realms[0] != "local" {
		t.Errorf("Realms = %v, want [local]", resp.Realms)
	}
}

// TestListRealms_NilRegistry_FallsBackToLocal — tests that don't wire
// a registry still see a sane response.
func TestListRealms_NilRegistry_FallsBackToLocal(t *testing.T) {
	s := testServer(t)
	resp, err := s.ListRealms(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListRealms: %v", err)
	}
	if len(resp.Realms) != 1 || resp.Realms[0] != "local" {
		t.Errorf("Realms = %v, want [local]", resp.Realms)
	}
}
