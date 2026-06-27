// WebAuthn second factor.
//
// Architectural notes:
//
//   - go-webauthn/webauthn handles the cryptographic dance and
//     conformance; we wrap it with the litevirt-specific bits
//     (storing credentials in user_2fa, deriving WebauthnUser from
//     the existing local-user table).
//   - Registration and login are each a two-call dance:
//       Begin  → server returns challenge JSON
//       Finish → client posts the signed assertion / attestation
//     We persist the in-flight session on the daemon between the
//     two calls. uses an in-memory map keyed by user
//     name; (federation) will move this to a CRDT-replicated
//     short-lived store so any cluster node can complete the dance.
//   - CLI parity is not in scope — the WebAuthn handshake requires a
//     browser-resident authenticator. TOTP remains the CLI factor.

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wapkg "github.com/go-webauthn/webauthn/webauthn"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// credLabel encodes a credential ID as a stable string suitable for
// use as a user_2fa.label key. We base64url-encode (no padding) so
// the same byte ID always maps to the same label.
func credLabel(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

// WebAuthnConfig drives go-webauthn's wapkg.New(). Defaults are
// reasonable for litevirt's standalone-cluster shape; multi-tenant
// deployments can override the RP fields once lands.
type WebAuthnConfig struct {
	RPDisplayName string   // shown to users in the security-key prompt
	RPID          string   // the bare host (e.g. "litevirt.corp")
	RPOrigins     []string // ["https://litevirt.corp"]
}

// WebAuthnService bundles the go-webauthn engine with persistence
// helpers. One instance per daemon; constructed at startup once we
// know the cluster's UI domain.
type WebAuthnService struct {
	engine *wapkg.WebAuthn
	db     *corrosion.Client

	mu       sync.Mutex
	sessions map[string]*wapkg.SessionData // user → in-flight challenge
}

// NewWebAuthnService validates config and constructs the service.
// Returns an error if go-webauthn refuses the config (typically
// missing RPID or origin).
func NewWebAuthnService(db *corrosion.Client, cfg WebAuthnConfig) (*WebAuthnService, error) {
	wcfg := &wapkg.Config{
		RPDisplayName: defaultStr(cfg.RPDisplayName, "litevirt"),
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	}
	engine, err := wapkg.New(wcfg)
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	return &WebAuthnService{
		engine:   engine,
		db:       db,
		sessions: map[string]*wapkg.SessionData{},
	}, nil
}

// BeginRegistration starts an enrolment for `username`. The returned
// JSON is what the browser posts to navigator.credentials.create.
// FinishRegistration must be called within the session window
// (default 60s — go-webauthn enforces).
func (s *WebAuthnService) BeginRegistration(ctx context.Context, username string) ([]byte, error) {
	user, err := s.loadUser(ctx, username)
	if err != nil {
		return nil, err
	}
	creation, sessionData, err := s.engine.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}
	s.storeSession(username, sessionData)
	return json.Marshal(creation)
}

// FinishRegistration validates the browser's signed attestation and
// persists the resulting credential under user_2fa.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, username string, attestation []byte) error {
	sess := s.takeSession(username)
	if sess == nil {
		return errors.New("no in-flight registration session")
	}
	user, err := s.loadUser(ctx, username)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytesReader(attestation))
	if err != nil {
		return fmt.Errorf("parse attestation: %w", err)
	}
	cred, err := s.engine.CreateCredential(user, *sess, parsed)
	if err != nil {
		return fmt.Errorf("verify attestation: %w", err)
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return corrosion.InsertUser2FA(ctx, s.db, corrosion.User2FARecord{
		Username: username, Method: "webauthn",
		Secret: string(blob), Label: credLabel(cred.ID),
	})
}

// BeginLogin mirrors BeginRegistration for the assertion (login)
// dance.
func (s *WebAuthnService) BeginLogin(ctx context.Context, username string) ([]byte, error) {
	user, err := s.loadUser(ctx, username)
	if err != nil {
		return nil, err
	}
	if len(user.WebAuthnCredentials()) == 0 {
		return nil, errors.New("user has no enrolled WebAuthn credentials")
	}
	assertion, sessionData, err := s.engine.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}
	s.storeSession(username, sessionData)
	return json.Marshal(assertion)
}

// FinishLogin validates the signed assertion and bumps the
// last_used_at timestamp on the matched credential.
func (s *WebAuthnService) FinishLogin(ctx context.Context, username string, assertion []byte) error {
	sess := s.takeSession(username)
	if sess == nil {
		return errors.New("no in-flight login session")
	}
	user, err := s.loadUser(ctx, username)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytesReader(assertion))
	if err != nil {
		return fmt.Errorf("parse assertion: %w", err)
	}
	cred, err := s.engine.ValidateLogin(user, *sess, parsed)
	if err != nil {
		return fmt.Errorf("validate assertion: %w", err)
	}
	// Confirm-and-consume the SPECIFIC asserted credential, scoped to the active
	// set. ValidateLogin runs against the credentials loaded at the top of this
	// call; if that credential was disabled (tombstoned) or its 2FA set
	// deactivated (active epoch changed — e.g. a delete→re-enroll) in the
	// meantime, the gated touch changes zero rows and we reject the login rather
	// than authenticate against a stale credential.
	touched, err := corrosion.TouchUser2FA(ctx, s.db, username, "webauthn", credLabel(cred.ID))
	if err != nil {
		return fmt.Errorf("confirm credential: %w", err)
	}
	if !touched {
		return errors.New("authenticating credential is no longer active")
	}
	return nil
}

// loadUser fetches the user-shape go-webauthn wants. Wraps the
// litevirt user + their persisted credentials in a webauthnUser.
func (s *WebAuthnService) loadUser(ctx context.Context, username string) (*webauthnUser, error) {
	u, err := corrosion.GetUser(ctx, s.db, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("user %q not found", username)
	}
	factors, err := corrosion.ListUser2FA(ctx, s.db, username)
	if err != nil {
		return nil, err
	}
	wu := &webauthnUser{username: u.Username, displayName: u.Username}
	for _, f := range factors {
		if f.Method != "webauthn" {
			continue
		}
		var c wapkg.Credential
		if err := json.Unmarshal([]byte(f.Secret), &c); err != nil {
			continue // skip mangled rows
		}
		wu.creds = append(wu.creds, c)
	}
	return wu, nil
}

func (s *WebAuthnService) storeSession(user string, sess *wapkg.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[user] = sess
}
func (s *WebAuthnService) takeSession(user string) *wapkg.SessionData {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[user]
	delete(s.sessions, user)
	return sess
}

// webauthnUser implements wapkg.User. We don't expose this struct —
// it's an internal adapter between our user_2fa schema and
// go-webauthn's expected interface.
type webauthnUser struct {
	username    string
	displayName string
	creds       []wapkg.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                      { return []byte(u.username) }
func (u *webauthnUser) WebAuthnName() string                    { return u.username }
func (u *webauthnUser) WebAuthnDisplayName() string             { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []wapkg.Credential { return u.creds }
func (u *webauthnUser) WebAuthnIcon() string                    { return "" }

// bytesReader exists so callers don't need to import bytes separately
// at every site.
func bytesReader(b []byte) *bytesReaderImpl { return &bytesReaderImpl{b: b} }

type bytesReaderImpl struct {
	b []byte
	i int
}

func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, fmtErrorEOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
func (r *bytesReaderImpl) Close() error { return nil }

// fmtErrorEOF is returned at end of bytesReaderImpl; we don't depend
// on io.EOF directly to avoid the larger import surface in this file.
var fmtErrorEOF = errors.New("EOF")

// asTime makes the go-webauthn TimedSessionData round-trip happy in
// tests where we want to inspect a session's expiry.
func sessionExpiry(sess *wapkg.SessionData) time.Time {
	if sess == nil {
		return time.Time{}
	}
	return sess.Expires
}
