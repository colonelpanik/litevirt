package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeLDAPConn implements LDAPConn with scripted bind/search behavior.
// Tests construct one per scenario and inject it via fakeDialer.
type fakeLDAPConn struct {
	// bindCalls records every (dn, password) pair Bind() received,
	// in order. The realm calls Bind twice for a successful auth:
	// once as service account, once as the user — tests rely on order.
	bindCalls []bindCall

	// userPasswords maps DN → password the conn will accept for Bind.
	// Any other DN/password combination returns an LDAPResultInvalidCredentials
	// error to mirror the real server.
	userPasswords map[string]string

	// userEntries maps the search filter (post-substitution) → result.
	// One entry per filter; multi-result scenarios use multiResults.
	userEntries map[string]*ldap.Entry

	// Optional override: returns this many entries instead of zero/one
	// regardless of filter — used to test the "ambiguous filter" path.
	multiResults []*ldap.Entry

	// searchErr forces Search to fail (transport-style error).
	searchErr error
	// dialErr is set on the dialer, not the conn — kept here for symmetry.
	closed bool
}

type bindCall struct {
	dn       string
	password string
}

func (c *fakeLDAPConn) Bind(dn, pw string) error {
	c.bindCalls = append(c.bindCalls, bindCall{dn, pw})
	if want, ok := c.userPasswords[dn]; ok && want == pw {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad creds"))
}

func (c *fakeLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	if c.multiResults != nil {
		return &ldap.SearchResult{Entries: c.multiResults}, nil
	}
	if e, ok := c.userEntries[req.Filter]; ok {
		return &ldap.SearchResult{Entries: []*ldap.Entry{e}}, nil
	}
	return &ldap.SearchResult{Entries: nil}, nil
}

func (c *fakeLDAPConn) Close() error { c.closed = true; return nil }

// fakeDialer hands the same fakeLDAPConn to every Dial call so tests can
// inspect interactions afterwards.
type fakeDialer struct {
	conn *fakeLDAPConn
	err  error
}

func (d *fakeDialer) Dial(ctx context.Context, url string, skip bool) (LDAPConn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func makeUserEntry(dn, cn, mail string, groups []string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{
		{Name: "cn", Values: []string{cn}},
		{Name: "mail", Values: []string{mail}},
		{Name: "memberOf", Values: groups},
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

// TestLDAPRealm_HappyPath drives a service-bind → search → user-bind
// sequence and asserts Principal fields.
func TestLDAPRealm_HappyPath(t *testing.T) {
	userDN := "uid=alice,ou=Users,dc=corp,dc=example"
	conn := &fakeLDAPConn{
		userPasswords: map[string]string{
			"cn=svc,dc=corp,dc=example": "svc-pw",
			userDN:                      "alice-pw",
		},
		userEntries: map[string]*ldap.Entry{
			"(&(objectClass=person)(|(uid=alice)(sAMAccountName=alice)))": makeUserEntry(
				userDN, "Alice Example", "alice@example.test",
				[]string{
					"CN=engineers,OU=Groups,DC=corp,DC=example",
					"CN=ops,OU=Groups,DC=corp,DC=example",
				},
			),
		},
	}
	dialer := &fakeDialer{conn: conn}

	realm, err := NewLDAPRealm(LDAPConfig{
		ShortName:    "corp",
		URL:          "ldaps://ad.example",
		BindDN:       "cn=svc,dc=corp,dc=example",
		BindPassword: "svc-pw",
		UserBaseDN:   "ou=Users,dc=corp,dc=example",
		Dialer:       dialer,
	})
	if err != nil {
		t.Fatalf("NewLDAPRealm: %v", err)
	}

	p, err := realm.Authenticate(context.Background(), Credentials{
		Username: "alice", Password: "alice-pw",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != "alice" || p.Realm != "ldap:corp" {
		t.Errorf("unexpected principal: %+v", p)
	}
	if p.Email != "alice@example.test" {
		t.Errorf("Email = %q", p.Email)
	}
	wantGroups := map[string]bool{"engineers": true, "ops": true}
	for _, g := range p.Groups {
		if !wantGroups[g] {
			t.Errorf("unexpected group %q (raw memberOf list should be normalized)", g)
		}
	}
	if len(p.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d (%v)", len(p.Groups), p.Groups)
	}
	if !conn.closed {
		t.Error("expected conn.Close() to be called")
	}
	// Order matters: service bind first, then user bind.
	if len(conn.bindCalls) != 2 {
		t.Fatalf("expected 2 binds, got %d", len(conn.bindCalls))
	}
	if conn.bindCalls[0].dn != "cn=svc,dc=corp,dc=example" {
		t.Errorf("first bind = %q, want service DN", conn.bindCalls[0].dn)
	}
	if conn.bindCalls[1].dn != userDN {
		t.Errorf("second bind = %q, want user DN", conn.bindCalls[1].dn)
	}
}

// TestLDAPRealm_BadPassword_ReturnsErrInvalidCredentials surfaces an
// ldap-protocol "invalid credentials" error as our typed sentinel.
func TestLDAPRealm_BadPassword_ReturnsErrInvalidCredentials(t *testing.T) {
	userDN := "uid=alice,ou=Users,dc=corp,dc=example"
	conn := &fakeLDAPConn{
		userPasswords: map[string]string{
			"cn=svc,dc=corp,dc=example": "svc-pw",
			userDN:                      "right-password",
		},
		userEntries: map[string]*ldap.Entry{
			"(&(objectClass=person)(|(uid=alice)(sAMAccountName=alice)))": makeUserEntry(userDN, "Alice", "a@x", nil),
		},
	}
	realm, _ := NewLDAPRealm(LDAPConfig{
		ShortName: "c", URL: "ldap://x", BindDN: "cn=svc,dc=corp,dc=example",
		BindPassword: "svc-pw", UserBaseDN: "ou=Users,dc=corp,dc=example",
		Dialer: &fakeDialer{conn: conn},
	})
	_, err := realm.Authenticate(context.Background(), Credentials{Username: "alice", Password: "wrong"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// TestLDAPRealm_UserNotFound also returns ErrInvalidCredentials so we don't
// leak account-existence to attackers.
func TestLDAPRealm_UserNotFound(t *testing.T) {
	conn := &fakeLDAPConn{
		userPasswords: map[string]string{"cn=svc,dc=corp,dc=example": "svc"},
	}
	realm, _ := NewLDAPRealm(LDAPConfig{
		ShortName: "c", URL: "ldap://x", BindDN: "cn=svc,dc=corp,dc=example",
		BindPassword: "svc", UserBaseDN: "ou=Users,dc=corp,dc=example",
		Dialer: &fakeDialer{conn: conn},
	})
	_, err := realm.Authenticate(context.Background(), Credentials{Username: "ghost", Password: "x"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// TestLDAPRealm_AmbiguousUserFilter rejects non-unique results so a sloppy
// filter cannot let an attacker auth as the wrong account.
func TestLDAPRealm_AmbiguousUserFilter(t *testing.T) {
	conn := &fakeLDAPConn{
		userPasswords: map[string]string{"cn=svc,dc=corp,dc=example": "svc"},
		multiResults: []*ldap.Entry{
			{DN: "uid=alice,ou=Users,dc=x"},
			{DN: "uid=alice2,ou=Users,dc=x"},
		},
	}
	realm, _ := NewLDAPRealm(LDAPConfig{
		ShortName: "c", URL: "ldap://x", BindDN: "cn=svc,dc=corp,dc=example",
		BindPassword: "svc", UserBaseDN: "ou=Users,dc=corp,dc=example",
		Dialer: &fakeDialer{conn: conn},
	})
	_, err := realm.Authenticate(context.Background(), Credentials{Username: "alice", Password: "x"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for ambiguous match, got %v", err)
	}
}

// TestLDAPRealm_DialFailure_Unavailable surfaces transport errors as
// ErrRealmUnavailable so the login handler can short-circuit cleanly.
func TestLDAPRealm_DialFailure_Unavailable(t *testing.T) {
	realm, _ := NewLDAPRealm(LDAPConfig{
		ShortName: "c", URL: "ldap://x", UserBaseDN: "ou=Users,dc=corp,dc=example",
		Dialer: &fakeDialer{err: errors.New("connection refused")},
	})
	_, err := realm.Authenticate(context.Background(), Credentials{Username: "a", Password: "b"})
	if !errors.Is(err, ErrRealmUnavailable) {
		t.Fatalf("expected ErrRealmUnavailable, got %v", err)
	}
}

// TestLDAPRealm_NormalizeGroupsFromMemberOf isolates the DN→short-name
// transform so AD-style memberOf lists end up as ["engineers", "ops"].
func TestLDAPRealm_NormalizeGroupsFromMemberOf(t *testing.T) {
	groups := []string{
		"CN=engineers,OU=Groups,DC=corp,DC=example",
		"cn=ops,ou=Groups,dc=corp,dc=example", // case-mixed
		"engineers",                           // already short
		"CN=engineers,OU=Other,DC=x",          // duplicate by short name
	}
	out := normalizeGroups(groups, "cn")
	want := []string{"engineers", "ops"}
	if len(out) != len(want) {
		t.Fatalf("normalized = %v, want %v", out, want)
	}
	for i, g := range want {
		if out[i] != g {
			t.Errorf("normalized[%d] = %q, want %q", i, out[i], g)
		}
	}
}
