package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig describes one LDAP/AD bind. Realm name becomes
// "ldap:<ShortName>" so role-bindings reference a specific directory.
type LDAPConfig struct {
	ShortName string

	// URL is the LDAP server URL, e.g. "ldaps://ad.corp.example:636".
	URL string

	// BindDN / BindPassword — the service account we use to search for users.
	// Anonymous bind is supported: leave both empty.
	BindDN       string
	BindPassword string

	// UserBaseDN is the subtree to search for users, e.g.
	// "ou=Users,dc=corp,dc=example".
	UserBaseDN string

	// UserFilter selects the user record. Use "%s" as the literal username
	// placeholder; we escape it before substitution. Defaults to:
	//   (&(objectClass=person)(|(uid=%s)(sAMAccountName=%s)))
	UserFilter string

	// GroupBaseDN scopes the group search; empty disables explicit group
	// search and we rely on the user record's memberOf attribute instead.
	GroupBaseDN string

	// GroupFilter is the search filter for groups the user belongs to.
	// "%s" is replaced with the user DN. Defaults to:
	//   (&(objectClass=group)(member=%s))
	GroupFilter string

	// Attributes — overridable so non-standard schemas can be handled.
	UserNameAttr  string // default "cn"
	UserMailAttr  string // default "mail"
	UserGroupAttr string // default "memberOf"
	GroupNameAttr string // default "cn"

	// SkipTLSVerify disables certificate validation. Use only for self-
	// signed dev directories; production deployments should ship CA certs
	// via the host trust store.
	SkipTLSVerify bool

	// Dialer lets tests inject a fake LDAP connection. Production callers
	// leave this nil — we then use ldap.DialURL.
	Dialer LDAPDialer
}

// LDAPConn is the subset of *ldap.Conn we depend on. Tests implement this
// directly without standing up a real server.
type LDAPConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPDialer returns a connected LDAPConn. Production: ldap.DialURL.
type LDAPDialer interface {
	Dial(ctx context.Context, url string, skipTLSVerify bool) (LDAPConn, error)
}

// LDAPRealm authenticates against an LDAP/AD directory.
type LDAPRealm struct {
	cfg LDAPConfig
}

// NewLDAPRealm validates required config and returns a realm ready to
// authenticate. Connection is per-request so a single bad connection does
// not poison subsequent logins.
func NewLDAPRealm(cfg LDAPConfig) (*LDAPRealm, error) {
	if cfg.ShortName == "" {
		return nil, errors.New("ldap: ShortName required")
	}
	if cfg.URL == "" || cfg.UserBaseDN == "" {
		return nil, errors.New("ldap: URL and UserBaseDN required")
	}
	cfg.UserFilter = defaultStr(cfg.UserFilter, "(&(objectClass=person)(|(uid=%s)(sAMAccountName=%s)))")
	cfg.GroupFilter = defaultStr(cfg.GroupFilter, "(&(objectClass=group)(member=%s))")
	cfg.UserNameAttr = defaultStr(cfg.UserNameAttr, "cn")
	cfg.UserMailAttr = defaultStr(cfg.UserMailAttr, "mail")
	cfg.UserGroupAttr = defaultStr(cfg.UserGroupAttr, "memberOf")
	cfg.GroupNameAttr = defaultStr(cfg.GroupNameAttr, "cn")
	if cfg.Dialer == nil {
		cfg.Dialer = realLDAPDialer{}
	}
	// Warn loudly about transport configurations that expose the bind
	// password (search-then-bind sends it in the clear over plain LDAP). We
	// don't refuse — some clusters tunnel LDAP over an already-encrypted link
	// (stunnel/VPN) — but a misconfiguration shouldn't be silent.
	if strings.HasPrefix(strings.ToLower(cfg.URL), "ldap://") {
		slog.Warn("LDAP realm uses plaintext ldap:// — bind credentials are sent unencrypted; prefer ldaps:// or StartTLS",
			"realm", "ldap:"+cfg.ShortName, "url", cfg.URL)
	}
	if cfg.SkipTLSVerify {
		slog.Warn("LDAP realm has SkipTLSVerify=true — server certificate is NOT validated, exposing logins to MITM",
			"realm", "ldap:"+cfg.ShortName)
	}
	return &LDAPRealm{cfg: cfg}, nil
}

// Name returns "ldap:<ShortName>".
func (r *LDAPRealm) Name() string { return "ldap:" + r.cfg.ShortName }

// Authenticate performs a search-then-bind:
//  1. Bind as service account (or anonymous).
//  2. Search for the user; require exactly one result.
//  3. Bind as the user with the supplied password — this is the actual
//     credential check.
//  4. Read groups from `memberOf` and/or a follow-up search.
//
// Returns ErrInvalidCredentials on any failed bind or zero search hits;
// ErrRealmUnavailable on dial/search transport failures.
func (r *LDAPRealm) Authenticate(ctx context.Context, creds Credentials) (*Principal, error) {
	if creds.Username == "" || creds.Password == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := r.cfg.Dialer.Dial(ctx, r.cfg.URL, r.cfg.SkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("%w: dial: %v", ErrRealmUnavailable, err)
	}
	defer conn.Close()

	if r.cfg.BindDN != "" {
		if err := conn.Bind(r.cfg.BindDN, r.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("%w: service bind: %v", ErrRealmUnavailable, err)
		}
	}

	filter := substituteUser(r.cfg.UserFilter, creds.Username)
	req := ldap.NewSearchRequest(
		r.cfg.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, // SizeLimit=2 → fast-fail on duplicates
		filter,
		[]string{"dn", r.cfg.UserNameAttr, r.cfg.UserMailAttr, r.cfg.UserGroupAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: user search: %v", ErrRealmUnavailable, err)
	}
	if len(res.Entries) == 0 {
		return nil, ErrInvalidCredentials
	}
	if len(res.Entries) > 1 {
		// Filter is too loose — refuse rather than guess.
		return nil, fmt.Errorf("%w: ambiguous user filter (%d results)", ErrInvalidCredentials, len(res.Entries))
	}
	entry := res.Entries[0]

	// Now actually verify the password by binding as the user.
	if err := conn.Bind(entry.DN, creds.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	groups := entry.GetAttributeValues(r.cfg.UserGroupAttr)
	if r.cfg.GroupBaseDN != "" {
		extra, gErr := r.searchGroups(conn, entry.DN)
		if gErr != nil {
			// Group-search failures are surfaced as ErrRealmUnavailable
			// rather than silently dropped — a sysadmin investigating a
			// permissions miss needs to see the LDAP error, not get a
			// successful login with mysteriously-empty groups.
			return nil, fmt.Errorf("%w: group search: %v", ErrRealmUnavailable, gErr)
		}
		groups = append(groups, extra...)
	}
	groups = normalizeGroups(groups, r.cfg.GroupNameAttr)

	p := &Principal{
		Subject: creds.Username, // we use the supplied username as the realm subject
		Realm:   r.Name(),
		Email:   firstAttr(entry, r.cfg.UserMailAttr),
		Name:    firstAttr(entry, r.cfg.UserNameAttr),
		Groups:  groups,
		Claims: map[string]string{
			"dn": entry.DN,
		},
	}
	return p, nil
}

// SyncGroups is a no-op — group memberships are pulled at login time.
func (r *LDAPRealm) SyncGroups(ctx context.Context) error { return nil }

func (r *LDAPRealm) searchGroups(conn LDAPConn, userDN string) ([]string, error) {
	filter := strings.ReplaceAll(r.cfg.GroupFilter, "%s", ldap.EscapeFilter(userDN))
	req := ldap.NewSearchRequest(
		r.cfg.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"dn", r.cfg.GroupNameAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if name := firstAttr(e, r.cfg.GroupNameAttr); name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

func substituteUser(filter, username string) string {
	esc := ldap.EscapeFilter(username)
	return strings.ReplaceAll(filter, "%s", esc)
}

// normalizeGroups extracts a friendly name from each group entry. AD's
// memberOf attribute returns full DNs ("CN=engineers,OU=Groups,DC=corp,DC=example");
// we strip to the leading "<attr>=name" component so role-bindings can use
// short names like "engineers".
func normalizeGroups(groups []string, attr string) []string {
	prefix := strings.ToLower(attr) + "="
	seen := map[string]bool{}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		short := g
		// If it looks like a DN, take the first RDN matching attr.
		if strings.Contains(g, ",") {
			parts := strings.SplitN(g, ",", 2)
			if strings.HasPrefix(strings.ToLower(parts[0]), prefix) {
				short = parts[0][len(prefix):]
			} else {
				short = parts[0]
			}
		}
		if !seen[short] {
			seen[short] = true
			out = append(out, short)
		}
	}
	return out
}

func firstAttr(e *ldap.Entry, attr string) string {
	v := e.GetAttributeValue(attr)
	return v
}

// realLDAPDialer is the production dialer using github.com/go-ldap/ldap/v3.
type realLDAPDialer struct{}

func (realLDAPDialer) Dial(ctx context.Context, url string, skipTLSVerify bool) (LDAPConn, error) {
	opts := []ldap.DialOpt{}
	if skipTLSVerify {
		opts = append(opts, ldap.DialWithTLSConfig(insecureTLS()))
	}
	conn, err := ldap.DialURL(url, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
