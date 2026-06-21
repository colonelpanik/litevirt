package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// RealmConfig is one entry under `auth.realms:` in the daemon config.
// It is YAML-friendly and realm-kind-agnostic; per-kind fields are in
// the OIDC / LDAP nested structs and ignored when the kind doesn't
// match.
//
// Example:
//
//	auth:
//	  realms:
//	    - name: corp-okta
//	      kind: oidc
//	      oidc:
//	        issuer_url: https://corp.okta.com
//	        client_id: 0oa…
//	        client_secret_file: /etc/litevirt/okta-secret
//	        redirect_url: https://litevirt.corp/oidc/callback
//	    - name: corp-ad
//	      kind: ldap
//	      ldap:
//	        url: ldaps://ad.corp.example
//	        bind_dn: cn=svc-litevirt,ou=Users,dc=corp,dc=example
//	        bind_password_file: /etc/litevirt/ldap-secret
//	        user_base_dn: ou=Users,dc=corp,dc=example
//
// The "local" realm is always present and need not be listed.
type RealmConfig struct {
	// Name becomes the realm name suffix: "oidc:<name>" / "ldap:<name>"
	// (or just the user-supplied name for local).
	Name string `yaml:"name"`

	// Kind selects which constructor runs: "local" | "oidc" | "ldap".
	Kind string `yaml:"kind"`

	OIDC *OIDCRealmConfig `yaml:"oidc,omitempty"`
	LDAP *LDAPRealmConfig `yaml:"ldap,omitempty"`
}

// OIDCRealmConfig is the YAML view of OIDCConfig. ClientSecretFile is
// preferred over inlining the secret in config.yaml — the path's
// permissions are checked at load time (must be 0600).
type OIDCRealmConfig struct {
	IssuerURL          string   `yaml:"issuer_url"`
	ClientID           string   `yaml:"client_id"`
	ClientSecret       string   `yaml:"client_secret,omitempty"`
	ClientSecretFile   string   `yaml:"client_secret_file,omitempty"`
	RedirectURL        string   `yaml:"redirect_url"`
	Scopes             []string `yaml:"scopes,omitempty"`
	GroupsClaim        string   `yaml:"groups_claim,omitempty"`
	EmailClaim         string   `yaml:"email_claim,omitempty"`
	NameClaim          string   `yaml:"name_claim,omitempty"`
	SubjectClaim       string   `yaml:"subject_claim,omitempty"`
}

// LDAPRealmConfig is the YAML view of LDAPConfig.
type LDAPRealmConfig struct {
	URL                string   `yaml:"url"`
	BindDN             string   `yaml:"bind_dn,omitempty"`
	BindPassword       string   `yaml:"bind_password,omitempty"`
	BindPasswordFile   string   `yaml:"bind_password_file,omitempty"`
	UserBaseDN         string   `yaml:"user_base_dn"`
	UserFilter         string   `yaml:"user_filter,omitempty"`
	GroupBaseDN        string   `yaml:"group_base_dn,omitempty"`
	GroupFilter        string   `yaml:"group_filter,omitempty"`
	UserNameAttr       string   `yaml:"user_name_attr,omitempty"`
	UserMailAttr       string   `yaml:"user_mail_attr,omitempty"`
	UserGroupAttr      string   `yaml:"user_group_attr,omitempty"`
	GroupNameAttr      string   `yaml:"group_name_attr,omitempty"`
	SkipTLSVerify      bool     `yaml:"skip_tls_verify,omitempty"`
}

// BuildRegistry constructs a Registry from a list of RealmConfigs and
// always-installs the "local" realm. Errors on the first config that
// fails to construct so the operator gets a clean signal at startup.
//
// The local DB is required because LocalRealm authenticates against it.
// `ctx` is forwarded to OIDC discovery (which makes a network call).
func BuildRegistry(ctx context.Context, db *corrosion.Client, configs []RealmConfig) (*Registry, error) {
	reg := NewRegistry()
	reg.Register(NewLocalRealm(db))
	for i, rc := range configs {
		switch rc.Kind {
		case "", "local":
			// "local" is auto-registered; an explicit entry is a no-op.
			// We tolerate it so operators can document the local realm
			// in config.yaml alongside the others.
			continue
		case "oidc":
			if rc.OIDC == nil {
				return nil, fmt.Errorf("realms[%d] %q: kind=oidc requires an oidc: block", i, rc.Name)
			}
			cfg := OIDCConfig{
				ShortName:    rc.Name,
				IssuerURL:    rc.OIDC.IssuerURL,
				ClientID:     rc.OIDC.ClientID,
				ClientSecret: rc.OIDC.ClientSecret,
				RedirectURL:  rc.OIDC.RedirectURL,
				Scopes:       rc.OIDC.Scopes,
				GroupsClaim:  rc.OIDC.GroupsClaim,
				EmailClaim:   rc.OIDC.EmailClaim,
				NameClaim:    rc.OIDC.NameClaim,
				SubjectClaim: rc.OIDC.SubjectClaim,
			}
			if rc.OIDC.ClientSecretFile != "" {
				secret, err := readSecretFile(rc.OIDC.ClientSecretFile)
				if err != nil {
					return nil, fmt.Errorf("realms[%d] %q: client_secret_file: %w", i, rc.Name, err)
				}
				cfg.ClientSecret = secret
			}
			realm, err := NewOIDCRealm(ctx, cfg)
			if err != nil {
				return nil, fmt.Errorf("realms[%d] %q (oidc): %w", i, rc.Name, err)
			}
			reg.Register(realm)
		case "ldap":
			if rc.LDAP == nil {
				return nil, fmt.Errorf("realms[%d] %q: kind=ldap requires an ldap: block", i, rc.Name)
			}
			cfg := LDAPConfig{
				ShortName:     rc.Name,
				URL:           rc.LDAP.URL,
				BindDN:        rc.LDAP.BindDN,
				BindPassword:  rc.LDAP.BindPassword,
				UserBaseDN:    rc.LDAP.UserBaseDN,
				UserFilter:    rc.LDAP.UserFilter,
				GroupBaseDN:   rc.LDAP.GroupBaseDN,
				GroupFilter:   rc.LDAP.GroupFilter,
				UserNameAttr:  rc.LDAP.UserNameAttr,
				UserMailAttr:  rc.LDAP.UserMailAttr,
				UserGroupAttr: rc.LDAP.UserGroupAttr,
				GroupNameAttr: rc.LDAP.GroupNameAttr,
				SkipTLSVerify: rc.LDAP.SkipTLSVerify,
			}
			if rc.LDAP.BindPasswordFile != "" {
				secret, err := readSecretFile(rc.LDAP.BindPasswordFile)
				if err != nil {
					return nil, fmt.Errorf("realms[%d] %q: bind_password_file: %w", i, rc.Name, err)
				}
				cfg.BindPassword = secret
			}
			realm, err := NewLDAPRealm(cfg)
			if err != nil {
				return nil, fmt.Errorf("realms[%d] %q (ldap): %w", i, rc.Name, err)
			}
			reg.Register(realm)
		default:
			return nil, fmt.Errorf("realms[%d] %q: unknown kind %q (want local|oidc|ldap)", i, rc.Name, rc.Kind)
		}
	}
	return reg, nil
}

// readSecretFile reads a credentials file, requiring 0600 permissions
// to keep secrets off shared filesystems with lax umasks.
func readSecretFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("%s must not be group/other-readable", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Trim trailing whitespace so users can `echo > file` without surprises.
	end := len(data)
	for end > 0 && isSpaceByte(data[end-1]) {
		end--
	}
	return string(data[:end]), nil
}

func isSpaceByte(b byte) bool { return b == '\n' || b == '\r' || b == ' ' || b == '\t' }
