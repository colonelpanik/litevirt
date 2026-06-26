# Authentication & authorization

litevirt's auth model has two halves:

- **Authentication** asks "who are you?". A *realm* validates the
  credentials and returns a *Principal* (subject + groups).
- **Authorization** asks "may you do this?". A *path-based RBAC engine*
  evaluates role-bindings to grant or deny each operation.

Tokens, sessions, and 2FA all sit on top of these primitives.

## Realms

A realm is a pluggable authentication backend. Three are shipped:

| Realm | Name format | When to use |
|---|---|---|
| Local | `local` | Single-cluster, small team. Bcrypt passwords stored in the cluster DB. Always present. |
| OIDC | `oidc:<short-name>` | Federated SSO with corporate IdPs (Okta, Auth0, Keycloak, Azure AD, Google Workspace). Auth-code flow with PKCE. |
| LDAP / AD | `ldap:<short-name>` | On-prem Active Directory or OpenLDAP. Search-then-bind; group memberships pulled from `memberOf` (or a follow-up search). |

Realms are configured under `auth.realms:` in `/etc/litevirt/config.yaml`
— see `docs/configuration.md` for the YAML shape. The daemon refreshes
group caches from external realms every 5 minutes; the last error per
realm is exposed via the status RPC.

Roles map to *principal IDs*: `user:<subject>@<realm>` and
`group:<name>@<realm>`. Bind a role to a principal in the engine and the
caller gets the role's verbs at the binding's path.

## Path-based RBAC

Resources live under a tree:

```
/
├── hosts/<host-name>
├── projects/<project>
│   └── vms/<vm-name>
├── storage/<pool>
└── sdn/zones/<zone>            (planned)
```

Project paths are live — projects ship as a tenancy bucket; see
`docs/tenancy.md` for `lv project create`, hierarchical names like
`/projects/acme/team-foo`, and quota admission.

A role is a list of *verb wildcards*:

- `*` — every verb
- `vm.*` — every verb in the `vm` namespace (`vm.start`, `vm.read`, …)
- `*.read` — read on every namespace
- `vm.start` — exact verb

Built-in roles (seeded by `auth.SeedBuiltinRoles`):

| Role | Verbs |
|---|---|
| Admin | `*` |
| Operator | `vm.*`, `ct.*`, `network.{read,create,delete}`, `lb.*`, `image.{read,pull,import,push,build}`, `backup.*`, `snapshot.*`, `sg.read`, `audit.read`, `host.read`, `storage.pool.{read,write}`, `storage.content.{read,write}`, `resourcemap.{read,write}` |
| VMOperator | `vm.{start,stop,restart,console,read,exec}` |
| Viewer | `*.read` |
| Auditor | `*.read`, `audit.export` |
| BackupOperator | `backup.*`, `snapshot.*`, `vm.read` |
| NetworkAdmin | `network.*`, `lb.*`, `sg.*` |
| NoAccess | (none) |

A *binding* attaches a role to a principal at a path. With
`--propagate` the binding applies to that path and all descendants —
this is how the `Admin` role on `/` grants cluster-wide superuser
access.

### Cluster-global vs project-scoped verbs

Some resources are cluster-global, not project-scoped, and their RPCs are
checked at the root path `/` — so a token whose scope is limited to a project
(e.g. `/projects/acme`) cannot reach them, while an operator with a `/`-rooted
binding can:

- **Images** are a shared base-image library: `image.{pull,import,push,build}`
  are checked at `/`. (Override with project-scoped image namespaces if needed.)
- **Storage pools** (`storage.pool.*`) configure host mounts/sources — real infra
  authority; create/delete/update are checked at `/`. **Pool contents**
  (`storage.content.*`, file upload/list/delete) are checked at the pool path
  `/storage/pools/<name>`.
- **Networks** (`network.create`, `network.delete`) and **resource mappings**
  (`resourcemap.*`, PCI/device pools) are cluster-global, checked at `/`.

Interactive guest access — **console, VNC, and SPICE** — requires `vm.console`
on the specific VM's project path (`/projects/<project>/vms/<name>`), not just a
broad operator role.

```bash
lv role grant Admin    group:admin@local        --path /                --propagate
lv role grant Operator group:eng@oidc:corp      --path /projects/acme   --propagate
lv role grant Viewer   group:contractors@ldap:corp --path /projects/acme
```

`lv role ls` lists bindings (admins see all; non-admins see their own
only — server-side filtered). `lv role revoke <binding-id>` soft-deletes
a row by id.

## Sessions

`Login` mints an opaque session id (32 random bytes hex-encoded, prefixed
with `lvs_` on the wire so the auth interceptor distinguishes them from
API tokens). The session is stored in the cluster's `sessions`
table with three lifecycle markers:

- **Hard expiry** — 7 days after issue. Cannot be extended.
- **Idle timeout** — 8 hours of inactivity. Each authenticated RPC
  touches `last_used_at`. Idle sessions are auto-revoked on the next
  request.
- **Revoke** — user-initiated (`lv logout`, `lv session revoke <id>`)
  or admin-initiated.

Both timeouts are configurable in the daemon config under
`auth.session_idle_timeout` and `auth.session_hard_expiry` (Go duration
strings, e.g. `8h`, `168h`); the defaults above apply when unset.

Why not JWT? JWTs cannot be revoked before their `exp`. Real-world
incidents (lost laptop, leaked CI token) demand immediate kill. The
sessions table is small (one row per active login) and reads are an
indexed primary-key lookup, so the cost is in noise.

`lv session ls` shows your active sessions; `--user <name>` lists
another user's (admin only).

## API tokens

API tokens are long-lived bearer credentials for automation. They are
distinct from sessions:

- Stored as bcrypt(token) — verifiable but not recoverable.
- No idle timeout; an explicit `expires` (RFC3339) is the only bound.
- May carry **scope paths** that further restrict what the token can do.

```bash
lv user token-create alice ci-runner --expires 2026-12-31T00:00:00Z
lv user token-create alice deploy-acme \
    --scope-path /projects/acme \
    --scope-path /storage/main
```

A scoped token's effective permissions are
`intersection(user's role bindings, token scopes)`. Even if the bound
user is `Admin`, a token scoped to `/projects/acme` cannot touch
`/projects/other`.

## Two-factor authentication

Two factors are shipped:

- **TOTP** (RFC 6238 SHA-1 / 6 digits / 30s period) — works in the CLI
  and any authenticator app. Enroll with `lv 2fa enroll-totp`.
- **WebAuthn** (FIDO2 / passkeys) — browser-only because the protocol
  requires a resident authenticator. Enroll at `/account/2fa` in the
  web UI (requires `webauthn:` daemon config — see
  `docs/configuration.md`).

To enroll TOTP:

```bash
lv 2fa enroll-totp --label phone
```

The command prints:

- An `otpauth://` provisioning URL (paste into Google Authenticator /
  Authy / 1Password / etc., or render a QR in the UI).
- The base32 secret for manual entry.
- 10 single-use recovery codes — *save them now*; they are not stored
  in plaintext and cannot be re-shown.

After enrollment, `lv login` runs in two stages: it accepts the password,
the server returns `Requires_2Fa=true` with no token, and the CLI prompts
for the second factor. Recovery codes work in the same prompt — each
code is consumed on use.

For WebAuthn enrollment, open `/account/2fa` in the UI and click
"Register security key". The browser drives `navigator.credentials.create`
against the daemon; the resulting credential lands in the same
`user_2fa` table TOTP uses.

To disable a factor: `lv 2fa disable --method totp --label phone`.

## Migration from the legacy admin/operator/viewer roles

litevirt 0.x had a flat `admin > operator > viewer` ladder stored on
`users.role`. The new engine respects existing rows for backward
compatibility:

- Each legacy role appears as a synthetic group `group:<role>@local`.
- `RequirePerm` falls back to the legacy ladder ONLY when the engine
  has no bindings at all for the caller's principal set.
- One root binding migrates an entire team at once:

  ```bash
  lv role grant Admin    group:admin@local    --path / --propagate
  lv role grant Operator group:operator@local --path / --propagate
  lv role grant Viewer   group:viewer@local   --path / --propagate
  ```

Once those bindings exist, the legacy fallback never fires; the engine
is the only authority.

## Wire format quick reference

| Bearer prefix | Lookup table | Rejected on |
|---|---|---|
| `lvs_<hex>` | `sessions` | revoked, hard-expired, idle-timeout |
| `<hex>` (no prefix) | `tokens` (bcrypt match) | `deleted_at`, `expires_at` |
| (no Authorization header) | mTLS client cert | invalid/expired peer cert |

mTLS callers are treated as `admin` because only the cluster's PKI can
issue valid client certs.
