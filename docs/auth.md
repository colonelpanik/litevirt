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

### OIDC realm keys

Under `auth.realms[].oidc:`. `issuer_url`, `client_id`, and `redirect_url` are
required; prefer `client_secret_file` (checked for 0600 at load) over inlining
`client_secret`.

| Key | Purpose |
|---|---|
| `scopes` | Extra scopes to request beyond the defaults. |
| `groups_claim` | Token claim carrying group membership; each value becomes a `group:<name>@<realm>` principal. |
| `subject_claim` | Claim used as the stable subject — the `user:<subject>@<realm>` principal. Override when `sub` is an opaque id and you want a readable, stable alternative. |
| `email_claim` | Claim read as the user's email address. |
| `name_claim` | Claim read as the user's display name. |

The claim overrides exist because IdPs disagree on claim names. Changing
`subject_claim` on a live realm re-keys every principal id, so existing role
bindings stop matching — rebind before switching it.

### LDAP / AD realm keys

Under `auth.realms[].ldap:`. `url` and `user_base_dn` are required; prefer
`bind_password_file` over inlining `bind_password`.

| Key | Purpose |
|---|---|
| `user_filter` | LDAP filter selecting user entries (e.g. `(objectClass=person)`). |
| `group_base_dn` | Subtree searched for groups. |
| `group_filter` | LDAP filter selecting group entries. |
| `user_name_attr` | Attribute read as the login/subject name. |
| `user_mail_attr` | Attribute read as the email address. |
| `user_group_attr` | Attribute on the user entry listing group membership (typically `memberOf`). |
| `group_name_attr` | Attribute on a group entry holding its name. |
| `skip_tls_verify` | Disables certificate verification on the LDAPS connection. **Leave off outside a lab** — it makes directory traffic, including bind credentials, trivially interceptable. |

As with OIDC, changing `user_name_attr` or `group_name_attr` re-keys principal
ids and invalidates existing role bindings.

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

`--allow-overcommit` (CreateVM/StartVM/UpdateVM) additionally requires
`vm.overcommit`: bypassing the host capacity check is an operator-level
judgment call, so a binding granting only lifecycle verbs (e.g. VMOperator)
cannot invoke it. Wildcard grants (`vm.*`, `*`) carry it; clusters on the
legacy role model (no bindings) are unchanged — any operator may pass it.

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
- **Storage pools** (`storage.pool.*`, configure host mounts/sources) and their
  **contents** (`storage.content.*`, file upload/list/delete) are both checked at the
  pool's project path via `poolRBACPathFor`: `/storage_pools/<name>` for a global pool
  (top-level — effectively a root/global grant, matching their real-infra authority),
  `/projects/<p>/storage_pools/<name>` for a project-owned one. Intra-cluster content
  calls (an entry-node forward, cross-host replication, auto-promote) authenticate as a
  cluster host cert and bypass this tenant check — a deliberate peer-trust boundary:
  any known cluster host cert can reach pool contents via these RPCs.
- **Networks** (`network.create`, `network.delete`) and **resource mappings**
  (`resourcemap.*`, PCI/device pools) are cluster-global, checked at `/`.

> **Upgrade note (content RBAC):** storage-pool content ops moved off the legacy flat
> path `/storage/pools/<name>` onto the project-scoped path above. Re-issue any explicit
> `storage.content.*` grant on the old path (admin / role-floor grants are unaffected).
> The check runs on the **entry** node a user authenticates to, so the isolation takes
> effect once those nodes are upgraded — an un-upgraded entry node still uses the old path.

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

Grants and revokes take effect **immediately**, without a daemon restart: a
grant reloads the engine synchronously, a revoke applies as an in-memory delta
(so it holds even if a subsequent reload fails, while the row tombstone keeps a
later reload from resurrecting it), and a ~30s backstop reload picks up bindings
mutated on a **peer** — the effective bound on a peer-side change is one
successful reload interval after it becomes locally visible. Deleting a user
tombstones that user's role bindings in the same transaction, so a deleted
account cannot retain access through a lingering binding.

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
| (no Authorization header) | mTLS client cert → classified (see below) | invalid/expired peer cert |

## mTLS principal model

A bearerless mTLS caller (no `Authorization` bearer) is classified by its
certificate, not blanket-trusted as `admin`:

| kind | condition | authority |
|---|---|---|
| **local-root** | connection is loopback **and** the cert CN is a trusted cluster host | `admin` (on-node root — running `lv` on a node is already root-equivalent) |
| **peer** | non-loopback **and** the cert CN is a trusted cluster host | `admin` (a trusted cluster node: peer RPCs + relaying an already-authorized user forward) |
| **client** | any other cert — the distributable CLI client cert, an unknown/empty CN, or a **removed** host's CN | must present a session bearer (`lv login`); denied once strict mode is enforced |

A bearer, when present, always wins and yields the real user (role/scope).

"Trusted cluster host" is decided from the `hosts` row, and the three cases are
distinct:

- a **tombstoned** row (a removed host) is refused outright;
- a **live** row is trusted, in any operational state — draining, fenced,
  upgrading and maintenance all stay trusted, because a recovering node needs its
  own rejoin RPCs accepted. The removal boundary is `deleted_at`, not state;
- **no row at all** falls back to the certificate, and is trusted only if it
  carries `ServerAuth`. That is what `lv host init`/`lv host add` issue for a host
  and what the distributable `lv-cli` certificate deliberately does not, so the CLI
  cert is never a peer.

That last case exists because hosts learn about each other by replication, and
replication is what this gates: requiring a live row meant a freshly provisioned
cluster — where every node holds only its own row — could never converge. An
unreadable row is **not** the same as an absent one and is refused, because an
error cannot rule out a removal.

**Removing a host revokes its certificate.** `lv host rm` appends the host's
certificate serial to the cluster CRL, so removal does not rest solely on the
tombstone reaching every node. It needs the CA private key, so run it from the
machine that ran `lv host init`; if it cannot, the command says so rather than
skipping revocation silently.

The CRL is then **replicated**, not copied around by hand. `lv host rm` publishes
it to the cluster, every node installs it within about half a minute, and each
daemon reloads `crl.pem` when the file changes. Two things make that safe to send
over a channel any peer can write to: a CRL is signed by the cluster CA, and every
node verifies that signature against its own `ca.crt` before the file is touched —
so a host publishing a CRL that omits its own serial is refused rather than
believed. Nodes install only a CRL numbered above the one they hold, and the table
is append-only and keyed by that number, so an unsignable row cannot displace or
bury a genuine one. `lv health` warns for as long as any peer's CRL version
is behind another's.

If publishing fails — the cluster was unreachable, the daemon was restarting — the
certificate is still revoked locally and only locally. Run `lv host publish-crl`
from that machine once the cluster is back. Re-running `lv host rm` does **not**
work: the host row is already tombstoned, so the command has no serial to look up
and stops before the publish step.

Distribution deliberately does **not** go over SSH. SSH is the bootstrap channel —
`host init`, `host add`, `rotate-audit-key` — for reaching a machine that is not
yet a cluster member. A revocation goes to nodes that are already mutually
authenticated peers with a replicated store built for exactly this, where an SSH
fan-out would be best-effort with a list of hosts it failed to reach.

**Threat model.** The daemon runs as root against the local libvirt socket and a
replicated state DB, so root on a node is already full local + cluster power —
RBAC does not (and cannot) constrain it, and a host cert is a legitimately
root-obtained *node* identity. What this model closes is that a **distributable**
credential (the shared CLI client cert) no longer equals admin: hand someone CLI
reach and they still need to `lv login` to act.

### Enforcement (`auth.strict_mtls_identity`)

Denial of bearerless `client` certs is off by default and gated by both the
`auth.strict_mtls_identity` config flag **and** the `strict_mtls_identity_v1`
capability being active cluster-wide. The config flag is the enforcement switch
**and** kill switch (set it false to disable regardless of any latch), and the
loopback local-root path is never gated — so a mis-flip is reversible and can
never lock out an on-node operator. Because peer/forwarded traffic uses host
certs (which stay `admin`), enabling it changes **no** node-to-node behavior; the
only operator-visible change is that a **remote** CLI must `lv login` first
(on-node `lv` over loopback is unaffected).

**The token is advertised by this build; enforcement remains default-off.**
`strict_mtls_identity_v1` is in `capabilities.supported`, so deploying this build
lets the capability activate + latch cluster-wide — but that is behavior-neutral,
because enforcement is `auth.strict_mtls_identity` (default false) **AND** the
latch. Deploying does NOT change auth. HA-degraded does NOT fire for an
advertised-but-disabled token (degraded tracks configured-to-enforce, not merely
advertised). Enabling is a single config step: set `auth.strict_mtls_identity:
true` on every node; the HA monitor drives the latch while the cluster is healthy,
and the config flag stays the reversible kill switch (set it false + restart to
stand down, regardless of the latch marker). Validate on an ephemeral cluster
before enabling.

### Realm-aware role bindings (`auth.rbac_realm`)

Role bindings enforce against **realm-qualified** principals
(`user:<name>@<realm>`), so a legacy **bare** grant (`user:<name>`) never matches
and is inert. `auth.rbac_realm` opts a node into realm-aware grant grammar so it
stops minting new inert bindings. Like `auth.strict_mtls_identity`, it is gated by
the config flag **and** the `rbac_realm_v1` capability latched cluster-wide, and
the flag is the reversible kill switch (default false):

- **Flag off (default):** a bare grant is stored verbatim — legacy behavior,
  mixed-version-safe.
- **Flag on, not yet latched:** a bare `user:<name>` grant is **rejected**
  (`FailedPrecondition`) — specify an explicit realm. This is the safe
  pre-uniformity state: while any peer might still mint bare bindings, we refuse
  rather than canonicalize.
- **Flag on and latched fleet-wide:** a bare grant for a **known local user** is
  **resolved** to `user:<name>@local` and stored canonically; one that names no
  known local user is rejected (spell out the realm).

The grammar treats a principal as realm-qualified only when the part after the
last `@` names a realm (`local`, `oidc:*`, `ldap:*`) — so `user:alice@example.com`
is a bare username (an email), while `user:alice@oidc:corp` is realm-qualified.

Existing bare bindings created before enabling this remain **inert** (they never
granted access) until rewritten. Once the capability has latched fleet-wide, run
the one-time idempotent migration `lv role normalize` (supports `--dry-run`) to
rewrite resolvable legacy bare rows to canonical form; a bare binding whose realm
can't be resolved is left in place and reported as skipped. External OIDC/LDAP
**group** bindings are not yet enforced (group claims are not session-persisted).

### Forwarded identity (`auth.forwarded_identity`)

Cross-node requests are authorized on the **entry** node against the real user,
then forwarded to the owning node. The entry node relays the user's bearer to the
owner in `x-litevirt-fwd-bearer` (send-side is always on and ignored by nodes
that don't enforce it). When `auth.forwarded_identity` + the
`forwarded_identity_v1` capability are active, the owner re-authenticates that
bearer and runs RBAC + audit as the **real user** instead of `admin`; a forward
with no bearer (a background/system continuation — failover, reconcilers,
rebalancer, LB refresh, self-upgrade, replication) stays `admin` and audits as
`system`. Owner-side validation is fail-closed and never falls back to admin: a
session/user not yet replicated to the owner returns a **retryable** `Unavailable`
("forwarded identity not yet visible on owner; retry"), an
expired/revoked/malformed bearer returns `Unauthenticated`, and a resolvable user
that RBAC denies returns `PermissionDenied` — so an action taken immediately after
login or a role grant may briefly need a retry until replication catches up. The
forwarded bearer is only honored from a **peer** principal; a client cannot inject
it to impersonate a user.

> Peer-only RPC set (for a future flip that would stop accepting host certs on
> user-facing RPCs entirely): the replication/anti-entropy lane
> (`PushMutations`/`AckMutations`/state digest+dump/sensitive dumps), backup/
> restore transfer (`HasChunks`/`PushBackup`), failover probes
> (`CheckVMRuntime`/`CheckContainerRuntime`/`CheckVIPParticipant`/`CheckLBPresent`),
> `FetchBinary`, `GetVMIPRemote`, proof-bearing `PromoteReplica`/`ApplyLB`, and the
> peer-gated `ProvisionNetwork`/`SyncVTEP`/`UpdateFDB`/`RefreshLB`/
> `PushReplicaIncrement`. Not enforced today.
