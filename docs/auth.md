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
| **local-root** | connection is loopback **and** the cert CN is a live cluster host | `admin` (on-node root — running `lv` on a node is already root-equivalent) |
| **peer** | non-loopback **and** the cert CN is a live cluster host | `admin` (a trusted cluster node: peer RPCs + relaying an already-authorized user forward) |
| **client** | any other cert — the distributable CLI client cert, an unknown/empty CN, or a **removed** host's CN | must present a session bearer (`lv login`); denied once strict mode is enforced |

A bearer, when present, always wins and yields the real user (role/scope).
"Live cluster host" means a non-removed `hosts` row — a decommissioned node's
still-CA-valid cert is no longer trusted.

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

**The token ships DARK** — it is in the capability registry but NOT advertised
(`capabilities.all`, not `supported`), so merging/deploying this build is fully
inert: nothing activates and there is no HA-degraded during the rollout. Flipping
is a deliberate two-step: **(1)** ship a release that adds `strict_mtls_identity_v1`
to `capabilities.supported` and roll it fleet-wide (nodes then advertise it; the
capability activates + latches once all do — and a transient
`ha_degraded{unsupported_member}` is expected during that window until every node
is upgraded), then **(2)** set `auth.strict_mtls_identity: true` on every node.
Enforcement needs both; validate on an ephemeral cluster before either step.

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
