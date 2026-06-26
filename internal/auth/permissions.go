package auth

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Path canonicalization. Paths in litevirt RBAC look like:
//
//	/                              cluster root
//	/hosts                         all hosts
//	/hosts/host-a                  one host
//	/projects/acme                 a project
//	/projects/acme/vms/web-1       a single VM
//	/storage/main                  a storage pool
//	/sdn/zones/prod                an SDN zone
//
// Trailing slashes are stripped; case is preserved (Linux conventions).
// Empty string and "/" both refer to the cluster root.
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	// Strip trailing "/" for any path other than the root itself.
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return p
}

// pathPrefixOf reports whether `prefix` is an ancestor of (or equal to)
// `path`. Used by propagation: a binding on /projects/acme with
// propagate=true applies to /projects/acme/vms/web-1.
//
// "/foo/bar" is a prefix of "/foo/bar/baz" but NOT of "/foo/barred".
func pathPrefixOf(prefix, path string) bool {
	prefix = canonicalPath(prefix)
	path = canonicalPath(path)
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

// verbMatches reports whether a role's grant matches the requested verb.
// Granted verbs may be exact ("vm.start") or wildcarded:
//
//	"*"          — every verb
//	"vm.*"       — every verb in the vm namespace (vm.start, vm.read, …)
//	"*.read"     — read on every namespace (vm.read, lb.read, …)
//	"vm.start"   — only vm.start
//
// We explicitly do NOT support arbitrary glob (e.g. "v*.read") to keep the
// matcher fast and the security review surface small.
func verbMatches(grants []string, verb string) bool {
	for _, g := range grants {
		if g == "*" {
			return true
		}
		if g == verb {
			return true
		}
		// "<ns>.*" — namespace-wildcard.
		if strings.HasSuffix(g, ".*") && !strings.HasPrefix(g, "*") {
			ns := g[:len(g)-2]
			if strings.HasPrefix(verb, ns+".") {
				return true
			}
		}
		// "*.<verb>" — verb-wildcard across namespaces.
		if strings.HasPrefix(g, "*.") && !strings.HasSuffix(g, ".*") {
			suffix := g[1:] // "*.read" → ".read"
			if strings.HasSuffix(verb, suffix) {
				return true
			}
		}
	}
	return false
}

// engineSnapshot is the atomic unit of Engine state. We swap the entire
// snapshot on Reload so readers never see a torn (half-updated) view of
// roleVerbs vs bindings.
type engineSnapshot struct {
	roleVerbs map[string][]string
	bindings  []corrosion.RoleBindingRecord
}

// Engine resolves "may principal P perform verb V on path R?". One per
// daemon. Keeps an in-memory snapshot of role definitions + bindings,
// refreshed on every Reload() (called whenever role/binding tables mutate).
//
// The snapshot is held in an atomic.Pointer so concurrent reads (every
// authenticated RPC consults Allowed/HasAnyBinding) never need to lock,
// and Reload's swap is atomic.
type Engine struct {
	db   *corrosion.Client
	snap atomic.Pointer[engineSnapshot]
}

// NewEngine returns an engine reading from db. Caller must call Reload()
// after registering built-in roles.
func NewEngine(db *corrosion.Client) *Engine {
	e := &Engine{db: db}
	e.snap.Store(&engineSnapshot{roleVerbs: map[string][]string{}})
	return e
}

// Reload re-reads the roles and role_bindings tables. Cheap (ms on
// thousand-binding clusters) so it's safe to call after every mutation
// and on a periodic refresh.
func (e *Engine) Reload(ctx context.Context) error {
	roles, err := corrosion.ListRoles(ctx, e.db)
	if err != nil {
		return err
	}
	rv := make(map[string][]string, len(roles))
	for _, r := range roles {
		rv[r.Name] = r.Verbs
	}
	bindings, err := corrosion.ListRoleBindings(ctx, e.db)
	if err != nil {
		return err
	}
	e.snap.Store(&engineSnapshot{roleVerbs: rv, bindings: bindings})
	return nil
}

// Allowed reports whether a principal (and their groups) hold a binding
// that grants `verb` at `path`. Bindings with `propagate=true` apply to
// the path and all descendants; bindings with `propagate=false` apply
// only to the exact path.
//
// principalIDs should include the user-principal AND any group-principals
// (e.g. ["user:alice@local", "group:admins@local"]).
//
// Cluster-root bindings (path = "/") with propagate=true grant on every
// path — this is how the built-in Admin role works (one root binding
// gives full access).
func (e *Engine) Allowed(principalIDs []string, verb, path string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	path = canonicalPath(path)
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if !pSet[b.Principal] {
			continue
		}
		bp := canonicalPath(b.Path)
		if b.Propagate {
			if !pathPrefixOf(bp, path) {
				continue
			}
		} else {
			if bp != path {
				continue
			}
		}
		grants := snap.roleVerbs[b.Role]
		if len(grants) == 0 {
			continue
		}
		if verbMatches(grants, verb) {
			return true
		}
	}
	return false
}

// HasAnyBinding reports whether the engine has at least one binding for
// any of the given principals. Used by the transitional RequirePerm
// bridge to decide whether to fall back to legacy admin/operator/viewer.
func (e *Engine) HasAnyBinding(principalIDs []string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if pSet[b.Principal] {
			return true
		}
	}
	return false
}

// SeedBuiltinRoles installs (or refreshes) litevirt's standard roles. Idempotent.
func SeedBuiltinRoles(ctx context.Context, db *corrosion.Client) error {
	for _, r := range BuiltinRoles {
		rec := corrosion.RoleRecord{
			Name:        r.Name,
			Verbs:       r.Verbs,
			Description: r.Description,
			BuiltIn:     true,
		}
		if err := corrosion.InsertRole(ctx, db, rec); err != nil {
			return err
		}
	}
	return nil
}

// BuiltinRole is one of litevirt's pre-defined roles.
type BuiltinRole struct {
	Name        string
	Verbs       []string
	Description string
}

// BuiltinRoles is the list of roles seeded on every daemon start.
//
// Verb names are stable: an external automation (Terraform provider,
// scripts) may reference them. Wildcards collapse common cases.
var BuiltinRoles = []BuiltinRole{
	{
		Name:        "Admin",
		Verbs:       []string{"*"},
		Description: "Full access — every verb on every path. The cluster's superuser.",
	},
	{
		Name: "Operator",
		Verbs: []string{
			"vm.*", "ct.*",
			"network.read", "network.create", "network.delete",
			"lb.*",
			"image.read", "image.pull", "image.import", "image.push", "image.build",
			"backup.*",
			"snapshot.*",
			"sg.read",
			"audit.read",
			"host.read",
			"storage.pool.read", "storage.pool.write",
			"storage.content.read", "storage.content.write",
			"resourcemap.read", "resourcemap.write",
		},
		Description: "Day-to-day VM operations: create, start, stop, snapshot, backup, attach networks/LBs.",
	},
	{
		Name: "VMOperator",
		Verbs: []string{
			"vm.start", "vm.stop", "vm.restart",
			"vm.console", "vm.read", "vm.exec",
		},
		Description: "Restricted VM lifecycle: start/stop/console only. Cannot create or delete VMs.",
	},
	{
		Name:        "Auditor",
		Verbs:       []string{"*.read", "audit.export"},
		Description: "Read-only across all resources, plus audit-log export. Distinct from Viewer once audit becomes hash-chained; functionally equivalent to Viewer today.",
	},
	{
		Name:        "Viewer",
		Verbs:       []string{"*.read"},
		Description: "Read-only across all resources. Today this includes audit.read; will narrow this to non-audit reads.",
	},
	{
		Name: "BackupOperator",
		Verbs: []string{
			"backup.*",
			"snapshot.*",
			"vm.read",
		},
		Description: "Backup and snapshot operations only. Read-only on VMs.",
	},
	{
		Name: "NetworkAdmin",
		Verbs: []string{
			"network.*",
			"lb.*",
			"sg.*", // security groups
		},
		Description: "Networking and load balancing. No VM lifecycle access.",
	},
	{
		Name:        "NoAccess",
		Verbs:       []string{},
		Description: "Explicit deny-all. Useful for binding to revoked groups.",
	},
}
