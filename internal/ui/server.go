// Package ui serves the litevirt web dashboard on port 7445.
// Uses HTMX + Go templates — no JS framework, no build step.
package ui

import (
	"bytes"
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// migrateState tracks the progress of an in-flight migration for UI polling.
type migrateState struct {
	Phase      string
	Status     string
	DiskPct    float32
	MemoryPct  float32
	Error      string
	Done       bool
	TargetHost string
}

// Server is the web UI HTTP server.
type Server struct {
	grpc       pb.LiteVirtClient
	base       *template.Template // base.html + shared partials
	funcMap    template.FuncMap
	cluster    string
	migrations sync.Map // vmName → *migrateState
	backupOps  sync.Map // opID → *backupOpState (snapshot / restore / restore-live)
	statsRings sync.Map // "host:<name>" or "vm:<name>" → *StatsRing

	// db is a host-local Corrosion handle for read-only pages that
	// would otherwise require a new gRPC RPC for trivial reads
	// (e.g. /security-groups). Optional — nil = those pages render
	// an "unavailable on this build" empty state.
	db *corrosion.Client

	// backupRepos maps logical name → on-disk path, sourced from
	// daemon config `backup_repos:`. /backups iterates this map when
	// the caller doesn't pin a single repo via ?repo=. Empty map
	// means "no preconfigured repos" — UI degrades to the manual
	// query-param path.
	backupRepos map[string]string

	// wsOriginPatterns is the WebSocket Origin allowlist for the VNC /
	// console upgrades (host patterns, e.g. "vnc.example.com", "*.corp").
	// Empty (the default) enforces strict same-origin — the secure default
	// that still lets the UI reach its own WebSockets. Operators set it
	// (ui_allowed_origins) only when the UI is served behind a proxy on a
	// different host than the browser's Origin. (F5)
	wsOriginPatterns []string

	// tlsConfig, when set (ACME enabled, #13), makes ListenAndServe terminate
	// TLS itself. Nil = plain HTTP (default; e.g. behind a fronting proxy).
	tlsConfig *tls.Config
}

// SetTLSConfig enables TLS termination on the UI listener (ACME, #13).
func (s *Server) SetTLSConfig(c *tls.Config) { s.tlsConfig = c }

// SetWSOriginPatterns sets the WebSocket Origin allowlist. Nil/empty keeps the
// strict same-origin default.
func (s *Server) SetWSOriginPatterns(patterns []string) { s.wsOriginPatterns = patterns }

// SetCorrosionDB attaches a host-local Corrosion handle so the UI's
// read-only pages can query cluster state without a gRPC round-trip.
func (s *Server) SetCorrosionDB(db *corrosion.Client) { s.db = db }

// SetBackupRepos hands the UI server its view of the daemon's configured
// `backup_repos:` map so /backups can list them without query-string
// nudging. Pass the daemon's live map directly — the UI does not mutate.
func (s *Server) SetBackupRepos(repos map[string]string) { s.backupRepos = repos }

// NewServer creates a UI server backed by the given gRPC client.
func NewServer(client pb.LiteVirtClient, clusterName string) (*Server, error) {
	funcMap := template.FuncMap{
		"vmStateBadge":   vmStateBadge,
		"hostStateBadge": hostStateBadge,
		"firstIP":        firstIP,
		"vmActions":      vmActions,
		"memGiB":         func(mib int32) int32 { return mib / 1024 },
		"formatBytes":    formatBytes,
		"json":           jsonHelper,
		"truncate":       truncateHelper,
		"formatPct":      func(v float64) string { return fmt.Sprintf("%.1f", v) },
		"bytesToMiB":     func(b int64) int64 { return b / (1024 * 1024) },
		"memPctOf": func(used, total int64) float64 {
			if total == 0 {
				return 0
			}
			return float64(used) / float64(total) * 100
		},
		"poolPct": func(used, total int64) int {
			if total == 0 {
				return 0
			}
			return int(used * 100 / total)
		},
		"driverBadge": driverBadge,
		"icon":        iconHelper,
		"relTime":     relTimeHelper,
		"humanCron":   humanCronHelper,
		"meterClass":  meterClassHelper,
		"pct":         pctHelper,
		"dict":        dictHelper,
		"hasPrefix":   strings.HasPrefix,
	}

	// Parse base.html and shared partials (but NOT page templates — those are
	// cloned per-render). Partials live in templates/partials/ as {{define}}-only
	// files so every renderPage/renderPartial clone can reference them; the
	// {{define}} names must stay globally unique across all page templates.
	base, err := template.New("").Funcs(funcMap).ParseFS(templateFS,
		"templates/base.html", "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse base template: %w", err)
	}

	return &Server{grpc: client, base: base, funcMap: funcMap, cluster: clusterName}, nil
}

// renderPage renders a full page by cloning base.html and parsing the page
// template. Rendered into a buffer first so a mid-execute error (e.g. a nil
// field access in a template) can't emit a half-written page.
func (s *Server) renderPage(w http.ResponseWriter, pageTmpl string, data map[string]any) {
	t, err := s.base.Clone()
	if err == nil {
		t, err = t.ParseFS(templateFS, "templates/"+pageTmpl)
	}
	var buf bytes.Buffer
	if err == nil {
		err = t.ExecuteTemplate(&buf, "base.html", data)
	}
	if err != nil {
		slog.Error("render page", "template", pageTmpl, "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// renderPartial renders a named partial template (for HTMX responses). Buffered
// so a render failure swaps in a visible error rather than a blank region.
func (s *Server) renderPartial(w http.ResponseWriter, pageTmpl, partialName string, data any) {
	t, err := s.base.Clone()
	if err == nil {
		t, err = t.ParseFS(templateFS, "templates/"+pageTmpl)
	}
	var buf bytes.Buffer
	if err == nil {
		err = t.ExecuteTemplate(&buf, partialName, data)
	}
	if err != nil {
		slog.Error("render partial", "template", pageTmpl, "name", partialName, "error", err)
		writeRenderError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// renderFragment renders a standalone template file (e.g., modals) that don't
// need base.html. Buffered so a failed modal shows an error instead of silently
// not opening.
func (s *Server) renderFragment(w http.ResponseWriter, tmplFile string, data any) {
	t, err := template.New("").Funcs(s.funcMap).ParseFS(templateFS, "templates/"+tmplFile)
	var buf bytes.Buffer
	if err == nil {
		err = t.ExecuteTemplate(&buf, tmplFile, data)
	}
	if err != nil {
		slog.Error("render fragment", "template", tmplFile, "error", err)
		writeRenderError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// writeRenderError emits a small visible error for a failed HTMX swap. Returns
// 200 so htmx swaps it into the target (htmx skips the swap on non-2xx), making
// the failure visible instead of leaving a blank region.
func writeRenderError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<div class="error" style="margin:8px 0">Something went wrong rendering this view — check the server logs.</div>`))
}

// Handler returns the HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static files (public) — wrap to ensure JS files get correct MIME type
	// (embed.FS + FileServerFS can misdetect.js as text/plain on some systems).
	staticHandler := http.FileServerFS(staticFS)
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		}
		staticHandler.ServeHTTP(w, r)
	})

	// Auth routes (public)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Pages (require auth)
	mux.HandleFunc("GET /", s.requireAuthFunc(s.handleCluster))
	mux.HandleFunc("GET /hosts", s.requireAuthFunc(s.handleHosts))
	mux.HandleFunc("GET /hosts/{name}", s.requireAuthFunc(s.handleHostDetail))
	mux.HandleFunc("GET /vms", s.requireAuthFunc(s.handleVMs))
	mux.HandleFunc("GET /vms/{name}", s.requireAuthFunc(s.handleVMDetail))
	mux.HandleFunc("GET /stacks", s.requireAuthFunc(s.handleStacks))
	mux.HandleFunc("GET /stacks/{name}", s.requireAuthFunc(s.handleStackDetail))
	mux.HandleFunc("GET /networks", s.requireAuthFunc(s.handleNetworks))
	mux.HandleFunc("GET /lb", s.requireAuthFunc(s.handleLB))
	mux.HandleFunc("GET /lb/{name}", s.requireAuthFunc(s.handleLBDetail))
	mux.HandleFunc("POST /lb/{name}/delete", s.requireAuthFunc(s.handleLBDelete))
	mux.HandleFunc("POST /lb/{name}/drain", s.requireAuthFunc(s.handleLBDrain))
	mux.HandleFunc("GET /images", s.requireAuthFunc(s.handleImages))
	mux.HandleFunc("GET /events", s.requireAuthFunc(s.handleEvents))
	mux.HandleFunc("GET /activity", s.requireAuthFunc(s.handleActivity))
	mux.HandleFunc("GET /audit", s.requireAuthFunc(s.handleAudit))
	mux.HandleFunc("GET /storage", s.requireAuthFunc(s.handleStorage))
	mux.HandleFunc("GET /storage/ceph", s.requireAuthFunc(s.handleCephDashboard))
	mux.HandleFunc("GET /notifications", s.requireAuthFunc(s.handleNotifications))
	mux.HandleFunc("GET /ui/notifications/target-modal", s.requireAuthFunc(s.handleNotifyTargetModal))
	mux.HandleFunc("POST /ui/notifications/targets", s.requireAuthFunc(s.handleCreateNotifyTarget))
	mux.HandleFunc("DELETE /ui/notifications/targets/{id}", s.requireAuthFunc(s.handleDeleteNotifyTarget))
	mux.HandleFunc("POST /ui/notifications/targets/{id}/test", s.requireAuthFunc(s.handleTestNotifyTarget))
	mux.HandleFunc("GET /ui/notifications/route-modal", s.requireAuthFunc(s.handleNotifyRouteModal))
	mux.HandleFunc("POST /ui/notifications/routes", s.requireAuthFunc(s.handleCreateNotifyRoute))
	mux.HandleFunc("DELETE /ui/notifications/routes/{id}", s.requireAuthFunc(s.handleDeleteNotifyRoute))
	mux.HandleFunc("GET /resource-mappings", s.requireAuthFunc(s.handleResourceMappings))
	mux.HandleFunc("GET /ui/resource-mappings/create-modal", s.requireAuthFunc(s.handleMappingCreateModal))
	mux.HandleFunc("POST /ui/resource-mappings", s.requireAuthFunc(s.handleCreateMapping))
	mux.HandleFunc("DELETE /ui/resource-mappings/{name}", s.requireAuthFunc(s.handleDeleteMapping))
	mux.HandleFunc("GET /ui/resource-mappings/{name}/device-modal", s.requireAuthFunc(s.handleMappingDeviceModal))
	mux.HandleFunc("POST /ui/resource-mappings/{name}/devices", s.requireAuthFunc(s.handleAddMappingDeviceUI))
	mux.HandleFunc("DELETE /ui/resource-mappings/{name}/devices", s.requireAuthFunc(s.handleRemoveMappingDeviceUI))
	mux.HandleFunc("GET /firewall", s.requireAuthFunc(s.handleFirewall))
	mux.HandleFunc("GET /ui/firewall/cluster-rule-modal", s.requireAuthFunc(s.handleFWClusterRuleModal))
	mux.HandleFunc("POST /ui/firewall/cluster-rules", s.requireAuthFunc(s.handleCreateFWClusterRule))
	mux.HandleFunc("DELETE /ui/firewall/cluster-rules/{id}", s.requireAuthFunc(s.handleDeleteFWClusterRule))
	mux.HandleFunc("GET /ui/firewall/host-rule-modal", s.requireAuthFunc(s.handleFWHostRuleModal))
	mux.HandleFunc("POST /ui/firewall/host-rules", s.requireAuthFunc(s.handleCreateFWHostRule))
	mux.HandleFunc("DELETE /ui/firewall/host-rules/{id}", s.requireAuthFunc(s.handleDeleteFWHostRule))
	mux.HandleFunc("GET /ui/firewall/ipset-modal", s.requireAuthFunc(s.handleFWIPSetModal))
	mux.HandleFunc("POST /ui/firewall/ipsets", s.requireAuthFunc(s.handleCreateFWIPSet))
	mux.HandleFunc("DELETE /ui/firewall/ipsets/{id}", s.requireAuthFunc(s.handleDeleteFWIPSet))
	mux.HandleFunc("POST /ui/firewall/default-deny", s.requireAuthFunc(s.handleSetFWDefaultDeny))
	mux.HandleFunc("GET /security-groups", s.requireAuthFunc(s.handleSecurityGroups))
	mux.HandleFunc("GET /ui/security-groups/create-modal", s.requireAuthFunc(s.handleSGCreateModal))
	mux.HandleFunc("POST /ui/security-groups", s.requireAuthFunc(s.handleCreateSG))
	mux.HandleFunc("DELETE /ui/security-groups/{id}", s.requireAuthFunc(s.handleDeleteSG))
	mux.HandleFunc("GET /ui/security-groups/{id}/rule-modal", s.requireAuthFunc(s.handleSGRuleModal))
	mux.HandleFunc("POST /ui/security-groups/{id}/rules", s.requireAuthFunc(s.handleAddSGRule))
	mux.HandleFunc("DELETE /ui/security-groups/rules/{rule}", s.requireAuthFunc(s.handleDeleteSGRule))
	mux.HandleFunc("GET /containers", s.requireAuthFunc(s.handleContainers))
	mux.HandleFunc("GET /ui/containers-table", s.requireAuthFunc(s.handleContainersTable))
	mux.HandleFunc("GET /ui/containers/new-modal", s.requireAuthFunc(s.handleNewContainerModal))
	mux.HandleFunc("POST /ui/containers", s.requireAuthFunc(s.handleCreateContainer))
	mux.HandleFunc("POST /ui/containers/bulk", s.requireAuthFunc(s.handleBulkContainers))
	mux.HandleFunc("POST /ui/containers/{host}/{name}/start", s.requireAuthFunc(s.handleStartContainer))
	mux.HandleFunc("POST /ui/containers/{host}/{name}/stop", s.requireAuthFunc(s.handleStopContainer))
	mux.HandleFunc("DELETE /ui/containers/{host}/{name}", s.requireAuthFunc(s.handleDeleteContainer))
	mux.HandleFunc("GET /ui/containers/{host}/{name}/exec-modal", s.requireAuthFunc(s.handleContainerExecModal))
	mux.HandleFunc("POST /ui/containers/{host}/{name}/exec", s.requireAuthFunc(s.handleExecContainer))
	mux.HandleFunc("GET /backups", s.requireAuthFunc(s.handleBackups))
	mux.HandleFunc("GET /schedules", s.requireAuthFunc(s.handleSchedules))
	mux.HandleFunc("GET /rebalance", s.requireAuthFunc(s.handleRebalance))
	mux.HandleFunc("GET /projects", s.requireAuthFunc(s.handleProjects))
	mux.HandleFunc("GET /rbac", s.requireAuthFunc(s.handleRBAC))
	mux.HandleFunc("GET /ui/rbac/binding-modal", s.requireAuthFunc(s.handleRBACBindingModal))
	mux.HandleFunc("POST /ui/rbac/bindings", s.requireAuthFunc(s.handleGrantRole))
	mux.HandleFunc("DELETE /ui/rbac/bindings/{id}", s.requireAuthFunc(s.handleRevokeRole))
	mux.HandleFunc("GET /metrics-viewer", s.requireAuthFunc(s.handleMetricsViewer))
	mux.HandleFunc("GET /dashboards", s.requireAuthFunc(s.handleDashboards))
	mux.HandleFunc("GET /pci", s.requireAuthFunc(s.handlePCI))
	mux.HandleFunc("GET /users", s.requireAuthFunc(s.handleUsers))
	mux.HandleFunc("GET /account/2fa", s.requireAuthFunc(s.handleAccount2FA))
	mux.HandleFunc("GET /account/registry", s.requireAuthFunc(s.handleAccountRegistry))
	mux.HandleFunc("GET /ui/registry-creds/add-modal", s.requireAuthFunc(s.handleRegistryCredModal))
	mux.HandleFunc("POST /ui/registry-creds", s.requireAuthFunc(s.handleAddRegistryCredential))
	mux.HandleFunc("DELETE /ui/registry-creds", s.requireAuthFunc(s.handleDeleteRegistryCredential))
	mux.HandleFunc("POST /account/password", s.requireAuthFunc(s.handleAccountPassword))
	mux.HandleFunc("POST /account/2fa/webauthn/begin", s.requireAuthFunc(s.handleWebAuthnBegin))
	mux.HandleFunc("POST /account/2fa/webauthn/finish", s.requireAuthFunc(s.handleWebAuthnFinish))
	mux.HandleFunc("GET /diagnostics", s.requireAuthFunc(s.handleDiagnostics))
	mux.HandleFunc("GET /topology", s.requireAuthFunc(s.handleTopology))
	mux.HandleFunc("GET /health", s.requireAuthFunc(s.handleHealthTimeline))
	mux.HandleFunc("GET /vms/{name}/logs", s.requireAuthFunc(s.handleVMLogsPage))
	mux.HandleFunc("GET /stacks/{name}/logs", s.requireAuthFunc(s.handleStackLogsPage))

	// HTMX partials (require auth)
	mux.HandleFunc("GET /ui/cluster-stats", s.requireAuthFunc(s.handleClusterStats))
	mux.HandleFunc("GET /ui/vms-table", s.requireAuthFunc(s.handleVMsTable))
	mux.HandleFunc("GET /ui/vms/new-modal", s.requireAuthFunc(s.handleNewVMModal))
	mux.HandleFunc("GET /ui/vms/{name}/detail", s.requireAuthFunc(s.handleVMDetailPartial))
	mux.HandleFunc("GET /ui/vms/{name}/snapshot-modal", s.requireAuthFunc(s.handleSnapshotModal))
	mux.HandleFunc("GET /ui/vms/{name}/migrate-modal", s.requireAuthFunc(s.handleMigrateModal))
	mux.HandleFunc("GET /ui/vms/{name}/stats", s.requireAuthFunc(s.handleVMStatsPartial))
	mux.HandleFunc("GET /ui/events/stream", s.requireAuthFunc(s.handleEventsStream))
	mux.HandleFunc("GET /ui/images/pull-modal", s.requireAuthFunc(s.handlePullImageModal))
	mux.HandleFunc("GET /ui/images/build-modal", s.requireAuthFunc(s.handleBuildImageModal))
	mux.HandleFunc("GET /ui/images/push-modal", s.requireAuthFunc(s.handlePushImageModal))
	mux.HandleFunc("GET /ui/images-table", s.requireAuthFunc(s.handleImagesTable))
	mux.HandleFunc("GET /ui/stacks/deploy-modal", s.requireAuthFunc(s.handleDeployStackModal))
	mux.HandleFunc("POST /ui/stacks/plan", s.requireAuthFunc(s.handlePlanPreview))
	mux.HandleFunc("GET /ui/hosts/{name}/stats", s.requireAuthFunc(s.handleHostStatsPartial))
	mux.HandleFunc("GET /ui/networks/create-modal", s.requireAuthFunc(s.handleCreateNetworkModal))
	mux.HandleFunc("GET /ui/vms/{name}/edit-modal", s.requireAuthFunc(s.handleEditVMModal))
	mux.HandleFunc("GET /ui/vms/{name}/console-modal", s.requireAuthFunc(s.handleConsoleModal))
	mux.HandleFunc("GET /ui/vms/{name}/vnc-modal", s.requireAuthFunc(s.handleVNCModal))
	mux.HandleFunc("GET /ui/vms/{name}/tags-modal", s.requireAuthFunc(s.handleVMTagsModal))
	mux.HandleFunc("POST /ui/vms/{name}/tags", s.requireAuthFunc(s.handleSetVMTags))
	mux.HandleFunc("GET /ui/vms/{name}/spice-modal", s.requireAuthFunc(s.handleSpiceModal))
	mux.HandleFunc("GET /ui/vms/{name}/spice.vv", s.requireAuthFunc(s.handleSpiceVV))
	mux.HandleFunc("GET /ui/vms/{name}/compatible-hosts", s.requireAuthFunc(s.handleCompatibleHosts))
	mux.HandleFunc("GET /ui/vms/{name}/migrate-progress", s.requireAuthFunc(s.handleMigrateProgress))
	mux.HandleFunc("GET /ui/hosts/{name}/available-devices", s.requireAuthFunc(s.handleAvailableDevices))
	mux.HandleFunc("GET /ui/diagnostics-partial", s.requireAuthFunc(s.handleDiagnosticsPartial))
	mux.HandleFunc("GET /ui/storage-table", s.requireAuthFunc(s.handleStorageTable))
	mux.HandleFunc("GET /ui/storage/create-modal", s.requireAuthFunc(s.handleCreatePoolModal))
	mux.HandleFunc("GET /ui/storage/iso-browser", s.requireAuthFunc(s.handleISOBrowserModal))
	mux.HandleFunc("GET /ui/storage/contents", s.requireAuthFunc(s.handleStorageContents))
	mux.HandleFunc("POST /ui/storage/upload", s.requireAuthFunc(s.handleUploadStorageContent))
	mux.HandleFunc("GET /ui/schedules/create-modal", s.requireAuthFunc(s.handleScheduleModal))
	mux.HandleFunc("GET /ui/projects/create-modal", s.requireAuthFunc(s.handleProjectCreateModal))
	mux.HandleFunc("GET /ui/projects/quota-modal", s.requireAuthFunc(s.handleProjectQuotaModal))
	mux.HandleFunc("GET /ui/vms/{name}/replicate-volume-modal", s.requireAuthFunc(s.handleReplicateVolumeModal))
	mux.HandleFunc("GET /ui/vms/{name}/promote-modal", s.requireAuthFunc(s.handlePromoteModal))
	mux.HandleFunc("POST /ui/vms/{name}/promote", s.requireAuthFunc(s.handlePromoteReplica))
	mux.HandleFunc("GET /ui/search", s.requireAuthFunc(s.handleSearch))
	mux.HandleFunc("GET /ui/vms/{name}/exec-modal", s.requireAuthFunc(s.handleExecModal))
	mux.HandleFunc("POST /ui/vms/{name}/exec", s.requireAuthFunc(s.handleExecVM))
	mux.HandleFunc("GET /ui/lb/create-modal", s.requireAuthFunc(s.handleLBCreateModal))
	mux.HandleFunc("GET /ui/lb/{name}/edit-modal", s.requireAuthFunc(s.handleLBEditModal))
	mux.HandleFunc("GET /ui/health-partial", s.requireAuthFunc(s.handleHealthTimelinePartial))
	mux.HandleFunc("GET /ui/hosts/{name}/stats-history", s.requireAuthFunc(s.handleHostStatsHistory))
	mux.HandleFunc("GET /ui/vms/{name}/stats-history", s.requireAuthFunc(s.handleVMStatsHistory))
	mux.HandleFunc("GET /ui/vms/{name}/logs/stream", s.requireAuthFunc(s.handleVMLogsStream))
	mux.HandleFunc("GET /ui/restore-modal", s.requireAuthFunc(s.handleRestoreModal))
	mux.HandleFunc("GET /ui/hosts/{name}/upgrade-modal", s.requireAuthFunc(s.handleUpgradeModal))

	// Actions (require auth)
	mux.HandleFunc("POST /ui/vms", s.requireAuthFunc(s.handleCreateVM))
	mux.HandleFunc("POST /ui/vms/bulk", s.requireAuthFunc(s.handleBulkVMs))
	mux.HandleFunc("POST /ui/hosts/bulk", s.requireAuthFunc(s.handleBulkHosts))
	mux.HandleFunc("POST /ui/vms/{name}/start", s.requireAuthFunc(s.handleStartVM))
	mux.HandleFunc("POST /ui/vms/{name}/stop", s.requireAuthFunc(s.handleStopVM))
	mux.HandleFunc("POST /ui/vms/{name}/restart", s.requireAuthFunc(s.handleRestartVM))
	mux.HandleFunc("POST /ui/vms/{name}/snapshot", s.requireAuthFunc(s.handleCreateSnapshot))
	mux.HandleFunc("POST /ui/vms/{name}/set-memory", s.requireAuthFunc(s.handleSetVMMemoryUI))
	mux.HandleFunc("POST /ui/vms/{name}/snapshot/{snap}/restore", s.requireAuthFunc(s.handleRestoreSnapshot))
	mux.HandleFunc("DELETE /ui/vms/{name}/snapshot/{snap}", s.requireAuthFunc(s.handleDeleteSnapshot))
	mux.HandleFunc("POST /ui/vms/{name}/migrate", s.requireAuthFunc(s.handleMigrateVM))
	mux.HandleFunc("GET /ui/vms/{name}/clone-modal", s.requireAuthFunc(s.handleCloneModal))
	mux.HandleFunc("POST /ui/vms/{name}/clone", s.requireAuthFunc(s.handleCloneVM))
	mux.HandleFunc("POST /ui/vms/{name}/template", s.requireAuthFunc(s.handleConvertTemplate))
	mux.HandleFunc("DELETE /ui/vms/{name}", s.requireAuthFunc(s.handleDeleteVM))
	mux.HandleFunc("GET /ui/stacks/{name}/export", s.requireAuthFunc(s.handleStackExport))
	mux.HandleFunc("GET /ui/stacks/{name}/migrate-volumes-modal", s.requireAuthFunc(s.handleMigrateVolumesModal))
	mux.HandleFunc("POST /ui/stacks/{name}/migrate-volumes", s.requireAuthFunc(s.handleMigrateStackVolumes))
	mux.HandleFunc("POST /ui/stacks", s.requireAuthFunc(s.handleDeployStack))
	mux.HandleFunc("DELETE /ui/stacks/{name}", s.requireAuthFunc(s.handleDestroyStack))
	mux.HandleFunc("POST /ui/images/pull", s.requireAuthFunc(s.handlePullImage))
	mux.HandleFunc("POST /ui/images/build", s.requireAuthFunc(s.handleBuildImage))
	mux.HandleFunc("POST /ui/images/push", s.requireAuthFunc(s.handlePushImage))
	mux.HandleFunc("DELETE /ui/images/{name}", s.requireAuthFunc(s.handleDeleteImage))
	mux.HandleFunc("POST /ui/networks", s.requireAuthFunc(s.handleCreateNetwork))
	mux.HandleFunc("DELETE /ui/networks/{name}", s.requireAuthFunc(s.handleDeleteNetwork))
	mux.HandleFunc("POST /ui/hosts/{name}/drain", s.requireAuthFunc(s.handleDrainHost))
	mux.HandleFunc("POST /ui/hosts/{name}/undrain", s.requireAuthFunc(s.handleUndrainHost))
	mux.HandleFunc("POST /ui/hosts/{name}/fence", s.requireAuthFunc(s.handleFenceHost))
	mux.HandleFunc("DELETE /ui/hosts/{name}", s.requireAuthFunc(s.handleRemoveHost))
	mux.HandleFunc("POST /ui/hosts/{name}/labels", s.requireAuthFunc(s.handleHostLabelsUpdate))
	mux.HandleFunc("POST /ui/hosts/{name}/config", s.requireAuthFunc(s.handleConfigureHost))
	mux.HandleFunc("POST /ui/hosts/{name}/upgrade", s.requireAuthFunc(s.handleUpgradeHost))
	mux.HandleFunc("GET /ui/hosts/{name}/health", s.requireAuthFunc(s.handleHostHealthMatrix))
	mux.HandleFunc("POST /ui/users", s.requireAuthFunc(s.handleCreateUser))
	mux.HandleFunc("DELETE /ui/users/{name}", s.requireAuthFunc(s.handleDeleteUser))
	mux.HandleFunc("POST /ui/users/{name}/token", s.requireAuthFunc(s.handleCreateToken))
	mux.HandleFunc("DELETE /ui/tokens/{id}", s.requireAuthFunc(s.handleRevokeToken))
	mux.HandleFunc("POST /ui/diagnostics/sync", s.requireAuthFunc(s.handleForceSync))
	mux.HandleFunc("POST /ui/lb", s.requireAuthFunc(s.handleCreateLB))
	mux.HandleFunc("POST /ui/lb/{name}/update", s.requireAuthFunc(s.handleUpdateLB))
	mux.HandleFunc("POST /ui/lb/{name}/backend/{backend}/enable", s.requireAuthFunc(s.handleLBEnableBackend))
	mux.HandleFunc("POST /ui/lb/{name}/backend/{backend}/disable", s.requireAuthFunc(s.handleLBDisableBackend))
	mux.HandleFunc("GET /ui/vms/{name}/export-disk", s.requireAuthFunc(s.handleExportDisk))
	mux.HandleFunc("GET /ui/vms/{name}/backup-modal", s.requireAuthFunc(s.handleBackupModal))
	mux.HandleFunc("POST /ui/vms/{name}/backup-snapshot", s.requireAuthFunc(s.handleCreateBackupSnapshot))
	mux.HandleFunc("GET /ui/vms/{name}/backup-progress", s.requireAuthFunc(s.handleBackupProgress))
	mux.HandleFunc("GET /ui/backups/restore-from-modal", s.requireAuthFunc(s.handleRestoreFromModal))
	mux.HandleFunc("POST /ui/backups/restore-from", s.requireAuthFunc(s.handleRestoreFrom))
	mux.HandleFunc("GET /ui/backups/restore-live-modal", s.requireAuthFunc(s.handleRestoreLiveModal))
	mux.HandleFunc("POST /ui/backups/restore-live", s.requireAuthFunc(s.handleRestoreLive))
	mux.HandleFunc("GET /ui/backups/op-progress", s.requireAuthFunc(s.handleRestoreProgress))
	mux.HandleFunc("POST /ui/backups/verify", s.requireAuthFunc(s.handleRepoVerify))
	mux.HandleFunc("POST /ui/backups/gc", s.requireAuthFunc(s.handleRepoGC))
	mux.HandleFunc("GET /ui/backups/sync-modal", s.requireAuthFunc(s.handleRepoSyncModal))
	mux.HandleFunc("POST /ui/backups/sync", s.requireAuthFunc(s.handleRepoSync))
	mux.HandleFunc("GET /ui/backups/prune-modal", s.requireAuthFunc(s.handleRepoPruneModal))
	mux.HandleFunc("POST /ui/backups/prune", s.requireAuthFunc(s.handleRepoPrune))
	mux.HandleFunc("POST /ui/vms/restore", s.requireAuthFunc(s.handleRestoreVM))
	mux.HandleFunc("POST /ui/vms/{name}/update-spec", s.requireAuthFunc(s.handleUpdateVMSpec))
	mux.HandleFunc("POST /ui/vms/{name}/update-lifecycle", s.requireAuthFunc(s.handleUpdateVMLifecycle))
	mux.HandleFunc("POST /ui/vms/{name}/boot-order", s.requireAuthFunc(s.handleSetBootOrder))
	mux.HandleFunc("GET /ui/vms/{name}/resize-disk-modal", s.requireAuthFunc(s.handleResizeDiskModal))
	mux.HandleFunc("GET /ui/vms/{name}/move-volume-modal", s.requireAuthFunc(s.handleMoveVolumeModal))
	mux.HandleFunc("POST /ui/vms/{name}/move-volume", s.requireAuthFunc(s.handleMoveVolume))
	mux.HandleFunc("POST /ui/vms/{name}/move-volume-stream", s.requireAuthFunc(s.handleMoveVolumeStream))
	mux.HandleFunc("POST /ui/vms/{name}/replicate-volume", s.requireAuthFunc(s.handleReplicateVolume))
	mux.HandleFunc("POST /ui/storage", s.requireAuthFunc(s.handleCreatePool))
	mux.HandleFunc("DELETE /ui/storage/{name}", s.requireAuthFunc(s.handleDeletePool))
	mux.HandleFunc("POST /ui/schedules", s.requireAuthFunc(s.handleCreateSchedule))
	mux.HandleFunc("DELETE /ui/schedules/{vm}", s.requireAuthFunc(s.handleDeleteSchedule))
	mux.HandleFunc("GET /ui/schedules/repl-create-modal", s.requireAuthFunc(s.handleReplScheduleModal))
	mux.HandleFunc("POST /ui/schedules/repl", s.requireAuthFunc(s.handleCreateReplSchedule))
	mux.HandleFunc("DELETE /ui/schedules/repl/{vm}", s.requireAuthFunc(s.handleDeleteReplSchedule))
	mux.HandleFunc("POST /ui/audit/verify", s.requireAuthFunc(s.handleAuditVerify))
	mux.HandleFunc("GET /ui/audit/export", s.requireAuthFunc(s.handleAuditExport))
	mux.HandleFunc("POST /ui/rebalance/run", s.requireAuthFunc(s.handleRebalanceRun))
	mux.HandleFunc("POST /ui/rebalance/{id}/approve", s.requireAuthFunc(s.handleRebalanceApprove))
	mux.HandleFunc("POST /ui/rebalance/{id}/reject", s.requireAuthFunc(s.handleRebalanceReject))
	mux.HandleFunc("POST /ui/projects", s.requireAuthFunc(s.handleCreateProject))
	mux.HandleFunc("DELETE /ui/projects", s.requireAuthFunc(s.handleDeleteProject))
	mux.HandleFunc("POST /ui/projects/quota", s.requireAuthFunc(s.handleSetProjectQuota))
	mux.HandleFunc("POST /ui/vms/{name}/attach-disk", s.requireAuthFunc(s.handleAttachDisk))
	mux.HandleFunc("POST /ui/vms/{name}/resize-disk", s.requireAuthFunc(s.handleResizeDisk))
	mux.HandleFunc("POST /ui/vms/{name}/detach-disk", s.requireAuthFunc(s.handleDetachDisk))
	mux.HandleFunc("POST /ui/vms/{name}/attach-nic", s.requireAuthFunc(s.handleAttachNIC))
	mux.HandleFunc("POST /ui/vms/{name}/detach-nic", s.requireAuthFunc(s.handleDetachNIC))
	mux.HandleFunc("POST /ui/vms/{name}/attach-pci", s.requireAuthFunc(s.handleAttachPCI))
	mux.HandleFunc("POST /ui/vms/{name}/detach-pci", s.requireAuthFunc(s.handleDetachPCI))

	// VNC + Console (page and WebSocket)
	mux.HandleFunc("GET /vms/{name}/vnc", s.requireAuthFunc(s.handleVNCPage))
	mux.HandleFunc("GET /ws/vms/{name}/vnc", s.handleVNCWebSocket)
	mux.HandleFunc("GET /ws/vms/{name}/console", s.handleConsoleWebSocket)

	return mux
}

// ListenAndServe starts the HTTP server on the given address (e.g. ":7445").
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.csrfGuard(s.Handler()), ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}
	if s.tlsConfig != nil {
		slog.Info("UI server listening (TLS)", "addr", addr)
		srv.TLSConfig = s.tlsConfig
		// Certs come from the TLSConfig's GetCertificate (autocert + PKI fallback).
		return srv.ListenAndServeTLS("", "")
	}
	slog.Info("UI server listening", "addr", addr)
	return srv.ListenAndServe()
}

// csrfGuard rejects cross-site state-changing requests (CSRF defense-in-depth
// on top of the SameSite=Lax session cookie). It keys on the browser-set
// Sec-Fetch-Site header — which reflects the TRUE origin relationship even when
// the UI is behind a reverse proxy (a Host/Origin comparison would not), so it
// won't break proxied deployments:
//
//   - safe methods (GET/HEAD/OPTIONS) pass untouched;
//   - Sec-Fetch-Site: cross-site on an unsafe method is blocked (the classic
//     CSRF: a form/fetch from another site);
//   - same-origin / same-site / none pass (legitimate UI actions, bookmarks);
//   - no Sec-Fetch-Site (old browser / non-browser API client): fall back to an
//     Origin check — block only when Origin is present AND its host differs from
//     the request Host (and isn't an allowed pattern). A missing Origin (curl,
//     the CLI, server-to-server) is allowed: CSRF is a browser-only attack.
func (s *Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStateChanging(r.Method) && !s.csrfAllowed(r) {
			slog.Warn("blocked cross-site request", "method", r.Method, "path", r.URL.Path,
				"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"), "origin", r.Header.Get("Origin"))
			http.Error(w, "cross-site request blocked", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// csrfAllowed reports whether an unsafe-method request is same-site enough to
// proceed. See csrfGuard for the policy.
func (s *Server) csrfAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site":
		return false
	case "same-origin", "same-site", "none":
		return true
	}
	// No Sec-Fetch-Site — fall back to Origin.
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client; not a CSRF vector
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	for _, p := range s.wsOriginPatterns { // reuse the WebSocket allowlist
		if p == u.Host {
			return true
		}
	}
	return false
}

// pageData creates a base data map with common fields.
func (s *Server) pageData(title, page string) map[string]any {
	return map[string]any{
		"Title":       title,
		"Page":        page,
		"ClusterName": s.cluster,
	}
}

// sendToast sets the HX-Trigger header to show a toast notification.
func sendToast(w http.ResponseWriter, msg, typ string) {
	w.Header().Set("HX-Trigger", fmt.Sprintf(`{"showToast":{"message":%q,"type":%q}}`, msg, typ))
}

// disableStreamWriteTimeout clears the read/write deadlines on a long-lived
// streaming response (SSE tail or a large file download). The UI HTTP server
// sets WriteTimeout=30s for slowloris protection on normal pages; a stream that
// runs past 30s would otherwise have its connection torn down mid-flight,
// cancelling the request context and aborting the underlying op — which silently
// truncated disk exports and aborted live block-copies at ~30s. Call this once,
// after setting the response headers, in any handler that streams longer than
// that. csrfGuard/requireAuthFunc pass the original ResponseWriter through, so
// the controller reaches the real connection. (httptest.ResponseRecorder returns
// ErrNotSupported, which is harmless to ignore in tests.)
func disableStreamWriteTimeout(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})
}

// ── Template functions ───────────────────────────────────────────────────────

func vmStateBadge(state pb.VMState) template.HTML {
	switch state {
	case pb.VMState_VM_RUNNING:
		return `<span class="badge badge-green">running</span>`
	case pb.VMState_VM_STOPPED:
		return `<span class="badge badge-gray">stopped</span>`
	case pb.VMState_VM_CREATING, pb.VMState_VM_STARTING:
		return `<span class="badge badge-yellow">starting</span>`
	case pb.VMState_VM_STOPPING:
		return `<span class="badge badge-yellow">stopping</span>`
	case pb.VMState_VM_ERROR:
		return `<span class="badge badge-red">error</span>`
	case pb.VMState_VM_MIGRATING:
		return `<span class="badge badge-blue">migrating</span>`
	default:
		return `<span class="badge badge-gray">unknown</span>`
	}
}

func hostStateBadge(state pb.HostState) template.HTML {
	switch state {
	case pb.HostState_HOST_ACTIVE:
		return `<span class="badge badge-green">active</span>`
	case pb.HostState_HOST_DRAINING:
		return `<span class="badge badge-yellow">draining</span>`
	case pb.HostState_HOST_MAINTENANCE:
		return `<span class="badge badge-yellow">maintenance</span>`
	case pb.HostState_HOST_SUSPECT:
		return `<span class="badge badge-red">suspect</span>`
	case pb.HostState_HOST_OFFLINE:
		return `<span class="badge badge-red">offline</span>`
	default:
		return `<span class="badge badge-gray">unknown</span>`
	}
}

func driverBadge(driver string) template.HTML {
	switch driver {
	case "nfs":
		return `<span class="badge badge-blue">nfs</span>`
	case "ceph":
		return `<span class="badge badge-purple">ceph</span>`
	case "iscsi":
		return `<span class="badge badge-yellow">iscsi</span>`
	default:
		return `<span class="badge badge-gray">local</span>`
	}
}

func firstIP(ifaces []*pb.VMInterface) string {
	for _, i := range ifaces {
		if i.Ip != "" {
			return i.Ip
		}
	}
	return "—"
}

func vmActions(name string, state pb.VMState) template.HTML {
	var sb strings.Builder
	if state == pb.VMState_VM_STOPPED {
		fmt.Fprintf(&sb, `<button class="btn btn-sm btn-icon" title="Start" hx-post="/ui/vms/%s/start" hx-target="#vm-%s" hx-swap="outerHTML">%s</button>`, name, name, iconHelper("play"))
	}
	if state == pb.VMState_VM_RUNNING {
		fmt.Fprintf(&sb, `<button class="btn btn-sm btn-icon" title="Stop" hx-post="/ui/vms/%s/stop" hx-target="#vm-%s" hx-swap="outerHTML" hx-confirm="Stop %s?">%s</button>`, name, name, name, iconHelper("stop"))
		fmt.Fprintf(&sb, `<button class="btn btn-sm btn-icon" title="Restart" hx-post="/ui/vms/%s/restart" hx-target="#vm-%s" hx-swap="outerHTML">%s</button>`, name, name, iconHelper("restart"))
	}
	fmt.Fprintf(&sb, `<button class="btn btn-sm btn-icon btn-danger" title="Delete" hx-delete="/ui/vms/%s" hx-confirm="Delete %s?" hx-push-url="/vms">%s</button>`, name, name, iconHelper("delete"))
	return template.HTML(sb.String())
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func jsonHelper(v any) string {
	return fmt.Sprintf("%v", v)
}

func truncateHelper(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type ClusterStats struct {
	TotalHosts, ActiveHosts   int
	TotalVMs, RunningVMs      int
	StoppedVMs, ErrorVMs      int
	CPUUsed, CPUTotal         int32
	MemUsedGiB, MemTotalGiB   int32
	DiskUsedGiB, DiskTotalGiB int64
	CPUPct, MemPct, DiskPct   float64
}

func clusterStats(hosts []*pb.Host, vms []*pb.VM) ClusterStats {
	s := ClusterStats{TotalHosts: len(hosts), TotalVMs: len(vms)}
	var diskUsedBytes, diskTotalBytes int64
	for _, h := range hosts {
		if h.State == pb.HostState_HOST_ACTIVE {
			s.ActiveHosts++
		}
		s.CPUTotal += h.CpuTotal
		s.CPUUsed += h.CpuUsed
		s.MemTotalGiB += h.MemTotalMib / 1024
		s.MemUsedGiB += h.MemUsedMib / 1024
		// Disk: actual (statfs/df) usage summed across each host's pools,
		// matching the hosts list/detail pages — not allocated.
		u, t := sumPoolActual(h.GetStoragePools())
		diskUsedBytes += u
		diskTotalBytes += t
	}
	s.DiskUsedGiB = diskUsedBytes / (1024 * 1024 * 1024)
	s.DiskTotalGiB = diskTotalBytes / (1024 * 1024 * 1024)
	for _, v := range vms {
		switch v.State {
		case pb.VMState_VM_RUNNING:
			s.RunningVMs++
		case pb.VMState_VM_STOPPED:
			s.StoppedVMs++
		case pb.VMState_VM_ERROR:
			s.ErrorVMs++
		}
	}
	if s.CPUTotal > 0 {
		s.CPUPct = float64(s.CPUUsed) / float64(s.CPUTotal) * 100
	}
	if s.MemTotalGiB > 0 {
		s.MemPct = float64(s.MemUsedGiB) / float64(s.MemTotalGiB) * 100
	}
	if s.DiskTotalGiB > 0 {
		s.DiskPct = float64(s.DiskUsedGiB) / float64(s.DiskTotalGiB) * 100
	}
	return s
}
