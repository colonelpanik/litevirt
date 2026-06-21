package ui

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Repo maintenance actions for /backups. These call internal/pbsstore directly
// (in-process, same as the inventory page) rather than via gRPC, so they do NOT
// pass through the daemon's RBAC interceptor. They are reachable only by an
// authenticated UI session; treat repo mutation as an operator-level action and
// see docs/ui.md for the follow-up to expose these as RBAC-gated RPCs.

// openNamedRepo resolves a ?repo=<name> query param to an open repo.
func (s *Server) openNamedRepo(r *http.Request) (*pbsstore.Repo, string, error) {
	name := r.URL.Query().Get("repo")
	if name == "" {
		return nil, "", fmt.Errorf("repo required")
	}
	path := s.resolveRepoPath(name)
	repo, err := pbsstore.Open(path)
	return repo, name, err
}

// backupInFlight reports whether a backup to the named repo is currently
// running — GC must not race a push to the same repo (a just-written chunk
// whose manifest hasn't landed looks like garbage).
func (s *Server) backupInFlight(repoName string) bool {
	inflight := false
	s.backupOps.Range(func(_, v any) bool {
		st := v.(*backupOpState)
		if st.Kind == "backup" && st.Repo == repoName && !st.Done {
			inflight = true
			return false
		}
		return true
	})
	return inflight
}

func (s *Server) handleRepoVerify(w http.ResponseWriter, r *http.Request) {
	repo, name, err := s.openNamedRepo(r)
	if err != nil {
		sendToast(w, "Verify failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	stats, err := pbsstore.Verify(r.Context(), repo)
	if err != nil {
		sendToast(w, "Verify failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	bad := len(stats.Mismatches) + len(stats.Missing)
	if bad > 0 {
		sendToast(w, fmt.Sprintf("Repo %s: %d chunks checked, %d mismatched, %d missing", name, stats.ChunksChecked, len(stats.Mismatches), len(stats.Missing)), "error")
	} else {
		sendToast(w, fmt.Sprintf("Repo %s verified: %d chunks OK", name, stats.ChunksChecked), "success")
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRepoGC(w http.ResponseWriter, r *http.Request) {
	repo, name, err := s.openNamedRepo(r)
	if err != nil {
		sendToast(w, "GC failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.backupInFlight(name) {
		sendToast(w, "A backup to this repo is in progress — try GC again when it finishes", "error")
		w.WriteHeader(http.StatusConflict)
		return
	}
	stats, err := pbsstore.GC(r.Context(), repo)
	if err != nil {
		sendToast(w, "GC failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, fmt.Sprintf("GC on %s: removed %d chunks, reclaimed %s", name, stats.ChunksDeleted, formatBytes(stats.BytesReclaimed)), "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRepoSyncModal(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("repo")
	var dests []string
	for _, n := range s.repoNames() {
		if n != src {
			dests = append(dests, n)
		}
	}
	s.renderFragment(w, "repo_sync_modal.html", map[string]any{"Src": src, "Dests": dests})
}

func (s *Server) handleRepoSync(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	src, srcName, err := s.openNamedRepo(r)
	if err != nil {
		sendToast(w, "Sync failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dstName := strings.TrimSpace(r.FormValue("dest"))
	dst, err := pbsstore.Open(s.resolveRepoPath(dstName))
	if err != nil {
		sendToast(w, "Sync failed: open dest: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	stats, err := pbsstore.SyncRepo(r.Context(), src, dst)
	if err != nil {
		sendToast(w, "Sync failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, fmt.Sprintf("Synced %s → %s: %d manifests, %d chunks (%s), %d already present",
		srcName, dstName, stats.ManifestsCopied, stats.ChunksCopied, formatBytes(stats.BytesCopied), stats.ChunksSkipped), "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRepoPruneModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "repo_prune_modal.html", map[string]any{"Repo": r.URL.Query().Get("repo")})
}

// handleRepoPrune previews (apply=0) or applies (apply=1) a retention prune.
func (s *Server) handleRepoPrune(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	repo, name, err := s.openNamedRepo(r)
	if err != nil {
		sendToast(w, "Prune failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	policy := pbsstore.RetentionPolicy{
		KeepLast:    int(atoi32(r.FormValue("keep_last"))),
		KeepDaily:   int(atoi32(r.FormValue("keep_daily"))),
		KeepWeekly:  int(atoi32(r.FormValue("keep_weekly"))),
		KeepMonthly: int(atoi32(r.FormValue("keep_monthly"))),
		KeepYearly:  int(atoi32(r.FormValue("keep_yearly"))),
	}
	plan, err := pbsstore.PlanPrune(repo, policy)
	if err != nil {
		sendToast(w, "Prune plan failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if r.FormValue("apply") != "1" {
		// Preview: render the plan for confirmation.
		s.renderFragment(w, "repo_prune_preview.html", map[string]any{
			"Repo": name, "Keep": plan.Keep, "Delete": plan.Delete, "Policy": r.Form,
		})
		return
	}
	if err := pbsstore.ApplyPrune(repo, plan); err != nil {
		sendToast(w, "Prune failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, fmt.Sprintf("Pruned %s: kept %d, deleted %d manifests (run GC to reclaim space)", name, len(plan.Keep), len(plan.Delete)), "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}
