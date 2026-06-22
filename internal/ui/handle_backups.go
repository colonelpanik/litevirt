package ui

import (
	"log/slog"
	"net/http"
	"sort"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

// handleBackups renders /backups. Two modes:
//
//   - With ?repo=<path>: open that on-disk repo and list its manifests.
//     Used by the legacy URL form and by any non-configured browse.
//   - Without ?repo=: enumerate the daemon's configured `backup_repos:`
//     map (set via SetBackupRepos at startup) and render each repo's
//     manifest count + total size.
//
// Pre-flight failures (open / list) are surfaced per-repo so a single
// broken repo doesn't blank the whole page.
func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Backups", "backups")
	repoPath := r.URL.Query().Get("repo")
	data["RepoPath"] = repoPath

	if repoPath != "" {
		s.renderBackupsForRepo(w, data, repoPath)
		return
	}

	if len(s.backupRepos) == 0 {
		data["Hint"] = "No repos configured. Add a `backup_repos:` block to /etc/litevirt/config.yaml or append ?repo=<path> to this URL."
		s.renderPage(w, "backups.html", data)
		return
	}

	type repoEntry struct {
		Name       string
		Path       string
		Encryption string
		Count      int
		TotalBytes int64
		Error      string
	}

	names := make([]string, 0, len(s.backupRepos))
	for name := range s.backupRepos {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]repoEntry, 0, len(names))
	for _, name := range names {
		path := s.backupRepos[name]
		entry := repoEntry{Name: name, Path: path}
		repo, err := pbsstore.Open(path)
		if err != nil {
			slog.Info("ui: open backup repo", "name", name, "path", path, "error", err)
			entry.Error = err.Error()
			entries = append(entries, entry)
			continue
		}
		entry.Encryption = repo.Meta().Encryption
		manifests, err := repo.ListManifests()
		if err != nil {
			entry.Error = err.Error()
			entries = append(entries, entry)
			continue
		}
		entry.Count = len(manifests)
		for _, m := range manifests {
			entry.TotalBytes += m.TotalSize
		}
		entries = append(entries, entry)
	}
	data["Repos"] = entries
	s.renderPage(w, "backups.html", data)
}

// renderBackupsForRepo handles the legacy ?repo=<path> single-repo view.
func (s *Server) renderBackupsForRepo(w http.ResponseWriter, data map[string]any, repoPath string) {
	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		slog.Info("ui: open backup repo", "repo", repoPath, "error", err)
		data["Error"] = err.Error()
		s.renderPage(w, "backups.html", data)
		return
	}
	manifests, err := repo.ListManifests()
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "backups.html", data)
		return
	}
	data["Encryption"] = repo.Meta().Encryption
	data["Manifests"] = manifests
	s.renderPage(w, "backups.html", data)
}
