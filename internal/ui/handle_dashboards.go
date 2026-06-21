// embedded Grafana JSON panels. The dashboards live as
// static files under internal/ui/static/grafana/ and are served by
// the existing /static route. This handler renders an index page so
// operators can browse, download, and one-click-import them into
// their Grafana stack.

package ui

import (
	"embed"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed static/grafana/*.json
var grafanaDashboards embed.FS

// dashboardEntry is the per-file row the template renders.
type dashboardEntry struct {
	Filename    string // e.g. "cluster-overview.json"
	Title       string // pulled from the JSON's "title" field
	Description string // pulled from the JSON's "description" field
	UID         string // pulled from the JSON's "uid" field
}

func (s *Server) handleDashboards(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Dashboards", "dashboards")
	entries, err := listGrafanaDashboards()
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "dashboards.html", data)
		return
	}
	data["Dashboards"] = entries
	s.renderPage(w, "dashboards.html", data)
}

// listGrafanaDashboards walks the embedded FS, parses each JSON,
// and surfaces just enough metadata for the index page. Cheap: the
// dashboard set is small (4-6 files).
func listGrafanaDashboards() ([]dashboardEntry, error) {
	files, err := grafanaDashboards.ReadDir("static/grafana")
	if err != nil {
		return nil, err
	}
	var out []dashboardEntry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		body, err := grafanaDashboards.ReadFile(filepath.Join("static/grafana", f.Name()))
		if err != nil {
			continue
		}
		var meta struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			UID         string `json:"uid"`
		}
		_ = json.Unmarshal(body, &meta)
		out = append(out, dashboardEntry{
			Filename:    f.Name(),
			Title:       meta.Title,
			Description: meta.Description,
			UID:         meta.UID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out, nil
}
