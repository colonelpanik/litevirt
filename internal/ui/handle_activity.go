package ui

import (
	"net/http"
)

// handleActivity is a back-compat redirect: the former "Activity" page is now
// folded into the unified /events page (recent history + live tail), so old
// bookmarks and cross-links keep working. Query string (e.g. ?limit=) is
// preserved.
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	target := "/events"
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusFound)
}
