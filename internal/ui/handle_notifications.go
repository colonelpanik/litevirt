package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
)

// Notification CRUD runs in-process against the host-local Corrosion handle
// (same as `lv notify`), CRDT-replicated cluster-wide. Behind the UI session.

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Notifications", "notifications")
	if s.db == nil {
		data["Error"] = "corrosion DB not wired into UI server (build mismatch)"
		s.renderPage(w, "notifications.html", data)
		return
	}
	targets, err := corrosion.ListNotificationTargets(r.Context(), s.db)
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "notifications.html", data)
		return
	}
	routes, _ := corrosion.ListNotificationRoutes(r.Context(), s.db)
	data["Targets"] = targets
	data["Routes"] = routes
	s.renderPage(w, "notifications.html", data)
}

func (s *Server) handleNotifyTargetModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "notify_target_modal.html", nil)
}

func (s *Server) handleCreateNotifyTarget(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	typ := strings.TrimSpace(r.FormValue("type"))
	url := strings.TrimSpace(r.FormValue("url"))
	if name == "" || url == "" {
		sendToast(w, "name and url are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cfg, _ := json.Marshal(map[string]string{"url": url})
	// Validate it builds a real target before storing.
	if _, err := notify.NewTarget(name, typ, string(cfg)); err != nil {
		sendToast(w, "invalid target: "+err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, _ := newUIID()
	if err := corrosion.InsertNotificationTarget(r.Context(), s.db, corrosion.NotificationTarget{
		ID: id, Name: name, Type: typ, Config: string(cfg), Enabled: true,
	}); err != nil {
		sendToast(w, "create failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Target "+name+" created", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteNotifyTarget(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := corrosion.DeleteNotificationTarget(r.Context(), s.db, r.PathValue("id")); err != nil {
		sendToast(w, "delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Target deleted", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTestNotifyTarget(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	targets, _ := corrosion.ListNotificationTargets(r.Context(), s.db)
	for _, t := range targets {
		if t.ID != id {
			continue
		}
		target, err := notify.NewTarget(t.Name, t.Type, t.Config)
		if err != nil {
			sendToast(w, "bad target: "+err.Error(), "error")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if err := target.Send(ctx, notify.Notification{
			Kind: "test.notification", Severity: notify.SevInfo, Subject: t.Name,
			Detail: "litevirt test notification", Cluster: s.cluster, Timestamp: time.Now().UTC(),
		}); err != nil {
			sendToast(w, "send failed: "+err.Error(), "error")
			w.WriteHeader(http.StatusOK)
			return
		}
		sendToast(w, "Test notification sent to "+t.Name, "success")
		w.WriteHeader(http.StatusOK)
		return
	}
	sendToast(w, "target not found", "error")
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) handleNotifyRouteModal(w http.ResponseWriter, r *http.Request) {
	targets, _ := corrosion.ListNotificationTargets(r.Context(), s.db)
	s.renderFragment(w, "notify_route_modal.html", map[string]any{"Targets": targets})
}

func (s *Server) handleCreateNotifyRoute(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pattern := strings.TrimSpace(r.FormValue("event_pattern"))
	target := strings.TrimSpace(r.FormValue("target_id"))
	if pattern == "" || target == "" {
		sendToast(w, "pattern and target are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	minSev := r.FormValue("min_severity")
	if minSev == "" {
		minSev = "info"
	}
	rid, _ := newUIID()
	if err := corrosion.InsertNotificationRoute(r.Context(), s.db, corrosion.NotificationRoute{
		ID: rid, EventPattern: pattern, TargetID: target, MinSeverity: minSev, Enabled: true,
	}); err != nil {
		sendToast(w, "create failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Route created", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteNotifyRoute(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		sendToast(w, "cluster DB unavailable", "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := corrosion.DeleteNotificationRoute(r.Context(), s.db, r.PathValue("id")); err != nil {
		sendToast(w, "delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Route deleted", "success")
	w.Header().Set("HX-Redirect", "/notifications")
	w.WriteHeader(http.StatusOK)
}
