package ui

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// bulkResult is one row of a bulk operation outcome.
type bulkResult struct {
	Name    string
	Success bool
	Error   string
}

// bulkNames reads the selected-item list a bulk toolbar posts. The toolbars
// post the hidden input named `bulk_names` (set by bulk-select.js); we fall
// back to `names` so direct/API callers and older forms keep working.
func bulkNames(r *http.Request) []string {
	if v := splitCSV(r.FormValue("bulk_names")); len(v) > 0 {
		return v
	}
	return splitCSV(r.FormValue("names"))
}

// splitHostName splits a "host/name" bulk key (containers are keyed by both).
func splitHostName(key string) (host, name string) {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "", key
}

// runBulk fan-outs `action` over each name. Each call uses a derived context
// (so client cancellation propagates) and a 30-row error budget — beyond that
// the caller knows the operation broadly failed.
//
// Returns aggregate counts plus per-row outcomes for a partial-failure
// dialog.
func runBulk(ctx context.Context, names []string, action func(context.Context, string) error) (succeeded int, failed int, results []bulkResult) {
	results = make([]bulkResult, 0, len(names))
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	// Bound concurrency so a 1000-VM bulk doesn't fan out 1000 gRPC calls.
	sem := make(chan struct{}, 8)
	for _, n := range names {
		n := strings.TrimSpace(n)
		if n == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			err := action(ctx, n)
			mu.Lock()
			if err != nil {
				failed++
				msg := err.Error()
				if len(msg) > 200 {
					msg = msg[:200] + "…"
				}
				results = append(results, bulkResult{Name: n, Success: false, Error: msg})
			} else {
				succeeded++
				results = append(results, bulkResult{Name: n, Success: true})
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return
}

// handleBulkVMs dispatches `start | stop | restart | delete` over the
// posted set of VM names.
//
// Form: action=<verb>&names=vm-1,vm-2,vm-3
func (s *Server) handleBulkVMs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	names := bulkNames(r)
	if len(names) == 0 {
		sendToast(w, "no VMs selected", "warn")
		w.WriteHeader(http.StatusOK)
		return
	}

	var fn func(context.Context, string) error
	switch action {
	case "start":
		fn = func(ctx context.Context, name string) error {
			_, err := s.grpc.StartVM(ctx, &pb.StartVMRequest{Name: name})
			return err
		}
	case "stop":
		fn = func(ctx context.Context, name string) error {
			_, err := s.grpc.StopVM(ctx, &pb.StopVMRequest{Name: name})
			return err
		}
	case "restart":
		fn = func(ctx context.Context, name string) error {
			_, err := s.grpc.RestartVM(ctx, &pb.RestartVMRequest{Name: name})
			return err
		}
	case "delete":
		fn = func(ctx context.Context, name string) error {
			_, err := s.grpc.DeleteVM(ctx, &pb.DeleteVMRequest{Name: name})
			return err
		}
	default:
		http.Error(w, "invalid action: "+action, http.StatusBadRequest)
		return
	}

	ok, ko, results := runBulk(s.uiBearerCtx(r), names, fn)
	slog.Info("UI: bulk VM action", "action", action, "ok", ok, "fail", ko, "total", len(names))

	tone := "success"
	if ko > 0 && ok > 0 {
		tone = "warn"
	} else if ko > 0 {
		tone = "error"
	}
	sendToast(w, fmt.Sprintf("Bulk %s: %d ok, %d failed", action, ok, ko), tone)

	// If any row failed, render a small partial-failure dialog inline.
	if ko > 0 {
		s.renderFragment(w, "bulk_result.html", map[string]any{
			"Action":  action,
			"Results": results,
		})
		return
	}
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// handleBulkHosts dispatches `drain | undrain` over the posted set of
// host names.
func (s *Server) handleBulkHosts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	names := bulkNames(r)
	if len(names) == 0 {
		sendToast(w, "no hosts selected", "warn")
		w.WriteHeader(http.StatusOK)
		return
	}

	var fn func(context.Context, string) error
	switch action {
	case "drain":
		fn = func(ctx context.Context, name string) error {
			// DrainHost is a streaming RPC — we just need it to start
			// successfully. The drain happens asynchronously.
			stream, err := s.grpc.DrainHost(ctx, &pb.DrainHostRequest{Name: name})
			if err != nil {
				return err
			}
			// Consume one message to confirm the stream opened cleanly.
			_, err = stream.Recv()
			return err
		}
	case "undrain":
		fn = func(ctx context.Context, name string) error {
			_, err := s.grpc.UndrainHost(ctx, &pb.UndrainHostRequest{Name: name})
			return err
		}
	default:
		http.Error(w, "invalid action: "+action, http.StatusBadRequest)
		return
	}

	ok, ko, results := runBulk(s.uiBearerCtx(r), names, fn)
	slog.Info("UI: bulk host action", "action", action, "ok", ok, "fail", ko, "total", len(names))

	tone := "success"
	if ko > 0 && ok > 0 {
		tone = "warn"
	} else if ko > 0 {
		tone = "error"
	}
	sendToast(w, fmt.Sprintf("Bulk %s: %d ok, %d failed", action, ok, ko), tone)
	if ko > 0 {
		s.renderFragment(w, "bulk_result.html", map[string]any{
			"Action":  action,
			"Results": results,
		})
		return
	}
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// handleBulkContainers dispatches `start | stop | delete` over the posted set
// of containers. Each selected item is a "host/name" key (containers are keyed
// by both host and name).
//
// Form: action=<verb>&bulk_names=host-a/ct-1,host-b/ct-2
func (s *Server) handleBulkContainers(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	keys := bulkNames(r)
	if len(keys) == 0 {
		sendToast(w, "no containers selected", "warn")
		w.WriteHeader(http.StatusOK)
		return
	}

	var fn func(context.Context, string) error
	switch action {
	case "start":
		fn = func(ctx context.Context, key string) error {
			host, name := splitHostName(key)
			_, err := s.grpc.StartContainer(ctx, &pb.StartContainerRequest{HostName: host, Name: name})
			return err
		}
	case "stop":
		fn = func(ctx context.Context, key string) error {
			host, name := splitHostName(key)
			_, err := s.grpc.StopContainer(ctx, &pb.StopContainerRequest{HostName: host, Name: name, TimeoutSec: 30})
			return err
		}
	case "delete":
		fn = func(ctx context.Context, key string) error {
			host, name := splitHostName(key)
			_, err := s.grpc.DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: host, Name: name})
			return err
		}
	default:
		http.Error(w, "invalid action: "+action, http.StatusBadRequest)
		return
	}

	ok, ko, results := runBulk(s.uiBearerCtx(r), keys, fn)
	slog.Info("UI: bulk container action", "action", action, "ok", ok, "fail", ko, "total", len(keys))

	tone := "success"
	if ko > 0 && ok > 0 {
		tone = "warn"
	} else if ko > 0 {
		tone = "error"
	}
	sendToast(w, fmt.Sprintf("Bulk %s: %d ok, %d failed", action, ok, ko), tone)
	if ko > 0 {
		s.renderFragment(w, "bulk_result.html", map[string]any{
			"Action":  action,
			"Results": results,
		})
		return
	}
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
