// Package restapi implements a lightweight HTTP/JSON gateway over the litevirt gRPC API.
// It exposes a subset of common operations at well-known REST paths so that tools
// that can't speak gRPC (curl, CI scripts, monitoring) can interact with litevirt.
//
// Endpoint summary:
//
//	GET    /api/v1/health                              → Ping
//	GET    /api/v1/hosts                               → ListHosts
//	GET    /api/v1/hosts/{name}                        → InspectHost
//	DELETE /api/v1/hosts/{name}                        → RemoveHost
//	POST   /api/v1/hosts/{name}/drain                  → DrainHost (streaming, returns ack)
//	POST   /api/v1/hosts/{name}/undrain                → UndrainHost
//	PUT    /api/v1/hosts/{name}/labels                 → SetHostLabels
//	POST   /api/v1/hosts/{name}/fence                  → FenceHost
//	GET    /api/v1/hosts/{name}/health                 → GetHostHealth
//	GET    /api/v1/hosts/{name}/devices                → ListHostDevices
//	POST   /api/v1/hosts/{name}/rescan                 → RescanHost
//	GET    /api/v1/hosts/{name}/stats                  → GetHostStats
//	POST   /api/v1/hosts/{name}/config                 → ConfigureHost
//	GET    /api/v1/vms                                 → ListVMs (?stack=&host=)
//	POST   /api/v1/vms/{name}                          → CreateVM
//	GET    /api/v1/vms/{name}                          → InspectVM
//	PUT    /api/v1/vms/{name}                          → UpdateVM
//	DELETE /api/v1/vms/{name}                          → DeleteVM
//	POST   /api/v1/vms/{name}/start                    → StartVM
//	POST   /api/v1/vms/{name}/stop                     → StopVM
//	POST   /api/v1/vms/{name}/restart                  → RestartVM
//	POST   /api/v1/vms/{name}/exec                     → ExecVM
//	POST   /api/v1/vms/{name}/migrate                  → MigrateVM (streaming, returns first progress)
//	GET    /api/v1/vms/{name}/stats                    → GetVMStats
//	POST   /api/v1/vms/{name}/attach                   → AttachDevice
//	POST   /api/v1/vms/{name}/detach                   → DetachDevice
//	POST   /api/v1/vms/{name}/set-ip                   → SetVMIP
//	POST   /api/v1/vms/{name}/rebuild                  → RebuildVM
//	POST   /api/v1/vms/{name}/disks/{disk}/resize      → ResizeDisk
//	POST   /api/v1/vms/{name}/snapshots                → CreateSnapshot
//	GET    /api/v1/vms/{name}/snapshots                → ListSnapshots
//	POST   /api/v1/vms/{name}/snapshots/{snap}/restore → RestoreSnapshot
//	DELETE /api/v1/vms/{name}/snapshots/{snap}         → DeleteSnapshot
//	GET    /api/v1/stacks                              → ListStacks
//	POST   /api/v1/stacks/plan                         → DiffStack (full resolved plan)
//	POST   /api/v1/stacks/{name}/migrate-volumes       → MigrateStackVolumes (streaming)
//	GET    /api/v1/lbs                                 → ListLoadBalancers
//	GET    /api/v1/lbs/{name}                          → InspectLoadBalancer
//	POST   /api/v1/lbs                                 → CreateLoadBalancer
//	PUT    /api/v1/lbs/{name}                          → UpdateLoadBalancer
//	DELETE /api/v1/lbs/{name}                          → DeleteLoadBalancer
//	GET    /api/v1/lbs/{name}/stats                    → LBStats
//	POST   /api/v1/lbs/{name}/backends/{b}/drain       → DrainBackend
//	POST   /api/v1/lbs/{name}/backends/{b}/disable     → DisableBackend
//	POST   /api/v1/lbs/{name}/backends/{b}/enable      → EnableBackend
//	GET    /api/v1/networks                            → ListNetworks
//	GET    /api/v1/networks/{name}                     → GetNetwork
//	POST   /api/v1/networks                            → CreateNetwork
//	DELETE /api/v1/networks/{name}                     → DeleteNetwork
//	GET    /api/v1/images                              → ListImages
//	DELETE /api/v1/images/{name}                       → DeleteImage
//	POST   /api/v1/auth/login                          → Login
//	GET    /api/v1/users                               → ListUsers
//	POST   /api/v1/users                               → CreateUser
//	DELETE /api/v1/users/{name}                        → DeleteUser
//	POST   /api/v1/tokens                              → CreateToken
//	DELETE /api/v1/tokens/{id}                         → RevokeToken
//	GET    /api/v1/status                              → GetClusterStatus
//	GET    /api/v1/audit                               → ListAuditLog (?limit=N)
package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Server is the REST gateway.
type Server struct {
	grpc  pb.LiteVirtClient
	token string // optional static bearer token for auth
	mux   *http.ServeMux
}

// NewServer creates a REST gateway that forwards to the given gRPC client.
// token is an optional static bearer token; if empty, no auth is enforced
// (caller should bind the listener to localhost only).
func NewServer(grpc pb.LiteVirtClient, token string) *Server {
	s := &Server{grpc: grpc, token: token}
	s.mux = http.NewServeMux()
	s.registerRoutes()
	return s
}

// ListenAndServe starts the HTTP server on addr. Blocks until error.
func (s *Server) ListenAndServe(addr string) error {
	slog.Info("REST API gateway listening", "addr", addr)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/v1/health", s.noAuth(s.handleHealth))
	s.mux.HandleFunc("/api/v1/hosts", s.wrap(s.handleHosts))
	s.mux.HandleFunc("/api/v1/hosts/", s.wrap(s.handleHost))
	s.mux.HandleFunc("/api/v1/vms", s.wrap(s.handleVMs))
	s.mux.HandleFunc("/api/v1/vms/", s.wrap(s.handleVM))
	s.mux.HandleFunc("/api/v1/stacks/plan", s.wrap(s.handleStackPlan))
	s.mux.HandleFunc("/api/v1/stacks/", s.wrap(s.handleStack))
	s.mux.HandleFunc("/api/v1/stacks", s.wrap(s.handleStacks))
	s.mux.HandleFunc("/api/v1/lbs", s.wrap(s.handleLBs))
	s.mux.HandleFunc("/api/v1/lbs/", s.wrap(s.handleLB))
	s.mux.HandleFunc("/api/v1/networks", s.wrap(s.handleNetworks))
	s.mux.HandleFunc("/api/v1/networks/", s.wrap(s.handleNetwork))
	s.mux.HandleFunc("/api/v1/images", s.wrap(s.handleImages))
	s.mux.HandleFunc("/api/v1/images/", s.wrap(s.handleImage))
	s.mux.HandleFunc("/api/v1/auth/login", s.noAuth(s.handleLogin))
	s.mux.HandleFunc("/api/v1/users", s.wrap(s.handleUsers))
	s.mux.HandleFunc("/api/v1/users/", s.wrap(s.handleUser))
	s.mux.HandleFunc("/api/v1/tokens", s.wrap(s.handleTokens))
	s.mux.HandleFunc("/api/v1/tokens/", s.wrap(s.handleToken))
	s.mux.HandleFunc("/api/v1/status", s.wrap(s.handleStatus))
	s.mux.HandleFunc("/api/v1/audit", s.wrap(s.handleAudit))
	// parity surfaces — rebalance, 2fa, containers, firewall, regions.
	s.registerParityRoutes()
	// second pass: stack/container CRUD, sessions, services,
	// backup snapshot push/pull, volume move/replicate, preflight.
	s.registerCoverageRoutes()
	// third pass: audit-chain verify/export, storage pools, region list/migrate.
	s.registerAuditPoolRegionRoutes()
}

// noAuth wraps a handler with content-type but no auth (health, login).
func (s *Server) noAuth(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}
}

// wrap adds auth check and sets content-type around a handler.
func (s *Server) wrap(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		bearer := strings.TrimPrefix(auth, "Bearer ")

		if s.token != "" {
			// Static token mode: check against configured token.
			if bearer != s.token {
				jsonError(w, http.StatusUnauthorized, "invalid or missing bearer token")
				return
			}
		} else {
			// No static token configured — require a valid user bearer token.
			// The token is validated by the gRPC auth interceptor on each call
			// via grpcCtx(). Here we just ensure one is present.
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") || bearer == "" {
				jsonError(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}
}

func (s *Server) grpcCtx(r *http.Request) context.Context {
	ctx := r.Context()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+bearer))
	}
	return ctx
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp, err := s.grpc.Ping(s.grpcCtx(r), &pb.PingRequest{})
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	jsonWrite(w, map[string]string{"status": "ok", "host": resp.HostName})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ListHosts(s.grpcCtx(r), &pb.ListHostsRequest{})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/v1/hosts/<name>[/action]
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/hosts/")
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	if name == "" {
		jsonError(w, http.StatusBadRequest, "host name required")
		return
	}
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	ctx := s.grpcCtx(r)

	switch {
	case action == "" && r.Method == http.MethodGet:
		resp, err := s.grpc.InspectHost(ctx, &pb.InspectHostRequest{Name: name})
		if err != nil {
			jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonProto(w, resp)

	case action == "" && r.Method == http.MethodDelete:
		if _, err := s.grpc.RemoveHost(ctx, &pb.RemoveHostRequest{
			Name:  name,
			Force: r.URL.Query().Get("force") == "true",
		}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case action == "drain" && r.Method == http.MethodPost:
		// DrainHost is a server-streaming RPC. If the client requested SSE,
		// stream all progress events; otherwise return the first event then
		// detach (legacy ack-only behavior).
		stream, err := s.grpc.DrainHost(ctx, &pb.DrainHostRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		if wantsSSE(r) {
			streamSSE(w, r, func() (proto.Message, error) {
				m, err := stream.Recv()
				if m == nil {
					return nil, err
				}
				return m, err
			})
			return
		}
		jsonWrite(w, map[string]string{"status": "draining", "host": name})

	case action == "undrain" && r.Method == http.MethodPost:
		resp, err := s.grpc.UndrainHost(ctx, &pb.UndrainHostRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "labels" && r.Method == http.MethodPut:
		var req pb.SetHostLabelsRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.SetHostLabels(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "fence" && r.Method == http.MethodPost:
		var req pb.FenceHostRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.FenceHost(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "health" && r.Method == http.MethodGet:
		resp, err := s.grpc.GetHostHealth(ctx, &emptypb.Empty{})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "devices" && r.Method == http.MethodGet:
		resp, err := s.grpc.ListHostDevices(ctx, &pb.ListHostDevicesRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "rescan" && r.Method == http.MethodPost:
		resp, err := s.grpc.RescanHost(ctx, &pb.RescanHostRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "stats" && r.Method == http.MethodGet:
		resp, err := s.grpc.GetHostStats(ctx, &pb.GetHostStatsRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "config" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		// Docs advertise PUT; POST is preserved for backward compatibility.
		var req pb.ConfigureHostRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.ConfigureHost(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	default:
		jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown action %q or method %s", action, r.Method))
	}
}

func (s *Server) handleVMs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	q := r.URL.Query()
	resp, err := s.grpc.ListVMs(s.grpcCtx(r), &pb.ListVMsRequest{
		StackName: q.Get("stack"),
		HostName:  q.Get("host"),
	})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleVM(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/v1/vms/<name>[/action]
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/vms/")
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	ctx := s.grpcCtx(r)

	switch {
	case action == "" && r.Method == http.MethodGet:
		resp, err := s.grpc.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
		if err != nil {
			jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonProto(w, resp)

	case action == "" && r.Method == http.MethodPost:
		var req pb.CreateVMRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.grpc.CreateVM(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonProto(w, resp)

	case action == "" && r.Method == http.MethodPut:
		var req pb.UpdateVMRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.UpdateVM(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "" && r.Method == http.MethodDelete:
		if _, err := s.grpc.DeleteVM(ctx, &pb.DeleteVMRequest{Name: name}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case action == "start" && r.Method == http.MethodPost:
		if _, err := s.grpc.StartVM(ctx, &pb.StartVMRequest{Name: name}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonWrite(w, map[string]string{"status": "started", "vm": name})

	case action == "stop" && r.Method == http.MethodPost:
		stopReq := &pb.StopVMRequest{Name: name, Force: r.URL.Query().Get("force") == "true"}
		if v := r.URL.Query().Get("timeout"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				stopReq.Timeout = int32(n)
			}
		}
		if _, err := s.grpc.StopVM(ctx, stopReq); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonWrite(w, map[string]string{"status": "stopped", "vm": name})

	case action == "restart" && r.Method == http.MethodPost:
		if _, err := s.grpc.RestartVM(ctx, &pb.RestartVMRequest{Name: name}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonWrite(w, map[string]string{"status": "restarting", "vm": name})

	case action == "exec" && r.Method == http.MethodPost:
		var req pb.ExecVMRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.ExecVM(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "migrate" && r.Method == http.MethodPost:
		var req pb.MigrateVMRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.VmName = name
		stream, err := s.grpc.MigrateVM(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		if wantsSSE(r) {
			streamSSE(w, r, func() (proto.Message, error) {
				m, err := stream.Recv()
				if m == nil {
					return nil, err
				}
				return m, err
			})
			return
		}
		first, err := stream.Recv()
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, first)

	case action == "stats" && r.Method == http.MethodGet:
		resp, err := s.grpc.GetVMStats(ctx, &pb.GetVMStatsRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "attach" && r.Method == http.MethodPost:
		var req pb.AttachDeviceRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.VmName = name
		resp, err := s.grpc.AttachDevice(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "detach" && r.Method == http.MethodPost:
		var req pb.DetachDeviceRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.VmName = name
		resp, err := s.grpc.DetachDevice(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "set-ip" && r.Method == http.MethodPost:
		var req pb.SetVMIPRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.SetVMIP(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case action == "rebuild" && r.Method == http.MethodPost:
		var req pb.RebuildVMRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.RebuildVM(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	// POST /api/v1/vms/{name}/disks/{disk}/resize
	case strings.HasPrefix(action, "disks/") && r.Method == http.MethodPost:
		diskParts := strings.SplitN(strings.TrimPrefix(action, "disks/"), "/", 2)
		if len(diskParts) != 2 || diskParts[1] != "resize" {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown disk action %q", action))
			return
		}
		diskName := diskParts[0]
		var req pb.ResizeDiskRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.VmName = name
		req.DiskName = diskName
		resp, err := s.grpc.ResizeDisk(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	// Snapshots: POST/GET /api/v1/vms/{name}/snapshots[/{snap}[/restore]]
	case action == "snapshots" && r.Method == http.MethodPost:
		var req pb.CreateSnapshotRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.VmName = name
		resp, err := s.grpc.CreateSnapshot(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonProto(w, resp)

	case action == "snapshots" && r.Method == http.MethodGet:
		resp, err := s.grpc.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	case strings.HasPrefix(action, "snapshots/"):
		snapParts := strings.SplitN(strings.TrimPrefix(action, "snapshots/"), "/", 2)
		snap := snapParts[0]
		if len(snapParts) == 2 && snapParts[1] == "restore" && r.Method == http.MethodPost {
			resp, err := s.grpc.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: name, SnapshotName: snap})
			if err != nil {
				grpcHTTPError(w, http.StatusInternalServerError, err)
				return
			}
			jsonProto(w, resp)
		} else if len(snapParts) == 1 && r.Method == http.MethodDelete {
			if _, err := s.grpc.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: name, SnapshotName: snap}); err != nil {
				grpcHTTPError(w, http.StatusInternalServerError, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		} else {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown snapshot action %q or method %s", action, r.Method))
		}

	default:
		jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown action %q or method %s", action, r.Method))
	}
}

func (s *Server) handleStacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ListStacks(s.grpcCtx(r), nil)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

// handleStackPlan accepts compose YAML and returns the full resolved plan as JSON.
// POST /api/v1/stacks/plan  body: {"compose_yaml": "..."}
func (s *Server) handleStackPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.DiffStackRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ComposeYaml == "" {
		jsonError(w, http.StatusBadRequest, "compose_yaml required")
		return
	}
	resp, err := s.grpc.DiffStack(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

// handleStack routes stack-name-scoped actions: /api/v1/stacks/<name>/<action>.
//
//	POST /api/v1/stacks/{name}/migrate-volumes
//	     ?to=<pool>&map=vm=pool&map=vm/disk=pool&parallel=N&order=a,b
//	     &delete_source=true&dry_run=true&health_wait=60
//	     (streaming; request SSE via Accept: text/event-stream or ?stream=sse)
func (s *Server) handleStack(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/stacks/")
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	if name == "" {
		jsonError(w, http.StatusBadRequest, "stack name required")
		return
	}
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	ctx := s.grpcCtx(r)

	switch {
	case action == "migrate-volumes" && r.Method == http.MethodPost:
		q := r.URL.Query()
		req := &pb.MigrateStackVolumesRequest{
			StackName:    name,
			DefaultPool:  q.Get("to"),
			DeleteSource: q.Get("delete_source") == "true",
			DryRun:       q.Get("dry_run") == "true",
		}
		if v := q.Get("parallel"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				req.Parallel = int32(n)
			}
		}
		if v := q.Get("health_wait"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				req.HealthWaitSeconds = uint32(n)
			}
		}
		if v := q.Get("order"); v != "" {
			req.Order = strings.Split(v, ",")
		}
		placements, err := parseRESTPlacements(q["map"])
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Placements = placements
		if req.DefaultPool == "" && len(req.Placements) == 0 {
			jsonError(w, http.StatusBadRequest, "to or at least one map rule required")
			return
		}
		stream, err := s.grpc.MigrateStackVolumes(ctx, req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		if wantsSSE(r) {
			streamSSE(w, r, func() (proto.Message, error) {
				m, err := stream.Recv()
				if m == nil {
					return nil, err
				}
				return m, err
			})
			return
		}
		jsonWrite(w, map[string]string{"status": "migrating", "stack": name})

	default:
		jsonError(w, http.StatusNotFound, "unknown stack action")
	}
}

// parseRESTPlacements parses repeated ?map= values ("vm=pool" or
// "vm/disk=pool") into VolumePlacement messages.
func parseRESTPlacements(maps []string) ([]*pb.VolumePlacement, error) {
	var out []*pb.VolumePlacement
	for _, m := range maps {
		key, pool, ok := strings.Cut(m, "=")
		if !ok || key == "" || pool == "" {
			return nil, fmt.Errorf("invalid map %q: expected vm=pool or vm/disk=pool", m)
		}
		vm, disk, _ := strings.Cut(key, "/")
		if vm == "" {
			return nil, fmt.Errorf("invalid map %q: empty vm", m)
		}
		out = append(out, &pb.VolumePlacement{VmName: vm, DiskName: disk, TargetPool: pool})
	}
	return out, nil
}

// ── Load Balancers ───────────────────────────────────────────────────────────

func (s *Server) handleLBs(w http.ResponseWriter, r *http.Request) {
	ctx := s.grpcCtx(r)
	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.ListLoadBalancers(ctx, nil)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	case http.MethodPost:
		var req pb.CreateLBRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.grpc.CreateLoadBalancer(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonProto(w, resp)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "GET or POST only")
	}
}

func (s *Server) handleLB(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/v1/lbs/<name>[/stats | /backends/<backend>/<action>]
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/lbs/")
	parts := strings.SplitN(rest, "/", 4)
	name := parts[0]
	if name == "" {
		jsonError(w, http.StatusBadRequest, "load balancer name required")
		return
	}

	ctx := s.grpcCtx(r)

	switch {
	// GET /api/v1/lbs/{name}
	case len(parts) == 1 && r.Method == http.MethodGet:
		resp, err := s.grpc.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: name})
		if err != nil {
			jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonProto(w, resp)

	// PUT /api/v1/lbs/{name}
	case len(parts) == 1 && r.Method == http.MethodPut:
		var req pb.UpdateLBRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = name
		resp, err := s.grpc.UpdateLoadBalancer(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	// DELETE /api/v1/lbs/{name}
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if _, err := s.grpc.DeleteLoadBalancer(ctx, &pb.DeleteLBRequest{Name: name}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	// GET /api/v1/lbs/{name}/stats
	case len(parts) == 2 && parts[1] == "stats" && r.Method == http.MethodGet:
		resp, err := s.grpc.LBStats(ctx, &pb.LBStatsRequest{Name: name})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)

	// POST /api/v1/lbs/{name}/backends/{backend}/{drain|disable|enable}
	case len(parts) == 4 && parts[1] == "backends" && r.Method == http.MethodPost:
		backend := parts[2]
		action := parts[3]
		switch action {
		case "drain":
			resp, err := s.grpc.DrainBackend(ctx, &pb.DrainBackendRequest{LbName: name, Backend: backend})
			if err != nil {
				grpcHTTPError(w, http.StatusInternalServerError, err)
				return
			}
			jsonProto(w, resp)
		case "disable":
			resp, err := s.grpc.DisableBackend(ctx, &pb.DisableBackendRequest{LbName: name, Backend: backend})
			if err != nil {
				grpcHTTPError(w, http.StatusInternalServerError, err)
				return
			}
			jsonProto(w, resp)
		case "enable":
			resp, err := s.grpc.EnableBackend(ctx, &pb.EnableBackendRequest{LbName: name, Backend: backend})
			if err != nil {
				grpcHTTPError(w, http.StatusInternalServerError, err)
				return
			}
			jsonProto(w, resp)
		default:
			jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown backend action %q", action))
		}

	default:
		jsonError(w, http.StatusNotFound, fmt.Sprintf("unknown path or method %s %s", r.Method, r.URL.Path))
	}
}

// ── Networks ─────────────────────────────────────────────────────────────────

func (s *Server) handleNetworks(w http.ResponseWriter, r *http.Request) {
	ctx := s.grpcCtx(r)
	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.ListNetworks(ctx, nil)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	case http.MethodPost:
		var req pb.CreateNetworkRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.grpc.CreateNetwork(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonProto(w, resp)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "GET or POST only")
	}
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")
	if name == "" {
		jsonError(w, http.StatusBadRequest, "network name required")
		return
	}

	ctx := s.grpcCtx(r)

	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.GetNetwork(ctx, &pb.GetNetworkRequest{Name: name})
		if err != nil {
			jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonProto(w, resp)
	case http.MethodDelete:
		force := r.URL.Query().Get("force") == "true"
		if _, err := s.grpc.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: name, Force: force}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		jsonError(w, http.StatusNotFound, fmt.Sprintf("method %s not allowed", r.Method))
	}
}

// ── Images ───────────────────────────────────────────────────────────────────

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ListImages(s.grpcCtx(r), &emptypb.Empty{})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleImage(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/images/")
	if name == "" {
		jsonError(w, http.StatusBadRequest, "image name required")
		return
	}
	if r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "DELETE only")
		return
	}
	if _, err := s.grpc.DeleteImage(s.grpcCtx(r), &pb.DeleteImageRequest{Name: name}); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Auth ─────────────────────────────────────────────────────────────────────

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.LoginRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := s.grpc.Login(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	ctx := s.grpcCtx(r)
	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.ListUsers(ctx, &emptypb.Empty{})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	case http.MethodPost:
		var req pb.CreateUserRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.grpc.CreateUser(ctx, &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonProto(w, resp)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "GET or POST only")
	}
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if name == "" {
		jsonError(w, http.StatusBadRequest, "user name required")
		return
	}
	if r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "DELETE only")
		return
	}
	if _, err := s.grpc.DeleteUser(s.grpcCtx(r), &pb.DeleteUserRequest{Username: name}); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.CreateTokenRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp, err := s.grpc.CreateToken(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonProto(w, resp)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/")
	if id == "" {
		jsonError(w, http.StatusBadRequest, "token id required")
		return
	}
	if r.Method != http.MethodDelete {
		jsonError(w, http.StatusMethodNotAllowed, "DELETE only")
		return
	}
	if _, err := s.grpc.RevokeToken(s.grpcCtx(r), &pb.RevokeTokenRequest{Id: id}); err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Monitoring ───────────────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.GetClusterStatus(s.grpcCtx(r), &emptypb.Empty{})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	limit := int32(100)
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if n, err := strconv.Atoi(ls); err == nil && n > 0 {
			limit = int32(n)
		}
	}
	resp, err := s.grpc.ListAuditLog(s.grpcCtx(r), &pb.ListAuditLogRequest{Limit: limit})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func protoFromJSON(r *http.Request, msg proto.Message) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(body, msg)
}

var pjson = protojson.MarshalOptions{
	EmitUnpopulated: false,
	UseProtoNames:   true,
}

func jsonWrite(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

func jsonProto(w http.ResponseWriter, msg proto.Message) {
	b, err := pjson.Marshal(msg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "marshal: "+err.Error())
		return
	}
	_, _ = w.Write(b)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// grpcHTTPError writes an error response, mapping gRPC status codes to HTTP codes.
func grpcHTTPError(w http.ResponseWriter, fallbackCode int, err error) {
	if st, ok := grpcstatus.FromError(err); ok {
		switch st.Code() {
		case codes.Unauthenticated:
			jsonError(w, http.StatusUnauthorized, st.Message())
			return
		case codes.PermissionDenied:
			jsonError(w, http.StatusForbidden, st.Message())
			return
		case codes.NotFound:
			jsonError(w, http.StatusNotFound, st.Message())
			return
		case codes.InvalidArgument:
			jsonError(w, http.StatusBadRequest, st.Message())
			return
		case codes.AlreadyExists:
			jsonError(w, http.StatusConflict, st.Message())
			return
		case codes.FailedPrecondition:
			jsonError(w, http.StatusConflict, st.Message())
			return
		}
	}
	jsonError(w, fallbackCode, err.Error())
}
