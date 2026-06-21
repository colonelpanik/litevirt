// REST parity, third pass: the audit-chain, storage-pool, and region RPCs that
// had no HTTP surface. The underlying gRPC RPCs already exist; this only wires
// the gateway, following the same handler idiom as coverage.go.

package restapi

import (
	"net/http"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// registerAuditPoolRegionRoutes wires the third-pass parity additions.
// Called from registerRoutes() alongside registerCoverageRoutes().
func (s *Server) registerAuditPoolRegionRoutes() {
	// Audit hash-chain.
	s.mux.HandleFunc("/api/v1/audit/verify", s.wrap(s.handleAuditVerify))
	s.mux.HandleFunc("/api/v1/audit/export", s.wrap(s.handleAuditExport))

	// Storage pools.
	s.mux.HandleFunc("/api/v1/pools", s.wrap(s.handlePools))
	s.mux.HandleFunc("/api/v1/pools/", s.wrap(s.handlePool))

	// Region list + cross-region migrate (the bare /api/v1/regions GET stays
	// mapped to RegionStatus in parity.go).
	s.mux.HandleFunc("/api/v1/regions/list", s.wrap(s.handleRegionsList))
	s.mux.HandleFunc("/api/v1/regions/migrate", s.wrap(s.handleRegionMigrate))
}

// ── Audit chain ───────────────────────────────────────────────────────────────

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	resp, err := s.grpc.VerifyAuditChain(s.grpcCtx(r), &emptypb.Empty{})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ExportAuditChain(s.grpcCtx(r), &pb.ExportAuditChainRequest{
		Since: r.URL.Query().Get("since"),
		Until: r.URL.Query().Get("until"),
	})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

// ── Storage pools ─────────────────────────────────────────────────────────────

// handlePools: GET lists pools, POST creates one.
func (s *Server) handlePools(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.ListStoragePools(s.grpcCtx(r), &pb.ListStoragePoolsRequest{})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	case http.MethodPost:
		var req pb.CreateStoragePoolRequest
		if err := protoFromJSON(r, &req); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.grpc.CreateStoragePool(s.grpcCtx(r), &req)
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "GET or POST")
	}
}

// handlePool: GET inspects /api/v1/pools/{name}, DELETE removes it. The host is
// selected with ?host=; empty defaults to the daemon's own host.
func (s *Server) handlePool(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/pools/")
	if name == "" {
		jsonError(w, http.StatusBadRequest, "pool name required")
		return
	}
	host := r.URL.Query().Get("host")
	switch r.Method {
	case http.MethodGet:
		resp, err := s.grpc.GetStoragePool(s.grpcCtx(r), &pb.GetStoragePoolRequest{Name: name, Host: host})
		if err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		jsonProto(w, resp)
	case http.MethodDelete:
		if _, err := s.grpc.DeleteStoragePool(s.grpcCtx(r), &pb.DeleteStoragePoolRequest{Name: name, Host: host}); err != nil {
			grpcHTTPError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "GET or DELETE")
	}
}

// ── Regions ───────────────────────────────────────────────────────────────────

func (s *Server) handleRegionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	resp, err := s.grpc.ListRegions(s.grpcCtx(r), &pb.ListRegionsRequest{})
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	jsonProto(w, resp)
}

func (s *Server) handleRegionMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req pb.CrossRegionMigrateRequest
	if err := protoFromJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	stream, err := s.grpc.CrossRegionMigrate(s.grpcCtx(r), &req)
	if err != nil {
		grpcHTTPError(w, http.StatusInternalServerError, err)
		return
	}
	if wantsSSE(r) {
		streamSSE(w, r, func() (proto.Message, error) { return stream.Recv() })
		return
	}
	// Non-SSE callers get the first progress frame; long-running callers
	// should set Accept: text/event-stream.
	first, rerr := stream.Recv()
	if rerr != nil {
		grpcHTTPError(w, http.StatusInternalServerError, rerr)
		return
	}
	jsonProto(w, first)
}
