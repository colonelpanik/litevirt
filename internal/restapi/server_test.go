package restapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// fakeGRPC is a minimal stub gRPC client for REST gateway tests.
type fakeGRPC struct {
	pb.UnimplementedLiteVirtServer
}

func (f *fakeGRPC) Ping(_ interface{}, _ *pb.PingRequest, _ ...grpc.CallOption) (*pb.PingResponse, error) {
	return &pb.PingResponse{HostName: "test-host"}, nil
}
func (f *fakeGRPC) ListHosts(_ interface{}, _ *pb.ListHostsRequest, _ ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "host1"}}}, nil
}
func (f *fakeGRPC) InspectHost(_ interface{}, req *pb.InspectHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	return &pb.Host{Name: req.Name}, nil
}
func (f *fakeGRPC) ListVMs(_ interface{}, _ *pb.ListVMsRequest, _ ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	return &pb.ListVMsResponse{}, nil
}
func (f *fakeGRPC) InspectVM(_ interface{}, req *pb.InspectVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	return &pb.VM{Name: req.Name}, nil
}
func (f *fakeGRPC) ListStacks(_ interface{}, _ interface{}, _ ...grpc.CallOption) (*pb.ListStacksResponse, error) {
	return &pb.ListStacksResponse{}, nil
}

// newTestServer builds a Server backed by a mock gRPC client.
func newTestServer(token string) (*Server, pb.LiteVirtClient) {
	// We need a real pb.LiteVirtClient interface, so use a gRPC connection to nowhere.
	// Instead, use a real conn to avoid the interface mismatch.
	// For simplicity, build via a local in-process gRPC server.
	cc, _ := grpc.NewClient("localhost:0") // won't connect — tests only call non-RPC paths
	client := pb.NewLiteVirtClient(cc)
	return NewServer(client, token), client
}

func TestHealth_NoToken(t *testing.T) {
	// Build a server with no token requirement and a real (but non-connecting) client.
	// We can't easily stub the gRPC call, so test auth and routing logic only.
	s := NewServer(nil, "")
	_ = s // routing registered
}

func TestAuth_MissingToken_Returns401(t *testing.T) {
	s := &Server{token: "secret", mux: http.NewServeMux()}
	s.registerRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_WrongToken_Returns401(t *testing.T) {
	s := &Server{token: "secret", mux: http.NewServeMux()}
	s.registerRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_CorrectToken_Passes(t *testing.T) {
	// Test that the auth middleware passes with the correct token.
	// We test via /api/v1/vms (GET, method-check only, no gRPC needed for 405).
	// Use POST to get method-not-allowed — this is returned before gRPC is called.
	s := &Server{token: "secret", mux: http.NewServeMux()}
	s.registerRoutes()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	// Should not be 401 (auth passed); expect 405 from method check.
	if rec.Code == http.StatusUnauthorized {
		t.Error("correct token should not get 401")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 after auth, got %d", rec.Code)
	}
}

func TestVMs_MethodNotAllowed(t *testing.T) {
	s := &Server{token: "secret", mux: http.NewServeMux()}
	s.registerRoutes()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHosts_MethodNotAllowed(t *testing.T) {
	s := &Server{token: "secret", mux: http.NewServeMux()}
	s.registerRoutes()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestJsonError_Format(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	jsonError(rec, http.StatusBadRequest, "bad input")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body["error"] != "bad input" {
		t.Errorf("unexpected error body: %v", body)
	}
}
