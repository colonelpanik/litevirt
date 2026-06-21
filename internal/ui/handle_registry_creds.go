package ui

import (
	"net/http"
	"strings"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Registry-credential UI (v23). Unlike the SG/notification pages (which write
// Corrosion directly and have no user identity), these handlers call the gRPC
// RPCs via uiBearerCtx so the session bearer carries the username — the daemon
// resolves per-user ownership and redacts secrets for us.

func (s *Server) handleAccountRegistry(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	data := s.pageData("Account · Registry Credentials", "registry")
	data["IsOperator"] = s.callerIsOperator(r)
	resp, err := s.grpc.ListRegistryCredentials(ctx, &pb.ListRegistryCredentialsRequest{})
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "registry_creds.html", data)
		return
	}
	var mine, global []*pb.RegistryCredential
	for _, rc := range resp.Credentials {
		if rc.Scope == "global" {
			global = append(global, rc)
		} else {
			mine = append(mine, rc)
		}
	}
	data["Mine"] = mine
	data["Global"] = global
	s.renderPage(w, "registry_creds.html", data)
}

func (s *Server) handleRegistryCredModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "registry_cred_modal.html", map[string]any{
		"IsOperator": s.callerIsOperator(r),
	})
}

func (s *Server) handleAddRegistryCredential(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	registry := strings.TrimSpace(r.FormValue("registry"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	global := r.FormValue("global") == "on" || r.FormValue("global") == "true"
	if registry == "" || username == "" || password == "" {
		sendToast(w, "registry, username and password are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := s.grpc.SetRegistryCredential(s.uiBearerCtx(r), &pb.SetRegistryCredentialRequest{
		Global: global, Registry: registry, Username: username, Password: password,
	}); err != nil {
		sendToast(w, "save failed: "+grpcMsg(err), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Credential for "+registry+" saved", "success")
	w.Header().Set("HX-Redirect", "/account/registry")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteRegistryCredential(w http.ResponseWriter, r *http.Request) {
	registry := strings.TrimSpace(r.URL.Query().Get("registry"))
	global := r.URL.Query().Get("global") == "true"
	if registry == "" {
		sendToast(w, "registry is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := s.grpc.DeleteRegistryCredential(s.uiBearerCtx(r), &pb.DeleteRegistryCredentialRequest{
		Global: global, Registry: registry,
	}); err != nil {
		sendToast(w, "delete failed: "+grpcMsg(err), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Credential removed", "success")
	w.Header().Set("HX-Redirect", "/account/registry")
	w.WriteHeader(http.StatusOK)
}

// callerIsOperator reports whether the session user is operator or admin, used
// to reveal the global-credential controls. Fails closed (false) on error.
func (s *Server) callerIsOperator(r *http.Request) bool {
	who, err := s.grpc.Whoami(s.uiBearerCtx(r), &emptypb.Empty{})
	if err != nil {
		return false
	}
	return who.Role == "operator" || who.Role == "admin"
}

// grpcMsg unwraps a gRPC status to its bare message for a cleaner toast.
func grpcMsg(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Message()
	}
	return err.Error()
}
