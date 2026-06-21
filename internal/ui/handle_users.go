package ui

import (
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	users, _ := s.grpc.ListUsers(ctx, &emptypb.Empty{})
	data := s.pageData("Users", "users")
	data["Users"] = users.GetUsers()
	s.renderPage(w, "users.html", data)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	_, err := s.grpc.CreateUser(s.uiBearerCtx(r), &pb.CreateUserRequest{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		Role:     r.FormValue("role"),
	})
	if err != nil {
		sendToast(w, "Create user failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "User "+r.FormValue("username")+" created", "success")
	w.Header().Set("HX-Redirect", "/users")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, err := s.grpc.DeleteUser(s.uiBearerCtx(r), &pb.DeleteUserRequest{Username: name})
	if err != nil {
		sendToast(w, "Delete user failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "User "+name+" deleted", "success")
	w.Header().Set("HX-Redirect", "/users")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// Scope picker: comma- or newline-separated list of path prefixes.
	// Empty = inherit the user's full permissions. The auth engine
	// intersects token scopes with role bindings (— perms =
	// intersection(user, token)).
	scopes := splitAndTrim(r.FormValue("scope_paths"))
	token, err := s.grpc.CreateToken(s.uiBearerCtx(r), &pb.CreateTokenRequest{
		Username:   r.FormValue("username"),
		Name:       r.FormValue("label"),
		ScopePaths: scopes,
	})
	if err != nil {
		sendToast(w, "Create token failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Token created: "+token.Token, "success")
	w.WriteHeader(http.StatusOK)
}

func splitAndTrim(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r", "")
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, err := s.grpc.RevokeToken(s.uiBearerCtx(r), &pb.RevokeTokenRequest{Id: id})
	if err != nil {
		sendToast(w, "Revoke token failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Token revoked", "success")
	w.WriteHeader(http.StatusOK)
}
