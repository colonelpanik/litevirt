package restapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWrapCapsRequestBody(t *testing.T) {
	s := &Server{token: "token"}
	var readErr error
	h := s.wrap(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", int(maxRequestBodyBytes)+1)))
	req.Header.Set("Authorization", "Bearer token")
	h(httptest.NewRecorder(), req)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("body read error = %v, want *http.MaxBytesError", readErr)
	}
}
