package image

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func drain(ch chan PullProgress) {
	go func() {
		for range ch {
		}
	}()
}

// TestPull_RejectsDisallowedScheme verifies a file:// (or any non-http/https)
// source URL is refused before any fetch.
func TestPull_RejectsDisallowedScheme(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	ch := make(chan PullProgress, 8)
	drain(ch)
	err := Pull(s, "img", "file:///etc/passwd", "", PullOptions{}, ch)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("Pull(file://) = %v, want scheme error", err)
	}
}

// TestPull_RejectsRedirectToFile verifies a redirect that switches to a
// disallowed scheme is refused.
func TestPull_RejectsRedirectToFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	if err := Pull(s, "img", srv.URL, "", PullOptions{}, ch); err == nil {
		t.Fatal("Pull(redirect→file://) = nil, want error")
	}
}

// TestPull_FailsOnOversize verifies an oversized body FAILS (not silently
// truncates) once it passes the byte ceiling.
func TestPull_FailsOnOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stream more than the tiny ceiling below.
		blob := strings.Repeat("x", 4096)
		for i := 0; i < 8; i++ {
			fmt.Fprint(w, blob)
		}
	}))
	defer srv.Close()

	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 64)
	drain(ch)
	err := Pull(s, "img", srv.URL, "", PullOptions{MaxBytes: 1024}, ch)
	if err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("Pull(oversize) = %v, want ceiling error", err)
	}
	if s.ImageExists("img") {
		t.Error("oversized image must not be finalized")
	}
}

// TestPull_RejectsBadName verifies a traversal image name is refused.
func TestPull_RejectsBadName(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.Init()
	ch := make(chan PullProgress, 8)
	drain(ch)
	if err := Pull(s, "../../etc/x", "https://example.com/i.qcow2", "", PullOptions{}, ch); err == nil {
		t.Fatal("Pull(bad name) = nil, want error")
	}
}
