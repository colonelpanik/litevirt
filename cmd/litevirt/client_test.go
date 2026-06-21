package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// TestWithClient verifies the helper connects, runs fn with the client, always
// closes, and propagates errors from both Connect and fn.
func TestWithClient(t *testing.T) {
	origConnect := cli.Connect
	t.Cleanup(func() { cli.Connect = origConnect })

	t.Run("runs fn and closes", func(t *testing.T) {
		closed := false
		var gotClient pb.LiteVirtClient
		mock := &mockClient{}
		cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
			return mock, func() { closed = true }, nil
		}
		err := withClient(context.Background(), func(_ context.Context, c pb.LiteVirtClient) error {
			gotClient = c
			return nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotClient != pb.LiteVirtClient(mock) {
			t.Error("fn did not receive the connected client")
		}
		if !closed {
			t.Error("closer was not called")
		}
	})

	t.Run("connect error short-circuits", func(t *testing.T) {
		called := false
		cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
			return nil, nil, errors.New("boom")
		}
		err := withClient(context.Background(), func(_ context.Context, _ pb.LiteVirtClient) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Errorf("expected connect error and fn not called; err=%v called=%v", err, called)
		}
	})

	t.Run("fn error propagates and closer still runs", func(t *testing.T) {
		closed := false
		cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
			return &mockClient{}, func() { closed = true }, nil
		}
		want := errors.New("fn failed")
		err := withClient(context.Background(), func(_ context.Context, _ pb.LiteVirtClient) error {
			return want
		})
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
		if !closed {
			t.Error("closer should run even when fn errors")
		}
	})
}
