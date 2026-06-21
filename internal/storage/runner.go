package storage

import (
	"context"
	"errors"
	"os/exec"
)

// ErrUnimplemented is returned by a driver operation that has no implementation
// yet, so callers fail loudly instead of acting on a half-provisioned resource.
var ErrUnimplemented = errors.New("storage: operation not implemented")

// cmdRunner runs an external command and returns its combined output. Drivers
// shell out to tool binaries (rbd, zfs, …); routing those calls through a
// runner lets tests exercise failure/rollback paths without the real binaries.
type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// realCmd is the production runner: a plain exec with combined output.
func realCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
