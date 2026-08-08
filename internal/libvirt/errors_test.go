package libvirt

import (
	"errors"
	"fmt"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Each row exercises exactly ONE arm of IsNotFound: the typed rows carry an
// "opaque" message that matches no substring, and the message rows carry no
// libvirt error code. A row that satisfied both would not tell us which arm
// answered, so it could not catch that arm being deleted.
func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"typed ErrNoDomain",
			golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "opaque"},
			true,
		},
		{
			"typed ErrNoDomainSnapshot",
			golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainSnapshot), Message: "opaque"},
			true,
		},
		{
			"typed ErrNoDomainCheckpoint",
			golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainCheckpoint), Message: "opaque"},
			true,
		},
		{
			// The typed switch is a whitelist of absence codes, not "any typed error".
			"typed ErrInternalError",
			golibvirt.Error{Code: uint32(golibvirt.ErrInternalError), Message: "opaque"},
			false,
		},
		{
			// libvirt's real wording for a vanished snapshot, and the string
			// grpcapi's DeleteSnapshot matched by hand before this helper existed.
			"message no domain snapshot",
			errors.New("no domain snapshot with matching name 'snap1'"),
			true,
		},
		{
			// litevirt's own wrapper text (snapshot.go's DeleteSnapshot lookup).
			"message litevirt snapshot wrapper",
			fmt.Errorf("snapshot %q not found: %w", "snap1", errors.New("boom")),
			true,
		},
		{"message mixed case", errors.New("Domain Not Found"), true},
		{
			"message unrelated failure",
			errors.New("internal error: qemu unexpectedly closed the monitor"),
			false,
		},
		{
			// Write-lock contention is a RETRY predicate, a different question from
			// "does this object exist?" — snapshot.go keeps its own heuristics for it.
			// This row exists so a future refactor cannot quietly merge the two.
			"message write lock",
			errors.New("Failed to get write lock"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
