package libvirt

import (
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// IsNotFound classifies a libvirt error as "the object does not exist", so callers
// can treat a delete/lookup of an already-gone domain, snapshot, or checkpoint as
// success instead of conflating it with a real fault.
//
// Typed go-libvirt error codes are authoritative and checked first. The substring
// fallback exists because litevirt wraps several libvirt calls with its own text
// (e.g. snapshot.go's `snapshot %q not found: %w`), and because some paths surface
// a message-only error with no code attached — a typed-only check would regress
// those callers.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(golibvirt.Error); ok {
		switch e.Code {
		case uint32(golibvirt.ErrNoDomainCheckpoint),
			uint32(golibvirt.ErrNoDomain),
			uint32(golibvirt.ErrNoDomainSnapshot):
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no domain checkpoint") ||
		strings.Contains(msg, "no domain snapshot") ||
		strings.Contains(msg, "cannot find")
}
