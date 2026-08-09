// Package randid generates the short random identifiers litevirt uses as
// primary keys for replicated rows — audit entries, firewall and
// security-group rules, notification targets and routes, reservations,
// scheduler proposals, relocation tokens.
//
// The format is raw random bytes hex-encoded rather than a UUID, to keep ids
// short in CLI output. It is zero-dependency (stdlib only) so any package can
// import it without risking an import cycle. It replaces eight byte-identical
// per-package generators (failover.newID, grpcapi.newID, grpcapi.generateID,
// grpcapi.newNotifyID, scheduler.newID, health.ownerAssertID, ui.newUIID, and
// main.newID in cmd/litevirt/sg.go, which originated the scheme) that had
// drifted into two different crypto/rand error policies.
package randid

import (
	"crypto/rand"
	"encoding/hex"
)

// Bytes is the number of random bytes behind one ID. Do not change it: every
// ID this package has ever produced is a primary key in a replicated
// Corrosion table, and shrinking it raises the collision probability for rows
// that already exist. 8 bytes = 64 bits of entropy = 16 hex characters.
const Bytes = 8

// New returns Bytes cryptographically random bytes, hex-encoded — 16 lowercase
// hex characters.
//
// It returns no error, and that is deliberate. As of Go 1.24 crypto/rand.Read
// "never returns an error, and always fills b entirely"; it crashes the program
// irrecoverably if the system entropy source fails. There is therefore no
// caller-visible failure to report, and an error return would be unreachable
// code. Do not add one back: the previous error-returning variant only ever
// produced an empty string that callers inserted as a primary key.
func New() string {
	b := make([]byte, Bytes)
	_, _ = rand.Read(b) // cannot fail; see the doc comment
	return hex.EncodeToString(b)
}
