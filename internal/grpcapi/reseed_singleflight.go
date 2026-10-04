package grpcapi

import "sync"

// reseedInFlight admits ONE local reseed at a time in this process.
//
// The durable marker cannot express two overlapping reseeds: reseed_in_progress
// is a single row keyed id=1, so a second BeginReseed REPLACES the first's
// marker, and FinishReseed's generation check then reads "no newer reseed has
// started" — which the newer one satisfies. So the newer reseed finishing first
// cleared the gate while the older was still discarding, and a login admitted
// in that window read an empty user_2fa, derived Requires2FA=false, and saw an
// unchanged generation at mint: a password-only session for an enrolled
// account, which is the exact fail-open the generation exists to prevent, with
// the roles reversed.
//
// Refusing the overlap is better than representing it. A node reseeding itself
// twice at once has no meaning — both discard the same tables — and the
// alternative (a refcount, or in-flight generations as rows) buys the ability
// to do something that should not happen.
//
// PROCESS-LOCAL, deliberately. The only way two reseeds overlap is two
// concurrent ReseedHost calls on one daemon; after a restart there is no
// second goroutine, and the durable marker plus FinishReseed's generation check
// carry the cross-restart case on their own.
type reseedInFlight struct {
	mu     sync.Mutex
	active bool
}

// acquire admits a reseed, returning a release func and true. A second caller
// gets (nil, false) while the first is still running.
func (r *reseedInFlight) acquire() (func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		return nil, false
	}
	r.active = true
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			r.active = false
			r.mu.Unlock()
		})
	}, true
}
