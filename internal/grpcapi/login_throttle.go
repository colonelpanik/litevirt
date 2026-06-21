package grpcapi

import (
	"sync"
	"time"
)

// Brute-force lockout defaults. A lockout is per (username, client-IP) so a
// single attacker IP can't grind one account, and a single account can't be
// locked cluster-wide from one IP (the IP dimension keeps a shared-NAT office
// from locking everyone). State is in-memory and per-node — an attacker who
// can spread guesses across every node in the cluster gets maxFailures tries
// per node, which is an acceptable trade for not needing a replicated counter
// on the hot login path. The window resets on any successful login.
const (
	defaultLoginMaxFailures = 5
	defaultLoginWindow      = 15 * time.Minute // failures older than this are forgotten
	defaultLoginLockout     = 15 * time.Minute // how long a tripped key stays locked
)

// loginThrottle is an in-memory failed-login counter with lockout. Safe for
// concurrent use. A nil *loginThrottle is a no-op (tests that don't wire one
// see unthrottled behaviour).
type loginThrottle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry

	maxFailures int
	window      time.Duration
	lockout     time.Duration

	// now is a clock seam for tests; nil means time.Now.
	now func() time.Time
}

type throttleEntry struct {
	failures    int
	firstFail   time.Time
	lockedUntil time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		entries:     make(map[string]*throttleEntry),
		maxFailures: defaultLoginMaxFailures,
		window:      defaultLoginWindow,
		lockout:     defaultLoginLockout,
	}
}

func (t *loginThrottle) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// retryAfter returns how long the key must wait before another attempt is
// allowed, or 0 if attempts are currently permitted. A locked key whose
// lockout has expired is reset here so the next failure starts a fresh window.
func (t *loginThrottle) retryAfter(key string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[key]
	if e == nil {
		return 0
	}
	now := t.clock()
	if !e.lockedUntil.IsZero() {
		if now.Before(e.lockedUntil) {
			return e.lockedUntil.Sub(now)
		}
		// Lockout elapsed — forget the entry entirely.
		delete(t.entries, key)
		return 0
	}
	// Not locked, but drop a stale failure window so old failures don't
	// accumulate forever.
	if now.Sub(e.firstFail) > t.window {
		delete(t.entries, key)
	}
	return 0
}

// fail records a failed attempt and trips the lockout when the threshold is
// reached. Returns the lockout duration if this failure tripped it, else 0.
func (t *loginThrottle) fail(key string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	e := t.entries[key]
	if e == nil || now.Sub(e.firstFail) > t.window {
		e = &throttleEntry{firstFail: now}
		t.entries[key] = e
	}
	e.failures++
	if e.failures >= t.maxFailures {
		e.lockedUntil = now.Add(t.lockout)
		return t.lockout
	}
	return 0
}

// success clears any failure state for the key.
func (t *loginThrottle) success(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}
