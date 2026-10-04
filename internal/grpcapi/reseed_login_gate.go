package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// preSessionAuthMethods are the skipAuth entries that AUTHENTICATE a caller —
// the ones that take a credential and hand back a session. They bypass the
// interceptor because the caller has no bearer yet, which is correct and also
// means they are the only RPCs that can be reached on a node whose secret
// state is incomplete.
//
// Ping and ListRealms are deliberately NOT here. Ping is how an operator and
// every peer diagnose this node, and the reseed path itself calls it; gating it
// would hide the very condition the marker records and break the recovery it
// points at.
var preSessionAuthMethods = map[string]bool{
	"/litevirt.v1.LiteVirt/Login":               true,
	"/litevirt.v1.LiteVirt/BeginWebAuthnLogin":  true,
	"/litevirt.v1.LiteVirt/FinishWebAuthnLogin": true,
}

// admitPreSessionCredentialExchange decides, from ONE reading of the fence,
// whether a pre-session credential exchange may proceed — and stamps that same
// reading onto the context for the mint to compare against.
//
// One reading, not two, and that is the whole point. The refusal used to read
// the marker and the stamp used to read the generation separately; a reseed
// landing between the two made the stamp capture the POST-reseed generation, so
// the comparison at mintSession found no change. If the reseed had also
// finished by then, `incomplete` was clear again and a 2FA-enrolled account got
// a password-only session — the very race the generation was added to close,
// one layer in. Two reads cannot be ordered into safety; there has to be a
// single observation both halves derive from.
//
// The window this guards is real: a reseed discards the sensitive tables and
// restores them in a LATER step than users and their password hashes, and
// LocalRealm.Authenticate derives Requires2FA from len(factors) > 0, so an empty
// user_2fa reads as "nobody enrolled".
//
// An unreadable fence REFUSES. Returning the context unstamped instead left the
// mint unable to tell "the stamp was dropped" from "this did not come through
// the gate", so it skipped the comparison and fell back to the boolean the
// generation exists precisely because it is insufficient — a transient
// SQLITE_BUSY at the door reopening the whole hole.
//
// Ping and ListRealms are not gated: Ping is how this condition is diagnosed and
// the reseed path itself calls it, so gating it would hide the fault and break
// the recovery it points at.
func (s *Server) admitPreSessionCredentialExchange(ctx context.Context, method string) (context.Context, error) {
	if !preSessionAuthMethods[method] || s.db == nil {
		return ctx, nil
	}
	incomplete, source, generation, err := s.db.ReseedFence(ctx)
	if err != nil {
		return ctx, status.Errorf(codes.Unavailable,
			"cannot confirm this node finished its last reseed, so it will not authenticate: %v", err)
	}
	if incomplete {
		return ctx, status.Errorf(codes.Unavailable,
			"this node is mid-reseed from %s and its secret-bearing state is incomplete, so it "+
				"will not authenticate; repeat the reseed from %s (mTLS admin access still works)",
			source, source)
	}
	return context.WithValue(ctx, reseedFenceKey, generation), nil
}

// reseedFenceKeyType keys the fence reading taken when a pre-session credential
// exchange was admitted, so the mint at the far end can tell whether a reseed
// ran while the credentials were being checked.
type reseedFenceKeyType struct{}

var reseedFenceKey reseedFenceKeyType

// refuseIfReseedMovedSinceEntry refuses to issue a session when a reseed has
// begun — or begun AND finished — since this request was admitted.
//
// This is the other half of the gate, and without it the gate is a TOCTOU. The
// interceptor checks the marker once, before the handler runs; the handler then
// reads the user row, spends a deliberately-slow bcrypt on the password, and
// only THEN reads user_2fa. A request admitted just before a reseed starts
// therefore finishes its bcrypt on the far side of the discard, and
// LocalRealm.Authenticate reads an empty user_2fa as "nobody enrolled" — minting
// a session with no second factor for an enrolled account. The marker stops new
// requests; it cannot drain the ones already inside.
//
// The generation rather than a second read of the marker: an entire reseed can
// start and finish inside one bcrypt, and the boolean would be clear again.
//
// Called from mintSession rather than from Login, so every path that issues a
// session is covered — password login, WebAuthn, and whatever is added next —
// instead of only the one that was audited.
func (s *Server) refuseIfReseedMovedSinceEntry(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	incomplete, source, generation, err := s.db.ReseedFence(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot confirm this node finished its last reseed, so it will not issue a session: %v", err)
	}
	if incomplete {
		return status.Errorf(codes.Unavailable,
			"this node is mid-reseed from %s and its secret-bearing state is incomplete, so it "+
				"will not issue a session; repeat the reseed from %s", source, source)
	}
	entry, ok := ctx.Value(reseedFenceKey).(int64)
	if !ok {
		// No entry reading: this mint did not come through the pre-session gate,
		// so there is nothing to compare. The incomplete check above still holds.
		return nil
	}
	if generation != entry {
		return status.Errorf(codes.Unavailable,
			"a reseed ran while these credentials were being checked, so the second-factor "+
				"state they were checked against may already be gone; retry the login")
	}
	return nil
}
