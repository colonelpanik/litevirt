// Package capabilities defines the named split-brain-hardening feature tokens a
// daemon advertises via PingResponse.capabilities, and the set THIS build
// supports.
//
// Tokens gate fail-closed safety checks. A check activates (starts refusing, and
// for the proof table starts WAL-replicating to that peer) ONLY once every
// enforcement-relevant member advertises its token — read via a fresh peer Ping,
// never from stale replicated rows and never from schema_version (too coarse;
// unchanged by a schema-neutral phase). Activation is recomputed from fresh Pings;
// once confirmed cluster-wide it LATCHES durably (per token, via a marker file), so
// a later partition — where support can't be re-confirmed — fails closed rather
// than reverting to the legacy ungated path.
package capabilities

const (
	// SplitBrainGateV1 gates the composable dangerous-action gate (Phase 1): both
	// the use of the non-LWW runtime_action_proofs table AND enforcement of the
	// quorum/proof gate. WAL relay of proof mutations is suppressed per-peer to any
	// node not advertising this token; the peer-only sensitive anti-entropy lane
	// additionally carries proofs as a convergence net. Both apply the bespoke
	// MONOTONE merge (any node holding the table ships that resolver in the same v38
	// binary), so single-use can't be broken by an ordinary-LWW apply.
	SplitBrainGateV1 = "split_brain_gate_v1"
	// VIPDemoteV1 is the MINORITY-side Phase-2 token: this node can confirmed-stop keepalived
	// and remove/verify its own VIP locally on quorum loss. A SOFTWARE capability: no hardware
	// watchdog is required to advertise it or to self-demote — the watchdog is only an
	// OPTIONAL self-fence backstop for the corner where a demote can't be confirmed.
	VIPDemoteV1 = "vip_demote_v1"
	// VIPReleaseProbeV1 is the MAJORITY-side Phase-2 trust token: this node answers by-VIP
	// participant/absence probes (CheckVIPParticipant, direct or relayed) AUTHORITATIVELY, so
	// peers may trust its "not claiming" answer as a release proof when reclaiming a VIP. A node
	// may advertise one of {VIPDemoteV1, VIPReleaseProbeV1} without the other; the two flip
	// together as the Phase-2 pair. Also a software capability (no watchdog).
	VIPReleaseProbeV1 = "vip_release_probe_v1"
	// FenceEpochV1 gates Phase-5 fence-epoch staleness enforcement.
	FenceEpochV1 = "fence_epoch_v1"
	// OwnerEpochV1 gates Phase-5 enforcement, advertised only after Phase-4 backfill.
	OwnerEpochV1 = "owner_epoch_v1"
	// SafeFenceDefaultV1 gates the safe-fencing-default policy: once enforced
	// cluster-wide, an UNCONFIRMED best-effort fence is no longer treated as proof
	// of power-off — the coordinator requires an operator fence-confirm before
	// rescheduling (as it already does for the "manual" strategy), unless the host
	// explicitly opts into legacy proceed-anyway via LabelUnsafeAutoFailover. Gated
	// (not unconditional) because it changes live failover behavior, so a
	// mixed-version cluster must not flip mid-roll.
	SafeFenceDefaultV1 = "safe_fence_default_v1"
	// LWWSkewGuardV1 gates FUTURE-SKEW QUARANTINE for LWW merges (partial): once
	// enforced cluster-wide, an incoming row whose updated_at is beyond MaxSkew into
	// the future is quarantined (kept-local) rather than allowed to win, so a
	// fast-clock peer can't dominate last-writer-wins. Gated because a mixed-version
	// cluster must not start quarantining before every node enforces it.
	//
	// SCOPE — this is NOT a full HLC LWW fix. updated_at is STILL stamped from
	// per-process wall-clock RFC3339 (see corrosion.Client.NowTS), so this token does
	// NOT address the BACKWARD-clock case (a restart after a wall-clock step-back can
	// still emit older conflict keys → lost updates). Do not flip this thinking
	// split-brain item 2 is fully solved. The remaining work — persist the monotonic
	// timestamp high-water and/or emit HLC (a separately-validated conflict-key
	// migration) — is deliberately deferred to its own token, so this one is named for
	// exactly what it does (skew guard), leaving "hlc_lww_v1" free for the real flip.
	LWWSkewGuardV1 = "lww_skew_guard_v1"
	// StrictMTLSIdentityV1 gates the strict mTLS-identity auth model: a bearerless
	// client certificate (a distributable lv-cli cert, an unknown/empty CN, or a
	// removed host's CN) is no longer treated as admin — it must present a session
	// bearer. Peer (known-host) and on-node loopback certs keep admin authority, so
	// NO node-to-node wire behavior changes. Unlike the split-brain tokens this gates
	// an AUTH decision, so it deliberately does NOT rely on the hard fail-closed latch
	// for recovery: the daemon config flag auth.strict_mtls_identity is the real
	// enforcement switch (enforcement is config AND Enforced) and kill switch, and the
	// loopback local-root path is never gated — so a mis-flip is reversible and can
	// never lock out on-node root.
	//
	// ADVERTISED (in `supported`), enforcement default-off: this build advertises the
	// token so the cluster can latch it, but enforcement stays inert until an operator
	// sets auth.strict_mtls_identity — enforcement is config AND the latch, so a deploy
	// is behavior-neutral and the config flag is the reversible kill switch.
	StrictMTLSIdentityV1 = "strict_mtls_identity_v1"
	// ForwardedIdentityV1 gates the owner-side promotion of a forwarded user
	// identity. An entry node propagates the caller's session bearer to the owning
	// node in x-litevirt-fwd-bearer (send-side is ungated + forward-compatible);
	// once this token is enforced, the owner re-authenticates that bearer and runs
	// RBAC + audit as the REAL user instead of the peer=admin trusted-forward. A
	// forward with no bearer (a system continuation off a background context) stays
	// peer=admin/system. Owner-side validation is fail-closed: a session/user not
	// yet replicated → Unavailable (retryable), not silent admin. Config-gated
	// (auth.forwarded_identity) + reversible like StrictMTLSIdentityV1.
	//
	// ADVERTISED (in `supported`), enforcement default-off (see StrictMTLSIdentityV1) —
	// inert until auth.forwarded_identity is set. (The send-side bearer relay is always
	// on but forward-compatible: with enforcement off, no owner promotes, so the relayed
	// header is ignored.)
	ForwardedIdentityV1 = "forwarded_identity_v1"
)

// supported is the set of tokens THIS build both implements AND advertises. A
// token is added here only once its machinery is fully wired, so cluster-wide
// activation of a fail-closed check can never precede a node's ability to honor it.
// (Phases 4/5 will append the epoch tokens.)
//
// ALL currently-implemented tokens are now ADVERTISED. SplitBrainGateV1 has no kill
// switch (it flips via advertisement alone); every OTHER token is gated `configFlag &&
// latch` (enforcement.* / auth.*), so advertising it is behavior-neutral until an
// operator sets its flag — the flip is decoupled from enablement. Enforcement of any
// token still activates only once every enforcement-relevant member advertises it
// (fresh Ping) and it latches per node.
//
//   - Phase 1 (SplitBrainGateV1) — FLIPPED (no config flag): the composable dangerous-action gate. Machinery +
//     activation-hardening in place and tested — full proof carried+validated for
//     promote/ApplyLB/restore, relocation token-bound proof, promote crash-idempotent
//     step resume, token-gated per-peer WAL proof replication PLUS a peer-only
//     sensitive anti-entropy convergence net (both monotone-merged), mint sites that
//     fresh-Ping the destination before stamping, marker presence forcing BOTH the
//     ExecutionGate and proof validation at execute sites, and a per-token durable
//     activation LATCH (partition fails closed, never reverts to legacy).
//   - Phase 2 (VIPDemoteV1 + VIPReleaseProbeV1) — ADVERTISED, enforcement default-off (gated by
//     enforcement.vip_self_demote / enforcement.vip_proof_reclaim): minority VIP self-demotion + majority
//     proof-gated reclaim, DECOUPLED from the watchdog. VIPDemoteV1 (minority): an isolated
//     (quorum-lost) LB host stops keepalived + removes its own VIP address — WITHOUT a
//     hardware watchdog. VIPReleaseProbeV1 (majority trust): peers reclaim a VIP only on a
//     release proof — a by-VIP absence answer (direct CheckVIPParticipant or relayed) trusted
//     ONLY from a host advertising this token. A watchdog is an OPTIONAL backstop for one
//     corner: if the demote can't be CONFIRMED and a verified watchdog is armed the node
//     self-fences; if there's no verified self-fence it keeps retrying + raises HA-degraded,
//     and the majority stays in the safe gap (no reclaim without a release/fence proof — a
//     VIP outage, not a takeover). Warmup never demotes; a
//     sub-threshold blip never demotes (monotonic hysteresis); the startup-validated
//     timing invariant keeps the isolated side finishing before any majority reclaim.
//     Covers the daemon-alive gossip-partition case. DOCUMENTED GAPS (per plan, tied to
//     later phases): automatic majority reclaim across an UNREACHABLE holder needs a
//     real fence proof OR a verified absence proof (later phases) — until then it's an
//     intentional availability degradation (VIP down + alert), and a data-plane-only
//     partition (gRPC/gossip healthy but VRRP split) needs a VIP-conflict detector
//     (Phase-6 follow-up).
//
// Advertising is done for all implemented tokens; ENABLING each (setting its config
// flag in prod) is the staged step, gated per token on its own ephemeral-partition
// validation. Once advertised, enforcement activates only after EVERY
// enforcement-relevant member advertises it (fresh Ping), it latches, AND the config
// flag is on.
// OPERATOR NOTE: with the gate enforced, a 2-worker cluster with NO witness refuses
// automated failover (even-worker + no-witness blocks HA — deliberate); add a witness or
// accept the trade-off. Validate on an ephemeral partition before flipping in prod.
//
// DE-ADVERTISING IS NOT A KILL SWITCH once a node has latched. Removing the token
// from `supported` stops NEW activation, but Enforced() first honors the durable
// per-token marker (<dataDir>/split_brain_activated.<token>) and returns true from
// it before consulting current advertised support — the whole point of the
// fail-closed latch (a partition mustn't silently re-open the legacy path).
//
// KILL SWITCH (the modern way — DO NOT delete marker files): every flippable token
// EXCEPT split_brain_gate_v1 is gated `configFlag && Enforced/Latched` at its
// decision site (auth.strict_mtls_identity/forwarded_identity, and
// enforcement.{safe_fence_default,lww_skew_guard,vip_self_demote,vip_proof_reclaim}).
// The config flag is authoritative for enforcement AND recovery: set it false +
// restart and enforcement stops regardless of the latch marker. Deleting a marker
// file to "stand down" is retired — it confuses the state machine (the HA monitor
// re-establishes the latch while the flag is on and the cluster is healthy). Only
// split_brain_gate_v1 has no config flag; for it, marker deletion remains the sole
// stand-down (it flips via `supported` alone).
var supported = []string{
	SplitBrainGateV1,
	// Advertised so the cluster can latch these; enforcement stays inert until the
	// matching config kill-switch is set true (see EnforcementConfig / AuthConfig).
	// Advertising a token means "this build SUPPORTS the feature", NOT "this node is
	// currently enforcing it".
	SafeFenceDefaultV1,
	LWWSkewGuardV1,
	VIPDemoteV1,
	VIPReleaseProbeV1,
	StrictMTLSIdentityV1,
	ForwardedIdentityV1,
}

// all is every capability token litevirt knows about (across phases), regardless
// of whether THIS build advertises it. Used to pre-load per-token durable
// activation latches at startup.
var all = []string{SplitBrainGateV1, VIPDemoteV1, VIPReleaseProbeV1, FenceEpochV1, OwnerEpochV1, SafeFenceDefaultV1, LWWSkewGuardV1, StrictMTLSIdentityV1, ForwardedIdentityV1}

// All returns a copy of every known capability token (all phases).
func All() []string {
	return append([]string(nil), all...)
}

// Supported returns a copy of the tokens this build advertises.
func Supported() []string {
	return append([]string(nil), supported...)
}

// Has reports whether tokens contains want.
func Has(tokens []string, want string) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}
