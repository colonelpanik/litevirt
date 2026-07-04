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
)

// supported is the set of tokens THIS build both implements AND advertises. A
// token is added here only once its machinery is fully wired, so cluster-wide
// activation of a fail-closed check can never precede a node's ability to honor
// it. (Phase 2 appends the pair VIPDemoteV1 + VIPReleaseProbeV1; Phases 4/5 append the
// epoch tokens.)
//
// Phase 1's SplitBrainGateV1 is now ADVERTISED (the Phase-1 flip, validated on an ephemeral
// partition first); Phase 2's tokens are NOT yet. So Phase-1 enforcement activates once every
// enforcement-relevant member advertises the token (fresh Ping) and then latches per node,
// while Phase 2 stays inert (its tokens de-advertised):
//
//   - Phase 1 (SplitBrainGateV1) — FLIPPED: the composable dangerous-action gate. Machinery +
//     activation-hardening in place and tested — full proof carried+validated for
//     promote/ApplyLB/restore, relocation token-bound proof, promote crash-idempotent
//     step resume, token-gated per-peer WAL proof replication PLUS a peer-only
//     sensitive anti-entropy convergence net (both monotone-merged), mint sites that
//     fresh-Ping the destination before stamping, marker presence forcing BOTH the
//     ExecutionGate and proof validation at execute sites, and a per-token durable
//     activation LATCH (partition fails closed, never reverts to legacy).
//   - Phase 2 (VIPDemoteV1 + VIPReleaseProbeV1) — NOT yet flipped: minority VIP self-demotion + majority
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
// Each flip is a one-line change: add the token(s) to `supported`. Phase 1 is DONE
// (SplitBrainGateV1 above); the Phase-2 flip appends VIPDemoteV1 + VIPReleaseProbeV1 after
// their own ephemeral-partition validation. Once advertised, enforcement activates only
// after EVERY enforcement-relevant member advertises it (fresh Ping) and then latches.
// OPERATOR NOTE: with the gate enforced, a 2-worker cluster with NO witness refuses
// automated failover (even-worker + no-witness blocks HA — deliberate); add a witness or
// accept the trade-off. Validate on an ephemeral partition before flipping in prod.
//
// DE-ADVERTISING IS NOT A KILL SWITCH once a node has latched. Removing the token
// from `supported` stops NEW activation, but Enforced() first honors the durable
// per-token marker (<dataDir>/split_brain_activated.<token>) and returns true from
// it before consulting current advertised support — the whole point of the
// fail-closed latch (a partition mustn't silently re-open the legacy path). So on a
// data dir where the token was EVER latched, a build with empty `supported` still
// enforces. To truly stand a latched node down, delete its marker file(s) as well.
// (This is now LIVE for split_brain_gate_v1: once a node latches it, de-advertising alone
// won't revert it — delete <dataDir>/split_brain_activated.split_brain_gate_v1 to stand it
// down. Still inert for the Phase-2 tokens, which no shipped build advertises yet.)
var supported = []string{SplitBrainGateV1}

// all is every capability token litevirt knows about (across phases), regardless
// of whether THIS build advertises it. Used to pre-load per-token durable
// activation latches at startup.
var all = []string{SplitBrainGateV1, VIPDemoteV1, VIPReleaseProbeV1, FenceEpochV1, OwnerEpochV1}

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
