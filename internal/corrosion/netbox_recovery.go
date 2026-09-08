package corrosion

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ── PERMANENT HOST LOSS: THE ONE PREMISE THAT IS NOT MACHINE-VERIFIED ───────
//
// READ THIS BEFORE CHANGING ANYTHING IN THIS FILE.
//
// Every other premise the NetBox proofs rest on is read off the cluster itself:
// a peer's own membership view, a peer's own digest of the address-bearing
// tables, a runtime scan of a peer's libvirt. Each is a machine checking a
// machine, and a wrong answer is a bug somebody can find.
//
// A row written through this file is different in kind. It is a HUMAN ASSERTION
// standing in for evidence a permanently lost machine can no longer produce, and
// litevirt cannot check it. Recording it — attributed, audited, replicated,
// immutable — makes it reviewable and makes a wrong one traceable to whoever
// made it. RECORDING IT DOES NOT MAKE IT TRUE. Nothing downstream may treat the
// existence of one of these rows as though the fact it asserts had been proved;
// what it does is substitute a named person's judgement for a proof, which is a
// trade an operator is entitled to make about their own cluster and which the
// code must not quietly present as something stronger.
//
// The corollary, and the reason the shapes here are as narrow as they are: an
// attestation must never be able to excuse MORE than the one premise it names.
// See RetirementPremise.

// RetirementPremise is WHICH premise a retirement excuses. There are exactly two
// retirable premises, they are separate, and neither is evidence for the other.
//
// It is a distinct string type, not a bare string, so a call site cannot pass
// "the premise I happen to have in hand" to a reader that wants the other one —
// and every consumer names its premise with a literal of this type at the point
// of use. Collapsing two premises into one permission is the conflation this
// subsystem has now hit three times; keeping them apart is worth a type.
type RetirementPremise string

const (
	// PremiseMembership excuses the obligation to ask THAT HOST which hosts it
	// knew of. It does NOT retire the hosts it could have told us about: those
	// come out of its manifest and stay inputs to discovery, so retiring a
	// source narrows who must answer and never narrows who must be asked.
	PremiseMembership RetirementPremise = "membership"

	// PremiseInventory excuses the obligation to obtain THAT HOST's digest of
	// the address-bearing tables before a bind may go live. It is a SEPARATE
	// premise from membership and is never implied by it: a lost machine's
	// unique VM/NIC/address rows are exactly what an inventory comparison exists
	// to notice, and "we know which hosts it knew" says nothing about them.
	PremiseInventory RetirementPremise = "inventory"
)

// retirablePremises is the closed set. A premise not listed here is not
// retirable — which is how the runtime premise stays non-retirable
// STRUCTURALLY: there is no constant for it, so no row can name it, so no
// reader can find one. Power-off evidence remains the only thing that excuses a
// runtime scan, and it comes from the fencing log.
var retirablePremises = map[RetirementPremise]bool{
	PremiseMembership: true,
	PremiseInventory:  true,
}

// ValidPremise reports whether p is one of the two retirable premises.
//
// It is exported because the gRPC layer must refuse an unknown premise on the
// WIRE rather than write a row nothing will ever read: a retirement for a
// premise no reader recognises is a row an operator believes has excused
// something, and silence is the worst possible answer there.
func ValidPremise(p RetirementPremise) bool { return retirablePremises[p] }

// UnknownIncarnation is the placeholder the daemon records when it cannot read
// its own host certificate (see RegisterHost).
//
// It is REFUSED as an incarnation identity everywhere in this file. It is not an
// identity at all — it is the absence of one — and every host that cannot read
// its certificate records the same string, so a retirement naming it would match
// whichever host later failed to read its own certificate. That is precisely the
// "attaches to whatever answers to the name" failure the incarnation exists to
// prevent, so it fails closed instead.
const UnknownIncarnation = "unknown"

// RecoveryManifest is one immutable record of what an operator established about
// a permanently lost host, for ONE premise.
//
// WHY THE INCARNATION IS hosts.cert_serial, AND NOT THE HOSTNAME OR AN EPOCH.
// The requirement is an identity that a re-admitted machine cannot inherit.
//
//   - The HOSTNAME cannot do it: it is the `hosts` primary key and is meant to
//     be reused. A retirement attached to a name would silently transfer to
//     whatever machine next answered to it, which is the whole failure mode.
//   - cert_serial CAN do it, and is forced to: AdmitHost REFUSES to re-admit a
//     name with the certificate it was removed under ("cannot be re-admitted
//     with its removed certificate"), so a machine re-admitted under the same
//     hostname necessarily presents a DIFFERENT serial. The property is
//     enforced by the admission path rather than hoped for. It is a 128-bit
//     CSPRNG value issued by the cluster CA, it is stable across an ordinary
//     daemon restart (RegisterHost is idempotent), it is replicated on the
//     `hosts` row, tombstones retain it, and it is the value peer mTLS already
//     pins the transport to — so it is not forgeable without the host's private
//     key, unlike a plain counter any writer can bump.
//   - The OWNER EPOCH cannot do it: it is per-WORKLOAD (`vms.vm_owner_epoch`,
//     `containers.owner_epoch`), an ownership generation for one VM or
//     container that TransferVMOwner increments on relocation. It says nothing
//     about a host, does not move when a host is re-admitted, and a host with no
//     workloads has none at all.
//   - `hosts.isolation_epoch` cannot do it either: it counts isolation events,
//     not admissions, so it does not change when a machine is replaced.
//
// The one place cert_serial is WIDER than "this admission" is a bare certificate
// reissue: RegisterHost re-records a live row's serial when the certificate on
// disk has been rotated. That makes a retirement stop matching, which withholds
// — the closure reopens and the operator re-attests against the new serial. It
// is the fail-closed direction, and it is the right one: a serial that moved is
// a serial this retirement was not written about.
type RecoveryManifest struct {
	ID string
	// ClusterFingerprint scopes the record to this installation, so a database
	// restored from another cluster carries no authority here.
	ClusterFingerprint string
	// HostName is RECORD ONLY — for an operator reading the row. Nothing
	// matches on it; see the type comment.
	HostName string
	// HostIncarnation is the lost machine's hosts.cert_serial.
	HostIncarnation string
	Premise         RetirementPremise
	// Accounting is the operator's account, one entry per line.
	//
	// For PremiseMembership these are HOST IDENTITIES the lost machine knew of,
	// and they stay inputs to discovery. For PremiseInventory it is whatever the
	// operator established about the lost machine's unique address-bearing
	// records — NOT machine-checked and deliberately not interpreted here.
	Accounting []string
	AttestedBy string
	AttestedAt string
}

// HostRetirement is one narrow grant: for this cluster, this host incarnation
// and this ONE premise, the proof may rest on the manifest instead of on
// evidence the lost machine can no longer produce.
type HostRetirement struct {
	ClusterFingerprint string
	HostIncarnation    string
	Premise            RetirementPremise
	HostName           string
	ManifestID         string
	AttestedBy         string
	AttestedAt         string
}

// InsertRecoveryManifest records one manifest. APPEND-ONLY: the id is fresh per
// attestation, so superseding an earlier record is a NEW row and the trail keeps
// both. INSERT OR IGNORE because the table is append-only cluster-wide — a
// replayed insert of the same id is the same assertion, not a rewrite.
//
// The caller supplies the id (randid.New()) rather than this deriving one, so
// the retirement written in the same operation can reference it.
func InsertRecoveryManifest(ctx context.Context, c *Client, m RecoveryManifest) error {
	if err := m.validate(); err != nil {
		return err
	}
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO netbox_recovery_manifests
		   (id, cluster_fingerprint, host_name, host_incarnation, premise,
		    accounting, attested_by, attested_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.ClusterFingerprint, m.HostName, m.HostIncarnation, string(m.Premise),
		strings.Join(m.Accounting, "\n"), m.AttestedBy, m.AttestedAt,
		c.NowWall(), c.NowTS())
}

// validate is the fail-closed gate on a manifest. Every branch here is a refusal
// to record something a reader could mistake for an accounting.
func (m RecoveryManifest) validate() error {
	switch {
	case m.ID == "":
		return fmt.Errorf("a recovery manifest needs an id")
	case m.ClusterFingerprint == "":
		return fmt.Errorf("a recovery manifest must name the cluster fingerprint it was attested in")
	case m.HostName == "":
		return fmt.Errorf("a recovery manifest must name the lost host")
	case m.HostIncarnation == "":
		return fmt.Errorf("a recovery manifest must name the lost host's incarnation " +
			"(its recorded certificate serial); a hostname is reusable and cannot identify one")
	case m.HostIncarnation == UnknownIncarnation:
		// See UnknownIncarnation: every host that cannot read its certificate
		// records this same string, so it identifies no incarnation at all.
		return fmt.Errorf("the recorded incarnation for host %q is %q, which is the placeholder "+
			"for a certificate serial that could not be read and identifies no incarnation; "+
			"repair the host record before retiring it", m.HostName, UnknownIncarnation)
	case !ValidPremise(m.Premise):
		return fmt.Errorf("unknown retirement premise %q; a manifest must account for %q or %q",
			m.Premise, PremiseMembership, PremiseInventory)
	case m.AttestedBy == "":
		// An unattributable attestation is the one thing worse than none: it
		// looks like evidence and names nobody who stands behind it.
		return fmt.Errorf("a recovery manifest must record who attested it")
	case m.AttestedAt == "":
		return fmt.Errorf("a recovery manifest must record when it was attested")
	case m.Premise == PremiseInventory && len(m.Accounting) == 0:
		// THE TWO PREMISES DIFFER HERE, deliberately.
		//
		// An INVENTORY accounting is a human account of what became of the lost
		// host's unique address-bearing records, so an empty one is not a claim
		// at all — it is a retirement with nothing behind it, which is the one
		// shape that would make the grant pure ceremony.
		//
		// An empty MEMBERSHIP accounting IS a substantive claim: "the lost host
		// knew of no hosts that the surviving cluster does not already know
		// of", which is the truthful answer for a converged cluster and the
		// commonest one. Requiring a placeholder there would be actively
		// harmful, because every entry in a membership accounting is read as a
		// HOST IDENTITY and folded into discovery — so filler text becomes a
		// phantom host that nothing can ever dial, and the closure it blocks is
		// the one this whole path exists to unblock.
		return fmt.Errorf("an inventory accounting must say what became of the lost host's " +
			"unique address-bearing records; an empty one retires the premise with nothing " +
			"behind it")
	}
	for _, a := range m.Accounting {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("a recovery manifest's accounting must not contain a blank entry")
		}
		if strings.ContainsAny(a, "\n\r") {
			// Entries are newline-separated in the column, so an embedded
			// newline would silently split one entry into two.
			return fmt.Errorf("a recovery manifest accounting entry must not contain a newline: %q", a)
		}
	}
	return nil
}

// InsertHostRetirement records one narrow grant. APPEND-ONLY and keyed
// (cluster_fingerprint, host_incarnation, premise), so re-attesting the same
// premise for the same incarnation is idempotent and can never turn into a
// second, wider grant.
func InsertHostRetirement(ctx context.Context, c *Client, r HostRetirement) error {
	switch {
	case r.ClusterFingerprint == "":
		return fmt.Errorf("a host retirement must name the cluster fingerprint it applies in")
	case r.HostIncarnation == "":
		return fmt.Errorf("a host retirement must name the host incarnation it applies to")
	case r.HostIncarnation == UnknownIncarnation:
		return fmt.Errorf("the recorded incarnation for host %q is %q and identifies no "+
			"incarnation; a retirement naming it would apply to whichever host next failed "+
			"to read its own certificate", r.HostName, UnknownIncarnation)
	case !ValidPremise(r.Premise):
		return fmt.Errorf("unknown retirement premise %q; only %q and %q are retirable, and "+
			"the runtime premise is deliberately not among them — a machine's workloads being "+
			"stopped still requires fencing evidence",
			r.Premise, PremiseMembership, PremiseInventory)
	case r.ManifestID == "":
		return fmt.Errorf("a host retirement must name the manifest that supplied its evidence")
	case r.AttestedBy == "":
		return fmt.Errorf("a host retirement must record who attested it")
	case r.AttestedAt == "":
		return fmt.Errorf("a host retirement must record when it was attested")
	}
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO netbox_host_retirements
		   (cluster_fingerprint, host_incarnation, premise, host_name, manifest_id,
		    attested_by, attested_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ClusterFingerprint, r.HostIncarnation, string(r.Premise), r.HostName,
		r.ManifestID, r.AttestedBy, r.AttestedAt, c.NowWall(), c.NowTS())
}

// ListHostRetirements reads every retirement recorded for ONE premise in ONE
// cluster, keyed by the host incarnation it names.
//
// PREMISE-SCOPED AT THE QUERY, which is deliberate and is the reason there is no
// "list all retirements" accessor: a caller that received every retirement would
// have to filter by premise itself, and a caller that forgot would treat a
// membership grant as an inventory one. The premise is a parameter of the read,
// so the SQL cannot return a premise the caller did not ask for.
//
// The map is keyed on incarnation, not on hostname, for the same reason the
// column exists: a hostname is reusable.
func ListHostRetirements(ctx context.Context, c *Client, fingerprint string,
	premise RetirementPremise) (map[string]HostRetirement, error) {

	if fingerprint == "" {
		return nil, fmt.Errorf("reading retirements requires a cluster fingerprint")
	}
	if !ValidPremise(premise) {
		return nil, fmt.Errorf("unknown retirement premise %q", premise)
	}
	rows, err := c.Query(ctx,
		`SELECT cluster_fingerprint, host_incarnation, premise, host_name, manifest_id,
		        attested_by, attested_at
		   FROM netbox_host_retirements
		  WHERE cluster_fingerprint = ? AND premise = ? AND deleted_at IS NULL`,
		fingerprint, string(premise))
	if err != nil {
		return nil, fmt.Errorf("read host retirements for premise %s: %w", premise, err)
	}
	out := make(map[string]HostRetirement, len(rows))
	for _, r := range rows {
		inc := r.String("host_incarnation")
		if inc == "" || inc == UnknownIncarnation {
			// A row that names no incarnation excuses nothing. Skipped rather
			// than errored: it cannot match any host, so it cannot mislead a
			// reader, and refusing the whole read would let one malformed row
			// block every legitimate retirement.
			continue
		}
		out[inc] = HostRetirement{
			ClusterFingerprint: r.String("cluster_fingerprint"),
			HostIncarnation:    inc,
			Premise:            RetirementPremise(r.String("premise")),
			HostName:           r.String("host_name"),
			ManifestID:         r.String("manifest_id"),
			AttestedBy:         r.String("attested_by"),
			AttestedAt:         r.String("attested_at"),
		}
	}
	return out, nil
}

// RecoveredMembershipIdentities is the UNION of the host identities named by
// every MEMBERSHIP manifest in this cluster, sorted and deduped.
//
// THIS IS THE POINT OF THE MANIFEST. Retiring a source retires the obligation to
// ask THAT HOST; it does not retire the hosts that host could have told us
// about. Those identities come out of here and go straight back into the
// candidate universe, so a permanently lost witness that was the only node able
// to name a third, still-running holder still causes that holder to be asked.
// Drop this from the discovery inputs and the recovery path becomes the bug it
// exists to avoid.
//
// UNIONED ACROSS EVERY MANIFEST, including superseded ones, and that is not
// laziness. More identities means more hosts ASKED, which is the leak direction;
// fewer means a holder goes unqueried, which is the collision direction. So the
// union is monotone in the safe direction and a superseding record can only ever
// widen it. It is also why the manifests table is append-only.
//
// PREMISE-SCOPED: only membership manifests are read. An inventory accounting is
// not a statement about who existed.
//
// It returns BARE NAMES and no roles, deliberately. A role reading is what
// excuses a host from a runtime scan, and an operator's recollection of a role
// is exactly the kind of unverified premise that must not reach that decision.
// Naming a host here can only ever cause it to be QUERIED.
func RecoveredMembershipIdentities(ctx context.Context, c *Client, fingerprint string) ([]string, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("reading recovered membership requires a cluster fingerprint")
	}
	rows, err := c.Query(ctx,
		`SELECT accounting FROM netbox_recovery_manifests
		  WHERE cluster_fingerprint = ? AND premise = ? AND deleted_at IS NULL`,
		fingerprint, string(PremiseMembership))
	if err != nil {
		return nil, fmt.Errorf("read recovered membership manifests: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		for _, name := range strings.Split(r.String("accounting"), "\n") {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ManifestsForIncarnation reads every manifest recorded for ONE host incarnation,
// for the operator-facing listing. Newest attestation first, so a superseded
// record reads as history rather than as the current account.
func ManifestsForIncarnation(ctx context.Context, c *Client, fingerprint, incarnation string) ([]RecoveryManifest, error) {
	if fingerprint == "" || incarnation == "" {
		return nil, fmt.Errorf("reading manifests requires a cluster fingerprint and an incarnation")
	}
	rows, err := c.Query(ctx,
		`SELECT id, cluster_fingerprint, host_name, host_incarnation, premise,
		        accounting, attested_by, attested_at
		   FROM netbox_recovery_manifests
		  WHERE cluster_fingerprint = ? AND host_incarnation = ? AND deleted_at IS NULL`,
		fingerprint, incarnation)
	if err != nil {
		return nil, fmt.Errorf("read manifests for incarnation: %w", err)
	}
	out := make([]RecoveryManifest, 0, len(rows))
	for _, r := range rows {
		var acc []string
		for _, a := range strings.Split(r.String("accounting"), "\n") {
			if a = strings.TrimSpace(a); a != "" {
				acc = append(acc, a)
			}
		}
		out = append(out, RecoveryManifest{
			ID:                 r.String("id"),
			ClusterFingerprint: r.String("cluster_fingerprint"),
			HostName:           r.String("host_name"),
			HostIncarnation:    r.String("host_incarnation"),
			Premise:            RetirementPremise(r.String("premise")),
			Accounting:         acc,
			AttestedBy:         r.String("attested_by"),
			AttestedAt:         r.String("attested_at"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AttestedAt != out[j].AttestedAt {
			return out[i].AttestedAt > out[j].AttestedAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// HostIncarnationOf reads the incarnation currently recorded for a host name —
// its `hosts`.cert_serial — INCLUDING a tombstoned row.
//
// Tombstones included because a permanently lost host is very often one an
// operator has already removed, and `lv host rm` retains the serial precisely so
// the removed certificate cannot be reused. Filtering them out would make the
// retirement unmatchable for the commonest shape of permanent loss.
//
// found=false means no row anywhere records this host. That is NOT an invitation
// to match on the name instead: with no recorded incarnation there is nothing to
// compare a retirement against, so every caller treats it as "the retirement
// cannot be revalidated" and withholds.
func HostIncarnationOf(ctx context.Context, c *Client, host string) (incarnation string, found bool, err error) {
	if host == "" {
		return "", false, fmt.Errorf("reading a host incarnation requires a host name")
	}
	rows, err := c.Query(ctx,
		`SELECT cert_serial FROM hosts WHERE name = ?`, host)
	if err != nil {
		return "", false, fmt.Errorf("read recorded incarnation for host %s: %w", host, err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0].String("cert_serial"), true, nil
}

// ── WITHDRAWING A RETIREMENT: REMOVING TRUST NEEDS NO EVIDENCE ──────────────
//
// READ THIS BEFORE CHANGING THE WITHDRAWAL PATH.
//
// A retirement is an operator's assertion substituted for machine evidence, so
// there has to be a way to take it back — a mistaken attestation would otherwise
// stand indefinitely. Two things about that are easy to get backwards.
//
// RECORDED IS NOT THE SAME AS INACTIVE. The resolver merely SKIPS a grant while
// its host is reachable; it does not durably invalidate it. If that same
// incarnation becomes unreachable again, the stored grant APPLIES AGAIN. A
// dormant grant is a live grant, so withdrawal must work on ANY recorded,
// unwithdrawn grant — active or dormant — with no prerequisite about the host
// being dead, unreachable, or currently matching. Refusing to withdraw a dormant
// grant would block withdrawal in exactly the state that most needs it.
//
// THE ASYMMETRY IS DELIBERATE. GRANTING trust needs evidence: an accounting, an
// exact incarnation, a host that is not answering, a revalidation immediately
// before the write. REMOVING it needs none of that, because every failure mode
// of a withdrawal is a WITHHELD premise — the proof goes back to being owed,
// which is the fail-closed direction. Anything that made withdrawal harder would
// be trading a safe outcome for an unsafe one.
//
// WHAT A WITHDRAWAL DOES NOT DO. It does not establish that the hosts a manifest
// named never existed. Those identities stay inputs to discovery
// (RecoveredMembershipIdentities reads every manifest and asks nothing about
// withdrawal), because naming a host can only ever cause it to be ASKED — the
// leak direction — and dropping them is how withdrawing a source would come to
// hide a still-running holder. It is the same rule that governs retirement
// itself, in the other direction.

// RetirementWithdrawal is one recorded withdrawal of trust in ONE GRANT VERSION.
//
// THE GRANT VERSION IS THE MANIFEST ID. Each attestation mints a fresh manifest
// id, so the manifests recorded for one (cluster, incarnation, premise) are that
// grant's version history — and naming one of them is what lets a withdrawal
// aimed at an earlier version leave a later one alone.
type RetirementWithdrawal struct {
	ClusterFingerprint string
	HostIncarnation    string
	Premise            RetirementPremise
	// ManifestID is the grant version this withdrawal removes trust in.
	ManifestID string
	// HostName is RECORD ONLY — for an operator reading the row.
	HostName    string
	WithdrawnBy string
	WithdrawnAt string
	// Reason is the operator's account of why trust was removed, kept beside the
	// original attestation rather than replacing it.
	Reason string
}

// InsertRetirementWithdrawal records the withdrawal of trust in ONE grant
// version.
//
// A SEPARATE TABLE, NOT ANOTHER RETIREMENT ROW. Inserting "another retirement
// with the same key" as a superseding void record is a SILENT NO-OP —
// netbox_host_retirements is keyed (cluster_fingerprint, host_incarnation,
// premise) and written with INSERT OR IGNORE — so the shape the problem suggests
// does nothing and reports success. And a revocation COLUMN would edit the
// operator's original assertion; withdrawal is an addition to the record.
//
// INSERT OR IGNORE here is not that trap: the key includes the manifest id, so a
// repeat is genuinely the same withdrawal of the same version, which is what
// makes withdrawal IDEMPOTENT rather than an error the second time.
func InsertRetirementWithdrawal(ctx context.Context, c *Client, w RetirementWithdrawal) error {
	switch {
	case w.ClusterFingerprint == "":
		return fmt.Errorf("a retirement withdrawal must name the cluster fingerprint it applies in")
	case w.HostIncarnation == "":
		return fmt.Errorf("a retirement withdrawal must name the host incarnation whose grant " +
			"it withdraws; a hostname is reusable and cannot identify one")
	case w.HostIncarnation == UnknownIncarnation:
		return fmt.Errorf("the incarnation %q is the placeholder for a certificate serial that "+
			"could not be read and identifies no incarnation, so no grant can be keyed to it",
			UnknownIncarnation)
	case !ValidPremise(w.Premise):
		return fmt.Errorf("unknown retirement premise %q; only %q and %q are retirable, so "+
			"only those can be withdrawn", w.Premise, PremiseMembership, PremiseInventory)
	case w.ManifestID == "":
		// Without a version this row would not name WHICH grant it withdraws,
		// and a later re-attestation could not be distinguished from the one
		// being withdrawn.
		return fmt.Errorf("a retirement withdrawal must name the grant version it withdraws " +
			"(the id of the recovery manifest that supplied it)")
	case w.WithdrawnBy == "":
		return fmt.Errorf("a retirement withdrawal must record who withdrew it")
	case w.WithdrawnAt == "":
		return fmt.Errorf("a retirement withdrawal must record when it was withdrawn")
	case strings.TrimSpace(w.Reason) == "":
		// Not a gate on the withdrawal — it is the reviewable half. The original
		// attestation records who asserted what and why; this records who took
		// it back and why, and a blank one leaves the trail saying only that
		// somebody did.
		return fmt.Errorf("a retirement withdrawal must record why trust was removed")
	}
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO netbox_retirement_withdrawals
		   (cluster_fingerprint, host_incarnation, premise, manifest_id, host_name,
		    withdrawn_by, withdrawn_at, reason, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ClusterFingerprint, w.HostIncarnation, string(w.Premise), w.ManifestID, w.HostName,
		w.WithdrawnBy, w.WithdrawnAt, w.Reason, c.NowWall(), c.NowTS())
}

// GrantVersionsFor is the manifest ids recorded for ONE premise in ONE cluster,
// keyed by host incarnation — each grant's VERSION HISTORY.
//
// One query for the whole premise rather than one per candidate, because the
// resolver runs this on every proof pass.
//
// PREMISE-SCOPED AT THE QUERY, for the reason every read of these tables is: a
// caller that received both premises' versions would have to filter, and a
// caller that forgot would treat a membership attestation as an inventory one.
func GrantVersionsFor(ctx context.Context, c *Client, fingerprint string,
	premise RetirementPremise) (map[string][]string, error) {

	if fingerprint == "" {
		return nil, fmt.Errorf("reading grant versions requires a cluster fingerprint")
	}
	if !ValidPremise(premise) {
		return nil, fmt.Errorf("unknown retirement premise %q", premise)
	}
	rows, err := c.Query(ctx,
		`SELECT host_incarnation, id FROM netbox_recovery_manifests
		  WHERE cluster_fingerprint = ? AND premise = ? AND deleted_at IS NULL`,
		fingerprint, string(premise))
	if err != nil {
		return nil, fmt.Errorf("read %s grant versions: %w", premise, err)
	}
	out := map[string][]string{}
	for _, r := range rows {
		inc, id := r.String("host_incarnation"), r.String("id")
		if inc == "" || id == "" {
			continue
		}
		out[inc] = append(out[inc], id)
	}
	for _, ids := range out {
		sort.Strings(ids)
	}
	return out, nil
}

// RetirementWithdrawals is the withdrawal state for ONE premise in ONE cluster:
// which grant versions have had trust removed, and which versions each grant
// currently rests on.
//
// It is a TYPE rather than two maps a caller compares, because the predicate is
// the whole subtlety and there must be exactly one copy of it. See Withdrawn.
type RetirementWithdrawals struct {
	// byIncarnation is incarnation → manifest id → the withdrawal record.
	byIncarnation map[string]map[string]RetirementWithdrawal
	// versions is incarnation → the manifest ids the grant rests on.
	versions map[string][]string
}

// Withdrawn reports whether the grant recorded for this incarnation has had
// trust removed from EVERY version it rests on.
//
// THIS IS THE PREDICATE, and both halves of it are load-bearing:
//
//  1. AT LEAST ONE WITHDRAWAL EXISTS. Without this the "every version is
//     withdrawn" test would be vacuously true for a grant with no manifest rows
//     visible yet, and an ordinary replication skew would read as a withdrawal.
//  2. EVERY RECORDED VERSION IS COVERED. A grant resting on a version nothing
//     has withdrawn still rests on a live human attestation, so it applies. That
//     is what makes a withdrawal unable to cancel a NEWER attestation: a
//     re-attestation mints a fresh manifest id, no withdrawal names it, and the
//     grant comes back on the strength of that record rather than of the one
//     that was withdrawn.
//
// THE DISCRIMINATOR IS AN IDENTITY, NEVER A CLOCK. A delayed or re-delivered
// copy of the old grant carries the manifest id it always had, so it is still
// covered and cannot resurrect anything; a genuinely new attestation carries an
// id no withdrawal names. Nothing here compares timestamps, so no clock skew and
// no replay ordering can flip the answer.
func (w RetirementWithdrawals) Withdrawn(incarnation string) bool {
	withdrawn := w.byIncarnation[incarnation]
	if len(withdrawn) == 0 {
		return false
	}
	for _, id := range w.versions[incarnation] {
		if _, ok := withdrawn[id]; !ok {
			return false
		}
	}
	return true
}

// Records is the withdrawals recorded for one incarnation, newest first, for the
// operator-facing listing. Present whether or not the grant is fully withdrawn:
// a withdrawal that a later attestation out-ran must still be visible, or the
// operator who made it would see their decision silently swallowed.
func (w RetirementWithdrawals) Records(incarnation string) []RetirementWithdrawal {
	out := make([]RetirementWithdrawal, 0, len(w.byIncarnation[incarnation]))
	for _, rec := range w.byIncarnation[incarnation] {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WithdrawnAt != out[j].WithdrawnAt {
			return out[i].WithdrawnAt > out[j].WithdrawnAt
		}
		return out[i].ManifestID < out[j].ManifestID
	})
	return out
}

// Versions is the grant versions recorded for one incarnation, sorted.
func (w RetirementWithdrawals) Versions(incarnation string) []string {
	return append([]string(nil), w.versions[incarnation]...)
}

// UnwithdrawnVersions is the grant versions this incarnation rests on that NO
// withdrawal names — the versions keeping a grant in force after a withdrawal.
//
// It exists so the withdrawal path and the listing can SAY which record a grant
// is still resting on. A withdrawal that a concurrent re-attestation out-ran
// must not be silently swallowed, and naming the version that beat it is what
// makes the outcome reviewable instead of mysterious.
func (w RetirementWithdrawals) UnwithdrawnVersions(incarnation string) []string {
	withdrawn := w.byIncarnation[incarnation]
	var out []string
	for _, id := range w.versions[incarnation] {
		if _, ok := withdrawn[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

// LoadRetirementWithdrawals reads the withdrawal state for ONE premise.
//
// TOMBSTONES ARE NOT FILTERED, deliberately, and this is the one read in the
// subsystem that does not filter them. A withdrawal removes trust; letting a
// `deleted_at` on the withdrawal row put a grant back into force would make
// deleting a row a way to RESTORE trust, which is the fail-open direction and
// the one thing this table must not permit. Restoring trust takes a fresh
// attestation under a new grant version, which is a positive act by a named
// person — not the disappearance of a row.
func LoadRetirementWithdrawals(ctx context.Context, c *Client, fingerprint string,
	premise RetirementPremise) (RetirementWithdrawals, error) {

	out := RetirementWithdrawals{byIncarnation: map[string]map[string]RetirementWithdrawal{}}
	if fingerprint == "" {
		return out, fmt.Errorf("reading retirement withdrawals requires a cluster fingerprint")
	}
	if !ValidPremise(premise) {
		return out, fmt.Errorf("unknown retirement premise %q", premise)
	}
	rows, err := c.Query(ctx,
		`SELECT cluster_fingerprint, host_incarnation, premise, manifest_id, host_name,
		        withdrawn_by, withdrawn_at, reason
		   FROM netbox_retirement_withdrawals
		  WHERE cluster_fingerprint = ? AND premise = ?`,
		fingerprint, string(premise))
	if err != nil {
		return out, fmt.Errorf("read %s retirement withdrawals: %w", premise, err)
	}
	for _, r := range rows {
		inc, id := r.String("host_incarnation"), r.String("manifest_id")
		if inc == "" || inc == UnknownIncarnation || id == "" {
			// Names no grant version, so it withdraws nothing. Skipped rather
			// than errored, for the same reason ListHostRetirements skips a row
			// with no incarnation: one malformed row must not block every
			// legitimate withdrawal.
			continue
		}
		if out.byIncarnation[inc] == nil {
			out.byIncarnation[inc] = map[string]RetirementWithdrawal{}
		}
		out.byIncarnation[inc][id] = RetirementWithdrawal{
			ClusterFingerprint: r.String("cluster_fingerprint"),
			HostIncarnation:    inc,
			Premise:            RetirementPremise(r.String("premise")),
			ManifestID:         id,
			HostName:           r.String("host_name"),
			WithdrawnBy:        r.String("withdrawn_by"),
			WithdrawnAt:        r.String("withdrawn_at"),
			Reason:             r.String("reason"),
		}
	}
	versions, err := GrantVersionsFor(ctx, c, fingerprint, premise)
	if err != nil {
		return RetirementWithdrawals{byIncarnation: map[string]map[string]RetirementWithdrawal{}}, err
	}
	out.versions = versions
	return out, nil
}
