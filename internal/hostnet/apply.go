package hostnet

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// System abstracts every host-touching action the apply protocol performs, so
// the protocol itself — ordering, refusals, rollback, journal discipline — is
// deterministic and testable with a fake. The real implementation (netplan
// exec, /etc/netplan IO, live ip/route state) lives in system_linux.go and is
// proven on the lab, not in unit tests.
type System interface {
	// NetplanAvailable reports whether this host can be managed at all
	// (netplan binary + /etc/netplan present). Non-netplan hosts refuse —
	// never fall back to imperative commands.
	NetplanAvailable() error
	// ReadManagedFile returns ManagedFile's content and whether it exists.
	ReadManagedFile() (string, bool, error)
	// WriteManagedFile atomically replaces ManagedFile.
	WriteManagedFile(content string) error
	// RemoveManagedFile deletes ManagedFile (restore of "didn't exist yet").
	RemoveManagedFile() error
	// ForeignFiles returns every OTHER netplan file (path → content).
	ForeignFiles() (map[string]string, error)
	// ClusterInterface resolves which interface currently carries ip
	// ('' when not found — the guards then run in reduced mode).
	ClusterInterface(ip string) (string, error)
	// ApplyWithRevert applies the currently written config behind a revert
	// window (`netplan try --timeout=…`: the kernel-side revert fires even if
	// this daemon dies mid-window), calls confirm while the window is open,
	// and accepts only when confirm returns nil. It reports whether the new
	// config was accepted; !accepted with a nil error means the confirm
	// failed and the runtime config was reverted.
	ApplyWithRevert(ctx context.Context, window time.Duration, confirm func(context.Context) error) (accepted bool, err error)
	// ConfirmConnectivity is the mechanical post-apply check: the cluster
	// address is still assigned, the default gateway (if there was one) still
	// answers, and this daemon's own gRPC listener accepts a local dial. It is
	// deliberately local — an operator who just lost SSH cannot click anything.
	ConfirmConnectivity(ctx context.Context) error
}

// Applier drives the journaled apply protocol for ONE host's intent rows.
type Applier struct {
	DB          *corrosion.Client
	HostName    string
	AdvertiseIP string
	Journal     *opjournal.Journal
	Sys         System
	// RevertWindow bounds how long a bad config can be live before the
	// kernel-side revert fires. Defaulted by Apply when zero.
	RevertWindow time.Duration
}

const (
	defaultRevertWindow = 30 * time.Second
	// journalKind marks host-network apply entries in the shared host-local
	// journal; recovery dispatches on it.
	journalKind = "host_network_apply"
	// artifact keys inside the journal entry.
	artPrevFile   = "prev_file"
	artPrevExists = "prev_exists"
	artRendered   = "rendered"
)

func (a *Applier) journalID() string { return "hostnet-apply-" + a.HostName }

// Plan renders the desired file, diffs it against the current one, and runs
// every refusal detector. It writes NOTHING — the RPC exposes it verbatim so
// the UI's plan-then-confirm flow shows exactly what apply would do.
type Plan struct {
	Rows     []corrosion.HostNetworkRecord
	Rendered string
	Current  string
	// NoOp is true when the rendered file already matches the current one.
	NoOp bool
	// CutoffReason is non-empty when the plan risks disconnecting this node
	// from the cluster; apply refuses it without force naming ClusterIface.
	CutoffReason string
	ClusterIface string
	// Conflicts maps a planned interface to the foreign netplan file that
	// already defines it. Any entry refuses the apply outright (no force).
	Conflicts map[string]string
	// currentExists distinguishes an empty ManagedFile from an absent one —
	// the restore path must know whether to write back '' or remove.
	currentExists bool
}

func (a *Applier) Plan(ctx context.Context) (*Plan, error) {
	if err := a.Sys.NetplanAvailable(); err != nil {
		return nil, fmt.Errorf("this host cannot be netplan-managed: %w", err)
	}
	rows, err := corrosion.ListHostNetworks(ctx, a.DB, a.HostName)
	if err != nil {
		return nil, err
	}
	rendered, err := Render(rows)
	if err != nil {
		return nil, err
	}
	current, exists, err := a.Sys.ReadManagedFile()
	if err != nil {
		return nil, err
	}
	foreign, err := a.Sys.ForeignFiles()
	if err != nil {
		return nil, err
	}
	clusterIface, err := a.Sys.ClusterInterface(a.AdvertiseIP)
	if err != nil {
		return nil, err
	}
	reason, _ := SelfCutoffRisk(rows, clusterIface, a.AdvertiseIP)
	return &Plan{
		Rows:          rows,
		Rendered:      rendered,
		Current:       current,
		NoOp:          exists && current == rendered,
		CutoffReason:  reason,
		ClusterIface:  clusterIface,
		Conflicts:     ForeignConflicts(rows, foreign),
		currentExists: exists,
	}, nil
}

// Apply drives one plan to a terminal outcome. force must name the cluster
// interface (” = no force): a cutoff-risk plan applies only when the caller
// explicitly wrote down which interface they are about to touch — a
// confirmation, not a flag.
//
// The ordering is the protocol's whole point:
//
//	refusals → rows 'applying' → JOURNAL (durable, with the snapshot) →
//	write file → apply-with-revert + confirm → commit | restore
//
// The journal precedes the file write, so there is no instant at which the
// host's config has changed without a durable record of how to put it back.
func (a *Applier) Apply(ctx context.Context, force string) error {
	plan, err := a.Plan(ctx)
	if err != nil {
		return err
	}
	if len(plan.Conflicts) > 0 {
		return fmt.Errorf("refusing: %s", describeConflicts(plan.Conflicts))
	}
	if plan.CutoffReason != "" {
		if force == "" {
			return fmt.Errorf("refusing: %s (re-run forcing interface %q to confirm)",
				plan.CutoffReason, plan.ClusterIface)
		}
		if force != plan.ClusterIface {
			return fmt.Errorf("refusing: %s (force names %q, but the cluster interface is %q)",
				plan.CutoffReason, force, plan.ClusterIface)
		}
	}
	if plan.NoOp {
		// The file already says what the rows want — the intent IS applied.
		// Recording that (rather than leaving rows 'desired' forever) is what
		// makes generation an honest confirmed-apply count.
		return a.markAllApplied(ctx, plan.Rows)
	}

	// One apply at a time per host: an existing journal entry IS the barrier
	// (and, after a crash, the thing recovery consumes — never overwrite it).
	if _, found, err := a.Journal.Read(a.journalID()); err != nil {
		return fmt.Errorf("read apply journal: %w", err)
	} else if found {
		return fmt.Errorf("another host network apply is in flight (or crashed and awaits recovery) — retry after it settles")
	}

	// Only the rows this apply is actually CHANGING transition through
	// applying → applied/rolled_back: an edit resets its row to desired, so
	// state==applied means "the previous file already carries this intent" —
	// and the restore-on-failure brings exactly that file back, leaving those
	// interfaces live and their rows truthfully 'applied'. (Found on the lab:
	// a refused apply of a new bridge stamped rolled_back onto an untouched,
	// still-live neighbor.)
	var pending []corrosion.HostNetworkRecord
	for _, r := range plan.Rows {
		if r.State == corrosion.HostNetworkApplied {
			continue
		}
		pending = append(pending, r)
	}
	for _, r := range pending {
		if err := corrosion.SetHostNetworkState(ctx, a.DB, a.HostName, r.Name, corrosion.HostNetworkApplying, ""); err != nil {
			return fmt.Errorf("mark %q applying: %w", r.Name, err)
		}
	}
	entry := opjournal.Entry{
		OperationID: a.journalID(),
		Kind:        journalKind,
		ResourceID:  a.HostName,
		Stage:       "applying",
		Artifacts: map[string]string{
			artPrevFile:   plan.Current,
			artPrevExists: fmt.Sprintf("%t", plan.Current != "" || fileExisted(plan)),
			artRendered:   plan.Rendered,
		},
	}
	if err := a.Journal.Write(entry); err != nil {
		a.recordRollback(ctx, pending, "journal write failed: "+err.Error())
		return fmt.Errorf("journal the apply (nothing was changed): %w", err)
	}

	if err := a.Sys.WriteManagedFile(plan.Rendered); err != nil {
		a.restoreFile(entry)
		a.recordRollback(ctx, pending, "write managed file: "+err.Error())
		_ = a.Journal.Remove(a.journalID())
		return fmt.Errorf("write %s: %w", ManagedFile, err)
	}

	window := a.RevertWindow
	if window <= 0 {
		window = defaultRevertWindow
	}
	accepted, err := a.Sys.ApplyWithRevert(ctx, window, a.Sys.ConfirmConnectivity)
	if err != nil || !accepted {
		reason := "connectivity confirm failed; configuration reverted"
		if err != nil {
			reason = "apply failed: " + err.Error()
		}
		a.restoreFile(entry)
		a.recordRollback(ctx, pending, reason)
		_ = a.Journal.Remove(a.journalID())
		if err != nil {
			return err
		}
		return fmt.Errorf("host network apply rolled back: %s", reason)
	}

	if err := a.markAllApplied(ctx, plan.Rows); err != nil {
		// The config IS live and confirmed; only the bookkeeping failed. Keep
		// the journal entry out of the way (the apply is done) and surface it.
		_ = a.Journal.Remove(a.journalID())
		return fmt.Errorf("apply confirmed but recording it failed: %w", err)
	}
	return a.Journal.Remove(a.journalID())
}

// Recover restores a crashed apply on daemon start: a journal entry means the
// daemon died between the file write and the outcome, so the previous file
// comes back, the runtime re-applies it, and the rows record the rollback.
// (If the crash happened inside the revert window, netplan's own revert
// already restored the RUNTIME state; the file restore below re-aligns the
// on-disk config with it either way.)
func (a *Applier) Recover(ctx context.Context) error {
	entry, found, err := a.Journal.Read(a.journalID())
	if err != nil {
		return fmt.Errorf("read apply journal: %w", err)
	}
	if !found {
		return nil
	}
	if entry.Kind != journalKind {
		return fmt.Errorf("journal entry %q has unexpected kind %q", a.journalID(), entry.Kind)
	}
	a.restoreFile(*entry)
	if _, err := a.Sys.ApplyWithRevert(ctx, 0, func(context.Context) error { return nil }); err != nil {
		// The restore config failed to apply — leave the journal entry so the
		// next start retries, and surface loudly: this host needs a human.
		return fmt.Errorf("restore previous host network config after crash: %w", err)
	}
	rows, err := corrosion.ListHostNetworks(ctx, a.DB, a.HostName)
	if err == nil {
		var pending []corrosion.HostNetworkRecord
		for _, r := range rows {
			if r.State == corrosion.HostNetworkApplying {
				pending = append(pending, r)
			}
		}
		a.recordRollback(ctx, pending, "daemon crashed mid-apply; previous configuration restored")
	}
	return a.Journal.Remove(a.journalID())
}

func (a *Applier) markAllApplied(ctx context.Context, rows []corrosion.HostNetworkRecord) error {
	for _, r := range rows {
		if r.State == corrosion.HostNetworkApplied {
			continue // already counted; a no-op apply must not re-mint generations
		}
		if err := corrosion.MarkHostNetworkApplied(ctx, a.DB, a.HostName, r.Name); err != nil {
			return fmt.Errorf("mark %q applied: %w", r.Name, err)
		}
	}
	return nil
}

func (a *Applier) recordRollback(ctx context.Context, rows []corrosion.HostNetworkRecord, reason string) {
	for _, r := range rows {
		_ = corrosion.SetHostNetworkState(ctx, a.DB, a.HostName, r.Name, corrosion.HostNetworkRolledBack, reason)
	}
}

func (a *Applier) restoreFile(entry opjournal.Entry) {
	if entry.Artifacts[artPrevExists] == "true" {
		_ = a.Sys.WriteManagedFile(entry.Artifacts[artPrevFile])
		return
	}
	_ = a.Sys.RemoveManagedFile()
}

// fileExisted reports whether ManagedFile existed at plan time: Current is ”
// both for an empty file and a missing one, and the restore path must know
// which (restore-empty vs remove).
func fileExisted(p *Plan) bool { return p.currentExists }

func describeConflicts(conflicts map[string]string) string {
	names := make([]string, 0, len(conflicts))
	for n := range conflicts {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s is already defined by %s", n, conflicts[n])
	}
	return "litevirt owns only " + ManagedFile + "; " + strings.Join(parts, "; ")
}
