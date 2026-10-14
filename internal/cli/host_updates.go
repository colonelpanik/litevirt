package cli

import (
	"fmt"

	"github.com/litevirt/litevirt/internal/hostupdates"
)

// HostUpdatesSummary renders a host's pending OS updates (published as host
// labels by its daemon) for `lv host ls`: "-" when it has not reported or has no
// package manager, "?" when its last check failed, "0", or "5 (2 security)".
func HostUpdatesSummary(labels map[string]string) string {
	if p, s, ok := hostupdates.FromLabels(labels); ok {
		if s > 0 {
			return fmt.Sprintf("%d (%d security)", p, s)
		}
		return fmt.Sprintf("%d", p)
	}
	if labels[hostupdates.LabelPending] == "unknown" {
		return "?"
	}
	return "-"
}

// hostUpdatesNote is the `lv host inspect` hint for a host with updates
// pending, or "" when there is nothing to say. litevirt installs nothing; the
// note says so rather than implying a command.
func hostUpdatesNote(host string, labels map[string]string) string {
	p, s, ok := hostupdates.FromLabels(labels)
	switch {
	case !ok && labels[hostupdates.LabelPending] == "unknown":
		return fmt.Sprintf("note: the last pending-OS-update check on %q failed; its update state is unknown (see the daemon log)", host)
	case !ok || p == 0:
		return ""
	case s > 0:
		return fmt.Sprintf("note: %q has %d pending OS package update(s), %d of them SECURITY updates; patch it with the host's own package manager (litevirt installs nothing)", host, p, s)
	default:
		return fmt.Sprintf("note: %q has %d pending OS package update(s); patch it with the host's own package manager (litevirt installs nothing)", host, p)
	}
}
