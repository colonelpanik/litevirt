// Package cephdeploy wraps cephadm so litevirt can bring up and grow a
// hyperconverged Ceph cluster across the same hosts that run litevirtd.
// The package mirrors Proxmox's "Ceph from the UI" experience without
// pulling in any C-bound Ceph libraries — every operation shells out
// to cephadm or rados.
//
// split:
//
//	1.5.A (this file): bootstrap (init), then per-role attach (mon, mgr,
//	                   osd) and topology read (status, osd-tree).
//	1.5.B: HTMX dashboard at /ui/storage/ceph + deploy wizard.
package cephdeploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// CephSpec carries the operator's intent: which interface the
// MON listens on, which fsid (cluster id) to use, and where to put
// state. Defaults match cephadm's own.
type CephSpec struct {
	// MonIP is the IP address the first MON binds to. Required.
	MonIP string
	// FSID is an optional pre-generated cluster UUID. Empty = let
	// cephadm pick one (it always emits one).
	FSID string
	// Network is the public CIDR (operator's storage VLAN). Empty =
	// let cephadm derive from MonIP.
	Network string
	// PauseHealthBan disables the cephadm "PAUSED" health-warning that
	// fires while OSDs are still being placed. Useful in tests.
	PauseHealthBan bool
}

// Validate covers the operator-error cases that cephadm only catches
// after a long network round-trip.
func (s *CephSpec) Validate() error {
	if s == nil {
		return errors.New("nil CephSpec")
	}
	if s.MonIP == "" {
		return errors.New("MonIP required")
	}
	if ip := net.ParseIP(s.MonIP); ip == nil {
		return fmt.Errorf("invalid MonIP %q", s.MonIP)
	}
	if s.Network != "" {
		if _, _, err := net.ParseCIDR(s.Network); err != nil {
			return fmt.Errorf("Network must be CIDR (e.g. 10.0.0.0/24): %v", err)
		}
	}
	return nil
}

// Runner is the shell-out boundary so tests don't need a real cephadm.
type Runner interface {
	Bootstrap(ctx context.Context, spec CephSpec) (string, error) // returns FSID
	AddMon(ctx context.Context, host string) error
	AddMgr(ctx context.Context, host string) error
	AddOSD(ctx context.Context, host, device string) error
	Status(ctx context.Context) (Status, error)
	OSDTree(ctx context.Context) (OSDTree, error)
}

// CephadmRunner is the production Runner backed by the cephadm CLI.
type CephadmRunner struct {
	// Bin overrides the cephadm binary path. Empty = "cephadm" on PATH.
	Bin string
}

// NewCephadmRunner returns a Runner that talks to /usr/sbin/cephadm.
func NewCephadmRunner() *CephadmRunner { return &CephadmRunner{} }

func (r *CephadmRunner) bin() string {
	if r.Bin != "" {
		return r.Bin
	}
	return "cephadm"
}

// Bootstrap brings up the first MON + MGR. Idempotent on the same host
// (cephadm itself refuses to re-bootstrap; we surface that as an error).
func (r *CephadmRunner) Bootstrap(ctx context.Context, spec CephSpec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	args := []string{"bootstrap", "--mon-ip", spec.MonIP, "--allow-overwrite", "--no-minimize-config"}
	if spec.FSID != "" {
		args = append(args, "--fsid", spec.FSID)
	}
	if spec.Network != "" {
		args = append(args, "--cluster-network", spec.Network, "--mon-network", spec.Network)
	}
	out, err := exec.CommandContext(ctx, r.bin(), args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cephadm bootstrap: %w: %s", err, out)
	}
	// cephadm prints "fsid: <uuid>" — grab it for the caller.
	return parseFSID(string(out)), nil
}

// AddMon adds a MON on host (must be SSH-reachable as root with the
// public key cephadm bootstrap installed).
func (r *CephadmRunner) AddMon(ctx context.Context, host string) error {
	return r.runCeph(ctx, "orch", "daemon", "add", "mon", host)
}

// AddMgr adds a Mgr on host.
func (r *CephadmRunner) AddMgr(ctx context.Context, host string) error {
	return r.runCeph(ctx, "orch", "daemon", "add", "mgr", host)
}

// AddOSD adds an OSD using the named block device on host.
//
//	device: "/dev/sdb" or "/dev/disk/by-id/wwn-…"
func (r *CephadmRunner) AddOSD(ctx context.Context, host, device string) error {
	return r.runCeph(ctx, "orch", "daemon", "add", "osd",
		fmt.Sprintf("%s:%s", host, device))
}

// Status returns a parsed view of `ceph -s --format json`.
func (r *CephadmRunner) Status(ctx context.Context) (Status, error) {
	out, err := exec.CommandContext(ctx, r.bin(), "shell", "--", "ceph", "-s", "--format", "json").CombinedOutput()
	if err != nil {
		return Status{}, fmt.Errorf("ceph -s: %w: %s", err, out)
	}
	var raw cephStatusJSON
	if err := json.Unmarshal(out, &raw); err != nil {
		return Status{}, fmt.Errorf("parse ceph -s json: %w", err)
	}
	return Status{
		FSID:         raw.FSID,
		Health:       raw.Health.Status,
		HealthDetail: raw.Health.detailString(),
		MonsTotal:    raw.MonMap.NumMons,
		OSDsTotal:    raw.OSDMap.NumOSDs,
		OSDsUp:       raw.OSDMap.NumUpOSDs,
		OSDsIn:       raw.OSDMap.NumInOSDs,
		PGsTotal:     raw.PGMap.NumPGs,
		BytesAvail:   raw.PGMap.BytesAvail,
		BytesUsed:    raw.PGMap.BytesUsed,
	}, nil
}

// OSDTree returns the cluster's CRUSH topology — used by the UI to
// render a host-by-host placement view.
func (r *CephadmRunner) OSDTree(ctx context.Context) (OSDTree, error) {
	out, err := exec.CommandContext(ctx, r.bin(), "shell", "--", "ceph", "osd", "tree", "--format", "json").CombinedOutput()
	if err != nil {
		return OSDTree{}, fmt.Errorf("ceph osd tree: %w: %s", err, out)
	}
	var raw cephOSDTreeJSON
	if err := json.Unmarshal(out, &raw); err != nil {
		return OSDTree{}, fmt.Errorf("parse osd tree: %w", err)
	}
	out2 := OSDTree{}
	for _, n := range raw.Nodes {
		out2.Nodes = append(out2.Nodes, OSDNode{
			ID: n.ID, Name: n.Name, Type: n.Type,
			Status: n.Status, Reweight: n.Reweight,
			Children: n.Children,
		})
	}
	return out2, nil
}

func (r *CephadmRunner) runCeph(ctx context.Context, args ...string) error {
	full := append([]string{"shell", "--", "ceph"}, args...)
	if out, err := exec.CommandContext(ctx, r.bin(), full...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// Status is the operator-facing summary.
type Status struct {
	FSID         string
	Health       string // HEALTH_OK | HEALTH_WARN | HEALTH_ERR
	HealthDetail string
	MonsTotal    int
	OSDsTotal    int
	OSDsUp       int
	OSDsIn       int
	PGsTotal     int
	BytesAvail   int64
	BytesUsed    int64
}

// OSDTree is the parsed CRUSH map.
type OSDTree struct {
	Nodes []OSDNode
}

// OSDNode is one entry in `ceph osd tree`.
type OSDNode struct {
	ID       int
	Name     string
	Type     string  // host | osd | rack | …
	Status   string  // up | down (for type=osd)
	Reweight float64 // CRUSH reweight, 1.0 = normal
	Children []int   // OSD IDs under this node when Type=host/rack
}

// ── JSON parsing helpers ────────────────────────────────────────────

// healthCheck is one entry under `health.checks`.
type healthCheck struct {
	Severity string `json:"severity"`
	Summary  struct {
		Message string `json:"message"`
	} `json:"summary"`
}

// cephHealth is the typed parser for the `health` block. We pull it
// out to its own type so detailString() can hang off it.
type cephHealth struct {
	Status string                 `json:"status"`
	Checks map[string]healthCheck `json:"checks"`
}

func (h cephHealth) detailString() string {
	if len(h.Checks) == 0 {
		return h.Status
	}
	var parts []string
	for k, v := range h.Checks {
		parts = append(parts, fmt.Sprintf("[%s] %s: %s", v.Severity, k, v.Summary.Message))
	}
	return strings.Join(parts, "; ")
}

type cephStatusJSON struct {
	FSID   string     `json:"fsid"`
	Health cephHealth `json:"health"`
	MonMap struct {
		NumMons int `json:"num_mons"`
	} `json:"monmap"`
	OSDMap struct {
		NumOSDs   int `json:"num_osds"`
		NumUpOSDs int `json:"num_up_osds"`
		NumInOSDs int `json:"num_in_osds"`
	} `json:"osdmap"`
	PGMap struct {
		NumPGs     int   `json:"num_pgs"`
		BytesAvail int64 `json:"bytes_avail"`
		BytesUsed  int64 `json:"bytes_used"`
	} `json:"pgmap"`
}

type cephOSDTreeJSON struct {
	Nodes []struct {
		ID       int     `json:"id"`
		Name     string  `json:"name"`
		Type     string  `json:"type"`
		Status   string  `json:"status"`
		Reweight float64 `json:"reweight"`
		Children []int   `json:"children"`
	} `json:"nodes"`
}

// parseFSID extracts the cluster UUID cephadm prints during bootstrap.
// Real output looks like one of these (cephadm versions vary):
//
//	Cluster fsid: 7e1c5e2a-…
//	INFO:cephadm:Cluster fsid: 7e1c5e2a-…
//
// We tolerate any leading prefix by searching for the marker substring.
func parseFSID(output string) string {
	const marker = "Cluster fsid:"
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		return strings.TrimSpace(line[idx+len(marker):])
	}
	return ""
}
