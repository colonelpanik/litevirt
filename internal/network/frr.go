package network

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"text/template"
)

// FRRConfig holds the BGP configuration for this host.
type FRRConfig struct {
	RouterID string
	LocalASN int
	Peers    []BGPPeer
}

// BGPPeer describes a BGP peer.
type BGPPeer struct {
	HostName string
	VTEPAddr string
	ASN      int
}

var frrTemplate = template.Must(template.New("frr").Parse(`frr version 10
hostname {{.Hostname}}
!
router bgp {{.Config.LocalASN}}
 bgp router-id {{.Config.RouterID}}
 no bgp ebgp-requires-policy
{{range .Config.Peers}} neighbor {{.VTEPAddr}} remote-as {{.ASN}}
{{end}} !
 address-family l2vpn evpn
{{range .Config.Peers}}  neighbor {{.VTEPAddr}} activate
{{end}}  advertise-all-vni
 exit-address-family
!
`))

// RenderFRRConfig generates frr.conf text using text/template.
func RenderFRRConfig(hostname string, cfg FRRConfig) (string, error) {
	data := struct {
		Hostname string
		Config   FRRConfig
	}{
		Hostname: hostname,
		Config:   cfg,
	}
	var buf bytes.Buffer
	if err := frrTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render frr config: %w", err)
	}
	return buf.String(), nil
}

// frrConfigPath is the path to the FRR config file; overridable in tests.
var frrConfigPath = "/etc/frr/frr.conf"

// frrInstalledFn checks if FRR is installed; overridable in tests.
var frrInstalledFn = func() bool {
	_, err := exec.LookPath("vtysh")
	return err == nil
}

// reloadFRRFn is the function used to reload FRR; overridable in tests.
var reloadFRRFn = reloadFRR

// WriteFRRConfig renders and writes the FRR config, then reloads FRR.
// Returns nil if FRR is not installed (logs a warning).
func WriteFRRConfig(hostname string, cfg FRRConfig) error {
	if !frrInstalledFn() {
		slog.Warn("FRR not installed, skipping BGP config write")
		return nil
	}

	content, err := RenderFRRConfig(hostname, cfg)
	if err != nil {
		return err
	}

	if err := os.WriteFile(frrConfigPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write frr config: %w", err)
	}

	return reloadFRRFn()
}

func reloadFRR() error {
	out, err := exec.Command("vtysh", "-c", "write memory").CombinedOutput()
	if err != nil {
		return fmt.Errorf("vtysh write memory: %w: %s", err, out)
	}
	return nil
}
