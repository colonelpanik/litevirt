package network

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// maxIfaceName is the Linux interface-name limit (IFNAMSIZ - 1). Names longer
// than this are rejected by `ip link add` ("Attribute failed policy
// validation") on kernels that enforce it, and silently truncated on older
// ones (risking collisions).
const maxIfaceName = 15

// IsolatedBridgeName returns the host bridge name for an isolated network.
// It is "br-iso-<name>" when that fits IFNAMSIZ, otherwise a stable hashed
// form "br-iso-<8 hex>" (exactly 15 chars) so long network names don't fail
// bridge creation. Every site that creates, deletes, or resolves an isolated
// bridge MUST use this so the names always agree.
func IsolatedBridgeName(networkName string) string {
	const prefix = "br-iso-"
	if len(prefix)+len(networkName) <= maxIfaceName {
		return prefix + networkName
	}
	sum := sha1.Sum([]byte(networkName))
	return prefix + hex.EncodeToString(sum[:])[:maxIfaceName-len(prefix)]
}

// VTEPRecord holds a host's VTEP information for a network.
type VTEPRecord struct {
	NetworkName string
	HostName    string
	VTEPAddr    string
	VNI         int
}

// Provision ensures network infra for def exists. Returns bridge name for libvirt.
// type="" or "bridge": returns def.Interface (zero new code, flat mode)
// type="vxlan": EnsureVXLAN, UpsertVTEP, SyncFloodEntries; if Subnet != "" also EnsureIRB
// type="isolated": create bridge with no uplink
// type="sriov": return def.PF
func Provision(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	switch def.Type {
	case "", "bridge":
		// Ensure the bridge exists; create it if missing.
		bridge := def.Interface
		if bridge == "" {
			return "", fmt.Errorf("bridge network requires interface name")
		}
		// Check if bridge pre-exists before we touch anything. Pre-existing
		// bridges (infrastructure bridges like br0) should not get DHCP/NAT
		// added unless the user explicitly enables them.
		bridgePreExisted := BridgeExists(bridge)
		if err := EnsureBridge(bridge); err != nil {
			return "", err
		}

		// If a VLAN ID is specified, create a VLAN sub-interface on the
		// default-route interface (or explicit underlay) and attach it to
		// the bridge. This gives VMs direct L2 access to the tagged VLAN.
		if def.VLAN > 0 {
			if err := EnsureBridgeVLAN(bridge, def.VLAN, def.Underlay); err != nil {
				return "", fmt.Errorf("bridge VLAN setup: %w", err)
			}
		}

		// When a VLAN is set, the bridge is on a physical network — VMs
		// talk directly to the VLAN's router. Skip DHCP/NAT/proxy ARP
		// (same logic as pre-existing bridges).
		onPhysicalVLAN := def.VLAN > 0

		if def.HostIsolation {
			// Host-isolated: no DHCP, no NAT. IPs delivered via cloud-init.
			if err := EnsureHostIsolation(bridge, nil); err != nil {
				return "", fmt.Errorf("ensure host isolation on %s: %w", bridge, err)
			}
		} else if !onPhysicalVLAN {
			RemoveHostIsolation(bridge) //nolint:errcheck
			// If subnet is defined and this is a litevirt-managed bridge (not
			// pre-existing infrastructure or physical VLAN), enable DHCP and
			// optionally NAT.
			if def.Subnet != "" && (!bridgePreExisted || def.DHCP) {
				gw, rangeStart, rangeEnd, mask, err := SubnetRange(def.Subnet)
				if err != nil {
					return "", fmt.Errorf("derive DHCP range: %w", err)
				}
				pidFile := fmt.Sprintf("/var/run/litevirt-dnsmasq-%s.pid", bridge)
				if err := startDHCPFunc(bridge, gw, rangeStart, rangeEnd, mask, pidFile); err != nil {
					return "", fmt.Errorf("start DHCP on %s: %w", bridge, err)
				}
				if def.NATEnabled() {
					if err := EnsureNAT(def.Subnet, bridge); err != nil {
						return "", fmt.Errorf("ensure NAT on %s: %w", bridge, err)
					}
				}
			}
			// Enable proxy ARP only when the host IS the VM gateway — i.e.,
			// DHCP and NAT are active, not on a physical VLAN.
			if def.Subnet != "" && def.NATEnabled() && (!bridgePreExisted || def.DHCP) {
				if err := EnsureProxyARP(bridge); err != nil {
					slog.Warn("proxy ARP setup failed (VMs may be unreachable from outside)", "bridge", bridge, "error", err)
				}
			}
		}
		return bridge, nil

	case "vxlan":
		vni := def.VNI
		if vni == 0 {
			return "", fmt.Errorf("vxlan network requires vni")
		}
		underlay := def.Underlay
		if underlay == "" {
			underlay = defaultRouteInterface()
		}
		if underlay == "" {
			return "", fmt.Errorf("vxlan network requires underlay interface (could not auto-detect; set 'underlay' explicitly)")
		}

		bridge, err := EnsureVXLAN(vni, underlay, localIP)
		if err != nil {
			return "", fmt.Errorf("ensure vxlan vni %d: %w", vni, err)
		}

		// Register this host's VTEP under the logical network name.
		if err := UpsertVTEP(ctx, db, networkName, hostName, localIP, vni); err != nil {
			return "", fmt.Errorf("upsert vtep: %w", err)
		}

		// Brief delay for CRDT convergence before reading peer VTEPs.
		time.Sleep(500 * time.Millisecond)

		// Sync flood entries from all known VTEPs
		if err := SyncFloodEntries(ctx, db, networkName, hostName, vni); err != nil {
			return "", fmt.Errorf("sync flood entries: %w", err)
		}

		if def.Subnet != "" {
			// IRB (anycast gateway) is always set up — VMs need a default route.
			if _, err := EnsureIRB(vni, def.Subnet); err != nil {
				return "", fmt.Errorf("ensure irb: %w", err)
			}

			if def.HostIsolation {
				// Host-isolated: no DHCP, no NAT. IPs delivered via cloud-init.
				// IRB gateway stays for routing (FORWARD), but INPUT is dropped.
			} else {
				if def.NATEnabled() {
					if err := EnsureNAT(def.Subnet, bridge); err != nil {
						return "", fmt.Errorf("ensure NAT on %s: %w", bridge, err)
					}
				}
				if isGatewayHost(ctx, db, networkName, hostName) {
					gw, rangeStart, rangeEnd, mask, err := SubnetRange(def.Subnet)
					if err != nil {
						return "", fmt.Errorf("derive DHCP range: %w", err)
					}
					pidFile := fmt.Sprintf("/var/run/litevirt-dnsmasq-vni%d.pid", vni)
					if err := startDHCPFunc(bridge, gw, rangeStart, rangeEnd, mask, pidFile); err != nil {
						return "", fmt.Errorf("start DHCP on %s: %w", bridge, err)
					}
				}
			}
		}

		if def.HostIsolation {
			if err := EnsureHostIsolation(bridge, nil); err != nil {
				return "", fmt.Errorf("ensure host isolation on %s: %w", bridge, err)
			}
		} else {
			RemoveHostIsolation(bridge) //nolint:errcheck
		}

		return bridge, nil

	case "isolated":
		// Create a bridge with no uplink; IsolatedBridgeName keeps the name
		// within IFNAMSIZ even for long network names.
		bridge := IsolatedBridgeName(networkName)
		out, err := execCommand("ip", "link", "add", bridge, "type", "bridge")
		if err != nil && !isFileExists(out) {
			return "", fmt.Errorf("ip link add isolated bridge: %w: %s", err, out)
		}
		out, err = execCommand("ip", "link", "set", bridge, "up")
		if err != nil && !isFileExists(out) {
			return "", fmt.Errorf("ip link set %s up: %w: %s", bridge, err, out)
		}

		if def.HostIsolation {
			// Host-isolated: no DHCP. IPs delivered via cloud-init.
			if err := EnsureHostIsolation(bridge, nil); err != nil {
				return "", fmt.Errorf("ensure host isolation on %s: %w", bridge, err)
			}
		} else {
			RemoveHostIsolation(bridge) //nolint:errcheck
			// If subnet is defined, enable DHCP implicitly.
			if def.Subnet != "" {
				gw, rangeStart, rangeEnd, mask, err := SubnetRange(def.Subnet)
				if err != nil {
					return "", fmt.Errorf("derive DHCP range: %w", err)
				}
				pidFile := fmt.Sprintf("/var/run/litevirt-dnsmasq-%s.pid", bridge)
				if err := startDHCPFunc(bridge, gw, rangeStart, rangeEnd, mask, pidFile); err != nil {
					return "", fmt.Errorf("start DHCP on %s: %w", bridge, err)
				}
				// NAT is skipped for isolated networks — they have no uplink.
				if def.NAT != nil && *def.NAT {
					slog.Warn("NAT requested on isolated network (no uplink) — skipping", "network", networkName)
				}
			}
		}

		return bridge, nil

	case "sriov":
		return def.PF, nil

	case "direct":
		// macvtap: VM attaches directly to the interface via macvtap.
		// No bridge needed. Return the interface name prefixed with "direct:"
		// so the caller knows to use macvtap XML instead of bridge XML.
		iface := def.Interface
		if iface == "" {
			return "", fmt.Errorf("direct network requires interface name")
		}
		if _, err := net.InterfaceByName(iface); err != nil {
			return "", fmt.Errorf("direct network interface %q not found: %w", iface, err)
		}
		// Ensure a macvlan companion exists so the host can communicate with
		// macvtap guests on the same parent interface (kernel limitation).
		ensureMacvlan(iface)
		return "direct:" + iface, nil

	default:
		return "", fmt.Errorf("unknown network type %q", def.Type)
	}
}

// Deprovision tears down network infrastructure for def on this host.
// It is the inverse of Provision: stops DHCP, removes bridges/VXLAN/IRB.
// networkName is the logical network name (used for isolated bridge naming).
func Deprovision(networkName string, def compose.NetworkDef) error {
	switch def.Type {
	case "", "bridge":
		bridge := def.Interface
		if bridge == "" {
			return nil
		}
		RemoveHostIsolation(bridge) //nolint:errcheck
		RemoveSNAT(bridge)          //nolint:errcheck
		RemoveProxyARP(bridge)
		// Stop DHCP and remove gateway IP + NAT if subnet was configured.
		if def.Subnet != "" {
			pidFile := fmt.Sprintf("/var/run/litevirt-dnsmasq-%s.pid", bridge)
			StopDHCP(pidFile) //nolint:errcheck
			// Remove the gateway IP that StartDHCP added to the bridge.
			if gw, _, _, _, err := SubnetRange(def.Subnet); err == nil {
				prefix := strings.SplitN(def.Subnet, "/", 2)
				if len(prefix) == 2 {
					execCommand("ip", "addr", "del", gw+"/"+prefix[1], "dev", bridge) //nolint:errcheck
				}
			}
			RemoveNAT(def.Subnet, bridge) //nolint:errcheck
		}
		// Remove VLAN sub-interface if we created one.
		if def.VLAN > 0 {
			RemoveBridgeVLAN(bridge, def.VLAN, def.Underlay)
		}
		// Don't delete user-managed bridges — they may be shared with other stacks.
		return nil

	case "vxlan":
		vni := def.VNI
		if vni == 0 {
			return nil
		}
		bridge := vxlanBridgeName(vni)
		RemoveHostIsolation(bridge) //nolint:errcheck
		RemoveSNAT(bridge)          //nolint:errcheck
		// Remove IRB gateway and NAT if subnet was set.
		if def.Subnet != "" {
			RemoveIRB(vni, def.Subnet)    //nolint:errcheck
			RemoveNAT(def.Subnet, bridge) //nolint:errcheck
			pidFile := fmt.Sprintf("/var/run/litevirt-dnsmasq-vni%d.pid", vni)
			StopDHCP(pidFile) //nolint:errcheck
		}
		return DeprovisionVXLAN(vni)

	case "isolated":
		bridge := IsolatedBridgeName(networkName)
		RemoveHostIsolation(bridge) //nolint:errcheck
		RemoveSNAT(bridge)          //nolint:errcheck
		// Stop DHCP if subnet was configured.
		if def.Subnet != "" {
			pidFile := fmt.Sprintf("/var/run/litevirt-dnsmasq-%s.pid", bridge)
			StopDHCP(pidFile) //nolint:errcheck
		}
		// Delete the isolated bridge (litevirt created it, safe to remove).
		out, err := execCommand("ip", "link", "del", bridge)
		if err != nil && !isNoSuchDevice(out) {
			return fmt.Errorf("ip link del %s: %w: %s", bridge, err, out)
		}
		return nil

	case "sriov":
		// SR-IOV PF is not managed by litevirt; nothing to tear down.
		return nil

	case "direct":
		// macvtap: nothing to tear down — the tap device is removed with the VM.
		return nil

	default:
		return fmt.Errorf("unknown network type %q", def.Type)
	}
}

// isNoSuchDevice returns true if the command output indicates the device does not exist.
func isNoSuchDevice(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "Cannot find device") || strings.Contains(s, "No such device")
}

// UpsertVTEP writes this host's VTEP into network_vteps.
func UpsertVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName, vtepIP string, vni int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return db.Execute(ctx,
		`INSERT INTO network_vteps (network_name, host_name, vtep_ip, vni, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(network_name, host_name) DO UPDATE SET
		   vtep_ip = excluded.vtep_ip,
		   vni = excluded.vni,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		networkName, hostName, vtepIP, vni, now,
	)
}

// GetVTEPs returns all active VTEPs for a network.
func GetVTEPs(ctx context.Context, db *corrosion.Client, networkName string) ([]VTEPRecord, error) {
	rows, err := db.Query(ctx,
		`SELECT network_name, host_name, vtep_ip, vni
		 FROM network_vteps WHERE network_name = ? AND deleted_at IS NULL`,
		networkName)
	if err != nil {
		return nil, err
	}

	vteps := make([]VTEPRecord, len(rows))
	for i, r := range rows {
		vteps[i] = VTEPRecord{
			NetworkName: r.String("network_name"),
			HostName:    r.String("host_name"),
			VTEPAddr:    r.String("vtep_ip"),
			VNI:         r.Int("vni"),
		}
	}
	return vteps, nil
}

// isGatewayHost returns true if hostName is the elected DHCP gateway for this
// VXLAN network. The gateway is the first VTEP host by lexical hostname order,
// ensuring deterministic, convergent election without coordination.
func isGatewayHost(ctx context.Context, db *corrosion.Client, networkName, hostName string) bool {
	vteps, err := GetVTEPs(ctx, db, networkName)
	if err != nil || len(vteps) == 0 {
		return true // no peers yet — we're the gateway
	}
	sort.Slice(vteps, func(i, j int) bool { return vteps[i].HostName < vteps[j].HostName })
	return vteps[0].HostName == hostName
}

// SyncFloodEntries reads all VTEPs for vni from DB and calls FloodEntry for each peer != hostName.
func SyncFloodEntries(ctx context.Context, db *corrosion.Client, networkName, hostName string, vni int) error {
	vteps, err := GetVTEPs(ctx, db, networkName)
	if err != nil {
		return fmt.Errorf("get vteps: %w", err)
	}

	for _, v := range vteps {
		if v.HostName == hostName {
			continue
		}
		if err := FloodEntry(vni, v.VTEPAddr); err != nil {
			return fmt.Errorf("flood entry %s: %w", v.VTEPAddr, err)
		}
	}
	return nil
}

// LocalIP returns the outbound IP of this host by dialing a UDP socket.
func LocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// ProvisionForVM looks up a network definition from corrosion and calls Provision
// to ensure all infrastructure (bridge, DHCP, NAT, VXLAN, IRB) exists on this host.
// Returns the bridge name, or "" if no provisioning is needed (flat bridge mode).
// Shared by grpcapi.CreateVM and health.Reconciler.
func ProvisionForVM(ctx context.Context, db *corrosion.Client, networkName, hostName string) (string, error) {
	rows, err := db.Query(ctx,
		`SELECT type, config FROM networks WHERE name = ? AND deleted_at IS NULL`,
		networkName)
	if err != nil || len(rows) == 0 {
		return "", nil // not in DB — flat bridge mode
	}

	netType := rows[0].String("type")
	configJSON := rows[0].String("config")

	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(configJSON), &def); err != nil {
		return "", fmt.Errorf("parse network config: %w", err)
	}
	def.Type = netType
	if def.Interface == "" {
		def.Interface = networkName
	}

	localIP := LocalIP()
	bridge, err := SafeProvision(ctx, db, networkName, def, localIP, hostName)
	if err != nil {
		return "", err
	}
	return bridge, nil
}
