package network

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/litevirt/litevirt/internal/netutil"
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

// BridgeName returns the host device a NIC on networkName attaches to: the
// same name Provision returns for def.
//
// A "direct" network answers "direct:<iface>", as Provision does. A network
// missing the field its type keys on (vni, pf, interface) falls back to its
// own name, which is the flat-bridge answer.
func BridgeName(networkName string, def compose.NetworkDef) string {
	switch def.Type {
	case "vxlan":
		if def.VNI != 0 {
			return vxlanBridgeName(def.VNI)
		}
	case "isolated":
		return IsolatedBridgeName(networkName)
	case "sriov":
		if def.PF != "" {
			return def.PF
		}
		return networkName
	case "direct":
		if def.Interface != "" {
			return "direct:" + def.Interface
		}
		return networkName
	}
	if def.Interface != "" {
		return def.Interface
	}
	return networkName
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

		// REFUSE BEFORE CREATING ANYTHING, and this ordering is the whole of
		// whether the refusal survives a retry.
		//
		// The check used to live inside startDHCPFor, below EnsureBridge. So the
		// first attempt CREATED the bridge and then refused — and the second read
		// a pre-existing bridge, which is the one input that turns DHCPWouldServe
		// off for this shape, and provisioned successfully with no DHCP server on
		// a subnet-ful network. Guests with no addresses and no explanation,
		// which is the outcome startDHCPFor's own comment says it refuses in
		// order to avoid. Hoisted here, the refusal reads the same host state
		// every time and a retry refuses identically.
		//
		// startDHCPFor still asks the same question, for the other two dnsmasq
		// sites (isolated, vxlan) which do not create a bridge this way; it is
		// one exported predicate, not two copies.
		if err := BoundNetworkDHCPRefusal(def,
			DHCPHostFacts{BridgePreExisted: bridgePreExisted}, networkName, bridge,
			hostName); err != nil {
			return "", err
		}

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

		scope := fwScopeNet(networkName)
		if def.HostIsolation {
			// Host-isolated: no DHCP, no NAT. IPs delivered via cloud-init.
			if err := corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
				ScopeKey: scope, Bridge: bridge, Isolate: true,
			}); err != nil {
				return "", fmt.Errorf("record host-isolation intent for %s: %w", bridge, err)
			}
		} else if !onPhysicalVLAN {
			// Start DHCP only on a litevirt-managed bridge — a pre-existing
			// infrastructure bridge (e.g. br0) must not get a DHCP server unless
			// the user explicitly enabled it. The gate is still keyed on
			// (!bridgePreExisted || def.DHCP); it lives in DHCPWouldServe now
			// because the NetBox bind-time refusal decides from the same
			// predicate, and two copies of it would drift.
			if err := startDHCPFor(def, DHCPHostFacts{BridgePreExisted: bridgePreExisted},
				networkName, bridge, hostName, dnsmasqPidFile(bridge)); err != nil {
				return "", err
			}
			// Record NAT (masquerade) intent whenever this managed subnet-network
			// wants NAT — independent of the DHCP-start gate above. On a
			// re-provision the bridge always exists, so gating NAT on
			// !bridgePreExisted would drop the intent and strand the network on
			// the pre-consolidation iptables rule; the empty-subnet check keeps
			// infra bridges (no subnet, e.g. br0) untouched. Matches the vxlan
			// case, which already records NAT on Subnet != "" && NATEnabled().
			natSubnet := ""
			if def.Subnet != "" && def.NATEnabled() {
				if err := EnableIPForwarding(); err != nil {
					return "", err
				}
				natSubnet = def.Subnet
			}
			if err := recordNATOrClear(ctx, db, hostName, scope, bridge, natSubnet); err != nil {
				return "", err
			}
			// Enable proxy ARP only when the host IS the VM gateway — i.e., NAT
			// is active (same condition as the masquerade intent above).
			if natSubnet != "" {
				if err := EnsureProxyARP(bridge); err != nil {
					slog.Warn("proxy ARP setup failed (VMs may be unreachable from outside)", "bridge", bridge, "error", err)
				}
			}
		} else {
			// Physical VLAN — litevirt manages no NAT/isolation here; clear stale intent.
			if err := corrosion.DeleteHostFWIntent(ctx, db, hostName, scope); err != nil {
				return "", err
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

		natSubnet := ""
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
					if err := EnableIPForwarding(); err != nil {
						return "", err
					}
					natSubnet = def.Subnet
				}
				if err := startDHCPFor(def,
					DHCPHostFacts{IsGatewayHost: isGatewayHost(ctx, db, networkName, hostName)},
					networkName, bridge, hostName, dnsmasqPidFileVNI(vni)); err != nil {
					return "", err
				}
			}
		}

		// Record NAT/isolation intent for the canonical firewall reconciler.
		scope := fwScopeNet(networkName)
		if def.HostIsolation {
			if err := corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
				ScopeKey: scope, Bridge: bridge, Isolate: true,
			}); err != nil {
				return "", fmt.Errorf("record host-isolation intent for %s: %w", bridge, err)
			}
		} else if err := recordNATOrClear(ctx, db, hostName, scope, bridge, natSubnet); err != nil {
			return "", err
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

		scope := fwScopeNet(networkName)
		if def.HostIsolation {
			// Host-isolated: no DHCP. IPs delivered via cloud-init.
			if err := corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
				ScopeKey: scope, Bridge: bridge, Isolate: true,
			}); err != nil {
				return "", fmt.Errorf("record host-isolation intent for %s: %w", bridge, err)
			}
		} else {
			// Not isolated and no uplink → no NAT either; clear any stale intent.
			if err := corrosion.DeleteHostFWIntent(ctx, db, hostName, scope); err != nil {
				return "", err
			}
			// If subnet is defined, enable DHCP implicitly — an isolated network
			// has no uplink and no router, so litevirt is the only possible
			// source of addresses. DHCPWouldServe says so for every host, which
			// is why a bind over an isolated network's subnet is refused
			// cluster-wide rather than on the binding node's own evidence.
			if err := startDHCPFor(def, DHCPHostFacts{},
				networkName, bridge, hostName, dnsmasqPidFile(bridge)); err != nil {
				return "", err
			}
			if def.Subnet != "" {
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
//
// It deletes this network's firewall intent (so the canonical reconciler drops
// its litevirt-fw NAT/isolation chains on the next pass) AND directly removes the
// legacy out-of-band rules — safe and immediate on teardown, where we want the
// rules gone rather than kept in lockstep.
func Deprovision(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, hostName string) error {
	if db != nil {
		_ = corrosion.DeleteHostFWIntent(ctx, db, hostName, fwScopeNet(networkName))
	}
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
			pidFile := dnsmasqPidFile(bridge)
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
		// The bridge itself goes only when litevirt created it here, no other
		// live network names it, and no workload on this host attaches to it;
		// an operator's bridge is never deleted.
		removeCreatedBridge(ctx, db, networkName, bridge, hostName)
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
			pidFile := dnsmasqPidFileVNI(vni)
			StopDHCP(pidFile) //nolint:errcheck
		}
		return DeprovisionVXLAN(vni)

	case "isolated":
		bridge := IsolatedBridgeName(networkName)
		RemoveHostIsolation(bridge) //nolint:errcheck
		RemoveSNAT(bridge)          //nolint:errcheck
		// Stop DHCP if subnet was configured.
		if def.Subnet != "" {
			pidFile := dnsmasqPidFile(bridge)
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

// removeCreatedBridge removes bridge, the device of bridge network
// networkName that is being torn down, when this host's record says
// EnsureBridge created it (RemoveCreatedBridgeIfUnused), no OTHER live
// network uses it as its device, and no VM or container on hostName attaches
// to it (bridgeNamedByWorkload). networkName itself does not count as a
// network: its own delete deprovisions before it tombstones the row.
//
// Every teardown of a bridge network reaches the bridge here — `lv network
// rm` and a stack delete — so the workload check guards both.
//
// It is best effort and never fails the teardown: a bridge it cannot prove
// unshared, or cannot remove, stays, as every bridge network's bridge did
// before. Without a database there is no way to prove the bridge unshared, so
// it stays.
func removeCreatedBridge(ctx context.Context, db *corrosion.Client, networkName, bridge, hostName string) {
	if db == nil {
		return
	}
	live, err := corrosion.ListNetworks(ctx, db)
	if err != nil {
		slog.Warn("network teardown: cannot read the live networks, so the bridge stays",
			"network", networkName, "bridge", bridge, "error", err)
		return
	}
	for _, r := range live {
		if r.Name == networkName {
			continue
		}
		var def compose.NetworkDef
		if r.Config != "" {
			if err := json.Unmarshal([]byte(r.Config), &def); err != nil {
				slog.Warn("network teardown: a live network's config is unreadable, so the bridge stays",
					"network", networkName, "bridge", bridge, "live_network", r.Name, "error", err)
				return
			}
		}
		def.Type = r.Type
		if BridgeName(r.Name, def) == bridge || (def.Interface == "" && r.Name == bridge) {
			slog.Info("network teardown: another live network uses the bridge, so it stays",
				"network", networkName, "bridge", bridge, "live_network", r.Name)
			return
		}
	}
	if who, err := bridgeNamedByWorkload(ctx, db, hostName, networkName, bridge); err != nil {
		slog.Warn("network teardown: cannot read this host's workload NICs, so the bridge stays",
			"network", networkName, "bridge", bridge, "error", err)
		return
	} else if who != "" {
		slog.Info("network teardown: a workload on this host still attaches to the bridge, so it stays",
			"network", networkName, "bridge", bridge, "workload", who)
		return
	}
	removed, err := RemoveCreatedBridgeIfUnused(bridge)
	switch {
	case err != nil:
		slog.Warn("network teardown: removing the bridge litevirt created failed; it stays",
			"network", networkName, "bridge", bridge, "error", err)
	case removed:
		slog.Info("network teardown: removed the bridge litevirt created", "network", networkName, "bridge", bridge)
	}
}

// bridgeNamedByWorkload names a live VM or container on hostName with a NIC
// that attaches to bridge, or returns "" when there is none. A NIC attaches to
// it when it names networkName (a `--force` delete leaves its NICs in place),
// names the bridge itself (a flat-bridge NIC, `--network <bridge>`), names
// another network — live or deleted — whose device is the bridge, or is a
// container's raw `bridge=` NIC, which has no interface row and is found in
// its create spec.
//
// The bridge's ports cannot answer this: a stopped VM has no tap on it, and a
// VM start does not re-create its bridge, so removing it leaves that VM
// unable to start. An error means the answer is unknown, and the caller keeps
// the bridge: a leaked bridge is harmless, a missing one is not.
func bridgeNamedByWorkload(ctx context.Context, db *corrosion.Client, hostName, networkName, bridge string) (string, error) {
	// The device each network name resolves to, from every network row,
	// live or deleted: a VM's domain keeps the bridge it was defined with
	// after its network is deleted. A name with no row is a flat bridge.
	netRows, err := db.Query(ctx, `SELECT name, type, config FROM networks`)
	if err != nil {
		return "", fmt.Errorf("read networks: %w", err)
	}
	netDev := map[string]string{}
	badDef := map[string]error{}
	for _, r := range netRows {
		name := r.String("name")
		var def compose.NetworkDef
		if c := r.String("config"); c != "" {
			if err := json.Unmarshal([]byte(c), &def); err != nil {
				badDef[name] = err
				continue
			}
		}
		def.Type = r.String("type")
		netDev[name] = BridgeName(name, def)
	}
	attaches := func(n string) (bool, error) {
		if n == "" {
			return false, nil
		}
		if n == networkName || n == bridge {
			return true, nil
		}
		if err, bad := badDef[n]; bad {
			return false, fmt.Errorf("network %s: config: %w", n, err)
		}
		return netDev[n] == bridge, nil
	}

	for _, q := range []string{
		`SELECT 'VM ' || vi.vm_name AS w, vi.network_name AS n FROM vm_interfaces vi
		   JOIN vms v ON v.name = vi.vm_name
		  WHERE v.host_name = ? AND v.deleted_at IS NULL AND vi.deleted_at IS NULL`,
		`SELECT 'VM ' || vn.vm_name AS w, vn.network_name AS n FROM vm_nics vn
		   JOIN vms v ON v.name = vn.vm_name
		  WHERE v.host_name = ? AND v.deleted_at IS NULL AND vn.deleted_at IS NULL`,
		`SELECT 'container ' || ci.ct_name AS w, ci.network_name AS n FROM container_interfaces ci
		   JOIN containers c ON c.host_name = ci.host_name AND c.name = ci.ct_name
		  WHERE ci.host_name = ? AND c.deleted_at IS NULL AND ci.deleted_at IS NULL`,
	} {
		rows, err := db.Query(ctx, q, hostName)
		if err != nil {
			return "", err
		}
		for _, r := range rows {
			hit, err := attaches(r.String("n"))
			if err != nil {
				return "", fmt.Errorf("%s: %w", r.String("w"), err)
			}
			if hit {
				return r.String("w"), nil
			}
		}
	}

	// A container's raw-bridge NIC has no interface row; its create spec
	// holds the bridge.
	rows, err := db.Query(ctx,
		`SELECT name, COALESCE(create_spec, '') AS create_spec FROM containers
		  WHERE host_name = ? AND deleted_at IS NULL`, hostName)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		raw := r.String("create_spec")
		if raw == "" {
			continue
		}
		var spec corrosion.ContainerCreateSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			return "", fmt.Errorf("container %s: create spec: %w", r.String("name"), err)
		}
		for _, n := range spec.Networks {
			if n.Bridge == bridge {
				return "container " + r.String("name"), nil
			}
			hit, err := attaches(n.NetworkName)
			if err != nil {
				return "", fmt.Errorf("container %s: %w", r.String("name"), err)
			}
			if hit {
				return "container " + r.String("name"), nil
			}
		}
	}
	return "", nil
}

// fwScopeNet is the host_fw_intent scope key for a network's provisioning
// decision (its LB counterpart is "lb:<name>", written by the LB path).
func fwScopeNet(networkName string) string { return "net:" + networkName }

// recordNATOrClear upserts a masquerade intent for (bridge, natSubnet) when
// natSubnet is set, or deletes any stale intent for the scope when it isn't — so a
// network that loses NAT (or never had it) leaves no orphaned masquerade behind.
func recordNATOrClear(ctx context.Context, db *corrosion.Client, hostName, scope, bridge, natSubnet string) error {
	if natSubnet == "" {
		return corrosion.DeleteHostFWIntent(ctx, db, hostName, scope)
	}
	return corrosion.UpsertHostFWIntent(ctx, db, hostName, corrosion.HostFWIntent{
		ScopeKey: scope, Bridge: bridge, MasqueradeSubnet: natSubnet,
	})
}

// isNoSuchDevice returns true if the command output indicates the device does not exist.
func isNoSuchDevice(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "Cannot find device") || strings.Contains(s, "No such device")
}

// UpsertVTEP writes this host's VTEP into network_vteps.
func UpsertVTEP(ctx context.Context, db *corrosion.Client, networkName, hostName, vtepIP string, vni int) error {
	now := db.NowTS()
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
	if ip := netutil.OutboundIP(); ip != "" {
		return ip
	}
	return "127.0.0.1"
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
