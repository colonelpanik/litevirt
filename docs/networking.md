# Networking

litevirt attaches VMs to Linux bridges on the host. It does not manage the physical network fabric — your switches, routers, and underlay are your responsibility.

## Network types

### Bridge (default)

Attaches VMs directly to a Linux bridge. The simplest option for flat datacenter networks.

```yaml
networks:
  lan:
    type: "bridge"
    interface: "br0"
```

litevirt auto-creates the bridge if it doesn't already exist. If you need to attach a physical uplink, create the bridge manually beforehand:

```bash
ip link add br0 type bridge
ip link set br0 up
ip link set eth0 master br0    # attach uplink
```

### VXLAN

Creates overlay networks between hosts using VXLAN encapsulation. Useful when you need L2 connectivity across L3 boundaries.

```yaml
networks:
  overlay:
    type: "vxlan"
    vni: 1000
    underlay: "eth0"
    port: 4789
    subnet: "10.10.0.0/24"
    dhcp: true
```

litevirt manages VTEP configuration and FDB entries. BGP peering between hosts distributes MAC/IP mappings.

### Isolated

A host-local bridge with no external connectivity. VMs on the same host can communicate, but there is no path to the outside.

```yaml
networks:
  internal:
    type: "isolated"
    subnet: "172.16.0.0/24"
    dhcp: true
```

The host bridge for an isolated network is `br-iso-<name>`; when that would
exceed Linux's 15-char interface-name limit it is automatically shortened to a
stable hashed form, so network names of any length work.

### SR-IOV

Passes a virtual function (VF) from an SR-IOV-capable NIC directly to the VM for near-native network performance.

```yaml
networks:
  fast:
    type: "sriov"
    pf: "eth1"
    spoof-check: true
```

Requires:

- IOMMU enabled in BIOS and kernel (`intel_iommu=on` or `amd_iommu=on`)
- SR-IOV capable NIC with VFs created
- `vfio-pci` kernel module loaded

### Direct (macvtap)

Attaches VMs directly to a host interface using macvtap, without creating a bridge. This is useful when the host interface carries the host's management IP (e.g., a VLAN sub-interface) and enslaving it to a bridge would disrupt connectivity.

```yaml
networks:
  mgmt:
    type: "direct"
    interface: "bond0.206"
```

The VM gets L2 access to the same network as the parent interface. No bridge, DHCP, or NAT is created by litevirt — the interface must already exist on the host.

When to use direct mode:

- **Management VLANs** — the host IP lives on a VLAN interface (e.g., `bond0.206`) and moving it to a bridge is impractical or risky.
- **Simple flat attachment** — you just need VMs on the same L2 segment as the host, with no overlay or isolation.

Limitations:

- **No VM-to-host communication** — macvtap in bridge mode does not allow the guest to reach the host's IP on the parent interface. This is a kernel-level restriction of macvtap. VMs can reach other devices on the network, but not the hypervisor itself via that interface.
- **No DHCP from litevirt** — IP assignment must come from an external DHCP server or be configured statically via cloud-init.
- **Interface must exist** — litevirt does not create the parent interface. It must be present on the host before deployment.

## VM network attachment

```yaml
vms:
  web:
    network:
      - name: "lan"
        model: "virtio"           # virtio (default) or e1000
        ip: "10.0.1.50"           # optional, DHCP if omitted
        mac: "52:54:00:ab:cd:ef"  # optional, auto-generated if omitted
        gateway: "10.0.1.1"       # optional
```

Multiple networks can be attached to a single VM:

```yaml
    network:
      - name: "frontend"
      - name: "backend"
        ip: "172.16.0.10"
```

## Container network attachment

Containers attach to the same logical networks as VMs and reach parity on the
managed path. A *managed* NIC (`network=<name>` on the CLI, or a compose `kind:
lxc` workload's `network:`) gets a tracked `container_interfaces` row, a
deterministic host veth + locally-administered MAC, an IPAM lease, a DNS record,
and per-NIC security-group enforcement on its veth. A *raw* NIC (`bridge=<br>`)
attaches straight onto a host bridge with no managed state (the admin escape
hatch).

```bash
lv ct create web --network network=app-net,name=eth0,security-groups=web;db
```

Bridge-family networks (bridge / vxlan / isolated) are supported; `direct` and
`sriov` are VM-only. See [containers.md](containers.md) for the full container
networking model.

## Network ownership (project isolation)

A network is either **global** (the default — usable by every project) or **owned
by a project**:

```bash
lv network create app-net --type bridge --project acme   # owned + isolated
lv network create mgmt --type bridge                     # global (shared)
```

A workload may attach only to a global network or one its own project owns;
attaching to another project's network is denied at create/attach time. A raw
bridge is outside isolation, so it requires cluster-root authority (a project
workload must use a managed network). See [tenancy.md](tenancy.md).

## VLAN trunk mode

For VMs that need to handle multiple VLANs (e.g., virtual routers):

```yaml
    network:
      - name: "trunk-port"
        trunk: [100, 101, 200]
```

## IP allocation

litevirt tracks IP allocations in the cluster state store. When a subnet is defined on a network, IPs are allocated from the pool and persisted.

Set a VM's IP after creation:

```bash
lv config my-vm --ip 10.0.1.50 --network lan
```

## NAT

By default, litevirt enables IP masquerading (NAT) for networks with a subnet defined. This gives VMs outbound internet access through the host.

To disable NAT on a network:

```yaml
networks:
  internal:
    type: "bridge"
    interface: "br-internal"
    subnet: "10.0.5.0/24"
    dhcp: true
    nat: false
```

NAT is ignored on isolated networks (no uplink) and on host-isolated networks (use `snat: true` on a load balancer instead — see [compose.md](compose.md#snat-via-vip)).

## IPv6

Network subnets accept IPv6 CIDRs. The IPAM allocator, dnsmasq DHCP/RA
configuration, and cloud-init network-config all handle v4 and v6
identically:

```yaml
networks:
  v6lan:
    type: "bridge"
    interface: "br0"
    subnet: "2001:db8:1::/64"
    dhcp: true     # enables DHCPv6 + Router Advertisements via dnsmasq
```

Notes:

- For v6, the gateway is `<network>::1` (e.g., `2001:db8:1::1`) and IP
  allocation starts at `<network>::2`. Up to 65 535 host addresses are
  enumerable per subnet (caps the IPAM scan; SLAAC-only deployments
  bypass this entirely).
- When `dhcp: true` on a v6 subnet, dnsmasq runs with `--enable-ra` so
  SLAAC-only guests still get a default route.
- VMs can have static v6 addresses via `ip:` on the network attachment
  (cloud-init network-config v1 handles them as `address: 2001:db8::42/64`),
  or via the dedicated `ipv6:` / `ipv6-gateway:` fields when running dual-stack
  alongside a v4 `ip:`:

  ```yaml
      network:
        - name: "v6lan"
          ip: "10.0.1.50"
          gateway: "10.0.1.1"
          ipv6: "2001:db8:1::42"
          ipv6-gateway: "2001:db8:1::1"
  ```

  An empty `ipv6:` falls back to SLAAC / DHCPv6 if the network is configured
  for it.
- Mixed dual-stack works: declare both v4 and v6 subnets on the same
  bridge if your guest expects both.

## DNS

litevirt runs a lightweight DNS server (default port 5354) that resolves VM **and managed-container** names to IP addresses. Records are created and removed automatically as workloads get an IP, move, or are deleted.

Name format: `<name>.<stack>.<domain>` in a stack, or `<name>.<domain>` standalone — the same namespace for VMs and containers. For example, with the default domain `litevirt.local`, `web-1` in the `myapp` stack resolves as `web-1.myapp.litevirt.local`. A managed container's record is maintained by the per-host IP scanner (which discovers a DHCP address, persists it, and writes the record); a migrate re-creates it on the target.

Configure the domain in `config.yaml`:

```yaml
dns_domain: "litevirt.local"
dns_port: 5354
```

## Security groups

Security groups **are implemented and enforced.** They provide per-VM
firewall rules via nftables, applied by the per-host firewall reconciler
that polls cluster state every 30 s. See [firewall.md](firewall.md) for
the full three-tier model (cluster / host / VM), the `lv sg` CLI, and
the AWS/GCP/Proxmox direction semantics.

Compose syntax (top-level `security-groups:`, referenced per-NIC):

```yaml
security-groups:
  web-sg:
    rules:
      - direction: "ingress"
        proto: "tcp"
        port: "80"
        cidr: "0.0.0.0/0"
        action: "accept"
      - direction: "ingress"
        proto: "tcp"
        port: "22"
        cidr: "10.0.0.0/8"
        action: "accept"

vms:
  web:
    network:
      - name: "lan"
        security-groups: [web-sg]
```
