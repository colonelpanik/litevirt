# GPU & PCI Passthrough

litevirt supports assigning PCI devices (GPUs, NICs, NVMe drives) directly to VMs for near-native hardware performance.

## Prerequisites

1. **IOMMU enabled** in BIOS and kernel:

```bash
# Intel
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"

# AMD
GRUB_CMDLINE_LINUX="amd_iommu=on iommu=pt"
```

Update GRUB and reboot after changes.

2. **vfio-pci module loaded:**

```bash
modprobe vfio-pci
echo "vfio-pci" >> /etc/modules-load.d/vfio.conf
```

3. **Device not bound to host driver** — litevirt handles binding/unbinding automatically.

## Discovering devices

List PCI devices on a host:

```bash
lv host devices host-a
lv host devices host-a --type gpu
lv host devices host-a --type network
lv host devices host-a --type nvme
```

Rescan to detect newly added devices:

```bash
lv host rescan host-a
```

litevirt tracks PCI topology including IOMMU groups, NUMA nodes, PCIe root ports, and NVLink cliques.

## Assigning devices in compose

### By type and vendor

```yaml
vms:
  ml-worker:
    image: "ubuntu-cuda"
    cpu: 16
    memory: "64G"
    devices:
      - type: "gpu"
        vendor: "10de"          # NVIDIA
        count: 2                # Request 2 GPUs
```

The placement engine selects a host with enough free devices matching the criteria. It prefers devices in the same NUMA node as the VM's CPU allocation and in the same NVLink clique for multi-GPU workloads.

### By exact PCI address

```yaml
    devices:
      - type: "gpu"
        address: "0000:41:00.0"
```

### Common vendor IDs

| Vendor | ID | Common devices |
|--------|----|----------------|
| NVIDIA | `10de` | GPUs (A100, H100, RTX) |
| AMD | `1002` | GPUs (MI300, Instinct) |
| Intel | `8086` | NICs, QAT accelerators |
| Mellanox | `15b3` | ConnectX NICs, InfiniBand HCAs |

## SR-IOV virtual functions

SR-IOV lets a single physical NIC present multiple virtual functions (VFs), each assignable to a different VM.

### Compose configuration

```yaml
networks:
  fast-net:
    type: "sriov"
    pf: "eth1"
    spoof-check: true

vms:
  worker:
    devices:
      - type: "network"
        sriov: true
        parent: "eth1"
        count: 1
```

### Daemon configuration

```yaml
pci:
  sriov:
    managed: true                    # litevirt may CREATE a VF pool on an adopted PF
    max_vfs_per_pf: 8                # pool size, clamped to the PF's hardware max
    managed_pfs: ["0000:41:00.0"]    # PFs litevirt may create VFs on (allowlist)
```

VF allocation follows a strict policy:

- **Reuse first, on any PF.** litevirt claims a free VF (one present on the host and
  unassigned in inventory) via an atomic compare-and-set. This works whether or not
  the PF is managed, and it **never writes `sriov_numvfs`**.
- **Create only on an adopted, empty PF.** When `managed: true` and the PF is in
  `managed_pfs` and its VF pool is currently empty, litevirt creates a pool of
  `min(max_vfs_per_pf, hardware sriov_totalvfs)` VFs **once**, then claims exactly what
  the request needs. A request larger than that cap is rejected up front.
- **Never resizes.** litevirt does not grow, shrink, or destroy a VF pool. A PF that
  already has more VFs than `max_vfs_per_pf` is marked degraded
  (`litevirt_sriov_degraded{reason="vfs_over_cap"}`); its existing free VFs can still be
  reused, but litevirt refuses to (re)create its pool. A PF with a non-empty pool short
  of free VFs fails the request with **no sysfs write**.

With `managed: false` (default), the operator provisions VFs; litevirt reuses the free
ones but never creates any:

```bash
echo 8 > /sys/class/net/eth1/device/sriov_numvfs
```

Configured-but-broken managed PFs surface as `litevirt_sriov_degraded` with
`reason="pf_not_found"` (malformed/absent BDF) or `reason="pf_not_sriov"` (not SR-IOV
capable); the gauge is aggregated across all PFs, so a reason stays set while any PF
still has it.

> Mixed-version note: SR-IOV policy is enforced by the host that owns the hardware. Do
> not set `managed: true` on a PF until its owning host runs a build that supports this
> policy — an older daemon ignores the allowlist and cap.

## Hot-plug

Attach a GPU to a running VM:

```bash
lv attach-pci my-vm --type gpu --vendor 10de
```

Detach a device:

```bash
lv detach-pci my-vm 0000:41:00.0
```

Hot-plug is supported for most PCI devices. Some devices (particularly GPUs with active CUDA contexts) may require the VM to be stopped first.

## Placement intelligence

When a VM requests PCI devices, the placement engine considers:

- **IOMMU groups** — all devices in a group must be assigned together
- **NUMA locality** — prefers devices on the same NUMA node as the VM's CPUs
- **NVLink topology** — for multi-GPU requests, prefers GPUs connected via NVLink
- **PCIe root port** — tracks which devices share PCIe bandwidth

## Migration with PCI devices

PCI passthrough devices cannot be live-migrated. Options:

1. Hot-detach the device, migrate, hot-attach on the new host
2. Cold migrate (stops the VM)
3. Use SR-IOV VFs which can be detached/reattached more gracefully

The migration command will fail with an error if the VM has PCI devices attached and `--cold` is not specified.

## Resource mappings

A **resource mapping** is a cluster-wide alias for an equivalent passthrough device
that exists (at possibly different PCI addresses) on more than one host. A VM that
requests a device *by mapping name* can be placed on — or migrated to — any host
registered under that mapping; litevirt resolves the name to the concrete PCI
address on the target host at allocation time. This is the litevirt analog of
Proxmox 8 "resource mappings".

```bash
lv mapping create gpu-a100 --description "NVIDIA A100 pool"
lv mapping add-device gpu-a100 0000:41:00.0 --host kvm-01 --vendor 10de --device A100
lv mapping add-device gpu-a100 0000:81:00.0 --host kvm-02 --vendor 10de --device A100
lv mapping ls
```

Reference it from a VM via the compose device spec:

```yaml
    devices:
      - mapping: "gpu-a100"
```

Mappings are CRDT-replicated (the `resource_mappings` table), so every daemon and the
`/resource-mappings` UI page see a consistent view. Placement/migration eligibility
checks that a candidate host has a device registered under each mapping the VM needs.
