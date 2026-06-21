#!/usr/bin/env python3
"""
Ansible dynamic inventory plugin for litevirt.

Usage as an inventory script:
    ansible -i litevirt_inventory.py all -m ping

Usage as an Ansible inventory plugin (ansible.cfg):
    [inventory]
    enable_plugins = litevirt_inventory

    # litevirt.yml
    plugin: litevirt_inventory
    lv_binary: /usr/local/bin/lv
    lv_host: node1.example.com

Or as an external script:
    chmod +x litevirt_inventory.py
    ansible-playbook -i ./litevirt_inventory.py playbook.yml
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

try:
    from ansible.plugins.inventory import BaseInventoryPlugin

    HAS_ANSIBLE = True
except ImportError:
    HAS_ANSIBLE = False

DOCUMENTATION = """
    name: litevirt_inventory
    plugin_type: inventory
    short_description: litevirt dynamic inventory
    description:
        - Fetches VM inventory from a litevirt cluster via the lv CLI.
        - Groups VMs by stack, host, and labels.
    options:
        lv_binary:
            description: Path to the lv CLI binary.
            default: lv
            env:
                - name: LV_BINARY
        lv_host:
            description: Target litevirt host (passed as LV_HOST env var).
            env:
                - name: LV_HOST
"""


def _run_lv(lv_binary: str, lv_host: str | None) -> dict:
    """Run `lv ansible-inventory --list` and return parsed JSON."""
    env = os.environ.copy()
    if lv_host:
        env["LV_HOST"] = lv_host

    result = subprocess.run(
        [lv_binary, "ansible-inventory", "--list"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"lv ansible-inventory failed (rc={result.returncode}): {result.stderr}"
        )

    return json.loads(result.stdout)


if HAS_ANSIBLE:

    class InventoryModule(BaseInventoryPlugin):
        NAME = "litevirt_inventory"

        def verify_file(self, path: str) -> bool:
            if super().verify_file(path):
                return path.endswith(("litevirt.yml", "litevirt.yaml"))
            return False

        def parse(self, inventory, loader, path, cache=True):
            super().parse(inventory, loader, path, cache)
            self._read_config_data(path)

            lv_binary = self.get_option("lv_binary") or "lv"
            lv_host = self.get_option("lv_host") or os.environ.get("LV_HOST")

            data = _run_lv(lv_binary, lv_host)
            meta = data.get("_meta", {})
            hostvars = meta.get("hostvars", {})

            # Add all hosts
            all_group = data.get("all", {})
            for host in all_group.get("hosts", []):
                self.inventory.add_host(host)
                for var_name, var_val in hostvars.get(host, {}).items():
                    self.inventory.set_variable(host, var_name, var_val)

            # Add child groups
            for group_name in all_group.get("children", []):
                self.inventory.add_group(group_name)
                group_data = data.get(group_name, {})
                for host in group_data.get("hosts", []):
                    self.inventory.add_host(host, group=group_name)

            # Add host-based groups from hostvars
            for host, hvars in hostvars.items():
                lv_host_name = hvars.get("litevirt_host", "")
                if lv_host_name:
                    group = f"host_{lv_host_name}"
                    self.inventory.add_group(group)
                    self.inventory.add_host(host, group=group)


def main():
    """Standalone script mode for use as an external inventory script."""
    import argparse

    parser = argparse.ArgumentParser(description="litevirt Ansible inventory")
    parser.add_argument("--list", action="store_true", help="List all hosts")
    parser.add_argument("--host", help="Get hostvars for a specific host")
    args = parser.parse_args()

    lv_binary = os.environ.get("LV_BINARY", "lv")
    lv_host = os.environ.get("LV_HOST")

    if args.host:
        # Return hostvars for a single host.
        data = _run_lv(lv_binary, lv_host)
        hostvars = data.get("_meta", {}).get("hostvars", {})
        print(json.dumps(hostvars.get(args.host, {}), indent=2))
    else:
        # --list (default)
        data = _run_lv(lv_binary, lv_host)
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
