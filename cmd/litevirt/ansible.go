package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ansibleInventory is the JSON structure Ansible expects.
// See: https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html
type ansibleInventory struct {
	All  ansibleGroup `json:"all"`
	Meta ansibleMeta  `json:"_meta"`
	// per-stack groups are embedded in All.Children
}

type ansibleGroup struct {
	Hosts    []string          `json:"hosts,omitempty"`
	Children []string          `json:"children,omitempty"`
	Vars     map[string]string `json:"vars,omitempty"`
}

type ansibleMeta struct {
	HostVars map[string]map[string]string `json:"hostvars"`
}

func newAnsibleInventoryCmd() *cobra.Command {
	var (
		list bool
		host string
	)
	cmd := &cobra.Command{
		Use:   "ansible-inventory",
		Short: "Output dynamic Ansible inventory from litevirt",
		Long: `Outputs a JSON inventory suitable for use as an Ansible dynamic inventory script.

Usage in ansible.cfg or on the command line:
  ansible -i 'lv ansible-inventory --list' all -m ping
  ansible-playbook -i 'lv ansible-inventory --list' site.yml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(_ context.Context, c pb.LiteVirtClient) error {
				if host != "" {
					// --host <hostname>: return hostvars for a single host.
					return printHostVars(cmd, c, host)
				}
				// --list: return full inventory.
				return printInventory(cmd, c)
			})
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "Output full inventory (required by Ansible)")
	cmd.Flags().StringVar(&host, "host", "", "Output hostvars for a single host")
	return cmd
}

func printInventory(cmd *cobra.Command, c pb.LiteVirtClient) error {
	ctx := cmd.Context()

	vms, err := c.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}

	inv := ansibleInventory{
		All: ansibleGroup{},
		Meta: ansibleMeta{
			HostVars: make(map[string]map[string]string),
		},
	}

	// Track groups.
	stackGroups := make(map[string][]string) // stack → []vmIP
	hostGroups := make(map[string][]string)  // host → []vmIP
	labelGroups := make(map[string][]string) // label_key_value → []vmIP

	for _, vm := range vms.Vms {
		if vm.State != pb.VMState_VM_RUNNING {
			continue
		}
		ip := firstIP(vm)
		if ip == "" {
			continue
		}

		inv.All.Hosts = append(inv.All.Hosts, ip)
		hvars := map[string]string{
			"ansible_host":     ip,
			"litevirt_vm_name": vm.Name,
			"litevirt_stack":   vm.StackName,
			"litevirt_host":    vm.HostName,
			"litevirt_state":   vm.State.String(),
		}
		if vm.Spec != nil {
			for k, v := range vm.Spec.Labels {
				hvars["litevirt_label_"+k] = v
			}
		}
		inv.Meta.HostVars[ip] = hvars

		if vm.StackName != "" {
			stackGroups[vm.StackName] = append(stackGroups[vm.StackName], ip)
			groupKey := "stack_" + vm.StackName
			if !containsStr(inv.All.Children, groupKey) {
				inv.All.Children = append(inv.All.Children, groupKey)
			}
		}

		if vm.HostName != "" {
			hostGroups[vm.HostName] = append(hostGroups[vm.HostName], ip)
			groupKey := "host_" + vm.HostName
			if !containsStr(inv.All.Children, groupKey) {
				inv.All.Children = append(inv.All.Children, groupKey)
			}
		}

		if vm.Spec != nil {
			for k, v := range vm.Spec.Labels {
				groupKey := "label_" + k + "_" + v
				labelGroups[groupKey] = append(labelGroups[groupKey], ip)
				if !containsStr(inv.All.Children, groupKey) {
					inv.All.Children = append(inv.All.Children, groupKey)
				}
			}
		}
	}

	// Build full output: merge sub-groups into top-level map.
	out := map[string]interface{}{
		"all":   inv.All,
		"_meta": inv.Meta,
	}
	for stack, hosts := range stackGroups {
		out["stack_"+stack] = ansibleGroup{Hosts: hosts}
	}
	for host, hosts := range hostGroups {
		out["host_"+host] = ansibleGroup{Hosts: hosts}
	}
	for label, hosts := range labelGroups {
		out[label] = ansibleGroup{Hosts: hosts}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printHostVars(cmd *cobra.Command, c pb.LiteVirtClient, hostIP string) error {
	ctx := cmd.Context()

	vms, err := c.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}

	for _, vm := range vms.Vms {
		if firstIP(vm) == hostIP {
			vars := map[string]string{
				"ansible_host":     hostIP,
				"litevirt_vm_name": vm.Name,
				"litevirt_stack":   vm.StackName,
				"litevirt_host":    vm.HostName,
				"litevirt_state":   vm.State.String(),
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(vars)
		}
	}

	// Not found — return empty JSON object (Ansible requirement).
	fmt.Fprintln(cmd.OutOrStdout(), "{}")
	return nil
}

func firstIP(vm *pb.VM) string {
	for _, iface := range vm.Interfaces {
		if iface.Ip != "" {
			return iface.Ip
		}
	}
	return ""
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
