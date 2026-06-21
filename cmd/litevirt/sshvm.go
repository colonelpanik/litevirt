package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newSSHCmd() *cobra.Command {
	var (
		user    string
		port    int
		keyFile string
	)
	cmd := &cobra.Command{
		Use:   "ssh <vm-name> [-- command...]",
		Short: "Open an SSH session to a VM",
		Long: `SSH into a VM by looking up its IP from the first network interface.

The VM must be running and have an IP address assigned (requires qemu-guest-agent
or DHCP with address reporting). Connects directly to the VM's IP — ensure your
network can reach it.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]
			remoteArgs := args[1:]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				vm, err := c.InspectVM(ctx, &pb.InspectVMRequest{Name: vmName})
				if err != nil {
					return fmt.Errorf("inspect VM: %w", err)
				}
				if vm.State != pb.VMState_VM_RUNNING {
					return fmt.Errorf("VM %q is not running (state: %s)", vmName, vm.State)
				}

				// Find first interface with an IP.
				ip := ""
				for _, iface := range vm.Interfaces {
					if iface.Ip != "" {
						ip = iface.Ip
						break
					}
				}
				if ip == "" {
					return fmt.Errorf("VM %q has no IP address assigned yet; try again in a moment", vmName)
				}

				sshUser := user
				if sshUser == "" {
					sshUser = "root"
				}

				// Build ssh argument list.
				sshArgs := []string{
					"-o", "StrictHostKeyChecking=accept-new",
					"-o", "ConnectTimeout=10",
				}
				if port != 0 {
					sshArgs = append(sshArgs, "-p", fmt.Sprintf("%d", port))
				}
				if keyFile != "" {
					sshArgs = append(sshArgs, "-i", keyFile)
				}
				sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", sshUser, ip))
				sshArgs = append(sshArgs, remoteArgs...)

				sshBin, err := exec.LookPath("ssh")
				if err != nil {
					return fmt.Errorf("ssh not found in PATH: %w", err)
				}

				// Replace this process with ssh (exec).
				return syscall.Exec(sshBin, append([]string{"ssh"}, sshArgs...), os.Environ())
			})
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "SSH username (default: root)")
	cmd.Flags().IntVarP(&port, "port", "p", 0, "SSH port (default: 22)")
	cmd.Flags().StringVarP(&keyFile, "identity", "i", "", "SSH identity file (private key)")
	return cmd
}
