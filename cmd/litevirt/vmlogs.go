package main

import (
	"context"
	"io"
	"os"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newLogsCmd() *cobra.Command {
	var (
		follow bool
		lines  int
	)

	cmd := &cobra.Command{
		Use:   "logs <vm>",
		Short: "Fetch logs for a VM from its host",
		Long: `Stream or print the libvirt QEMU log for a VM.

Reads /var/log/libvirt/qemu/<vm>.log via gRPC.
Use --follow / -f to stream new log lines in real time.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vmName := args[0]

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.GetVMLogs(ctx, &pb.GetVMLogsRequest{
					Name:   vmName,
					Follow: follow,
					Lines:  int32(lines),
				})
				if err != nil {
					return err
				}

				for {
					chunk, err := stream.Recv()
					if err != nil {
						if err == io.EOF {
							return nil
						}
						return err
					}
					os.Stdout.Write(chunk.Data)
				}
			})
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Stream new log lines (like tail -f)")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of log lines to show")

	return cmd
}
