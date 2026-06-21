package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Show cluster health matrix",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GetHostHealth(ctx, nil)
				if err != nil {
					return fmt.Errorf("get host health: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "OBSERVER\tTARGET\tSTATUS\tFAILURES\tLAST SEEN")
				for _, e := range resp.Entries {
					lastSeen := "-"
					if e.LastSeen != nil {
						ago := time.Since(e.LastSeen.AsTime()).Truncate(time.Second)
						lastSeen = ago.String() + " ago"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
						e.Observer, e.Target, e.Status,
						e.ConsecutiveFailures, lastSeen,
					)
				}
				return w.Flush()
			})
		},
	}
}
