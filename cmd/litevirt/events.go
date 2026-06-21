package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newEventsCmd() *cobra.Command {
	var types []string
	var limit int32
	var since string

	cmd := &cobra.Command{
		Use:   "events [vm]",
		Short: "Stream cluster events live, or show one VM's activity history",
		Long: `Without an argument, streams cluster events live (Ctrl-C to stop).
With a VM name, prints that VM's recorded activity history — lifecycle
transitions and backup outcomes (e.g. when a VM failed to back up).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// History mode: a VM name was given.
			if len(args) == 1 {
				return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
					resp, err := c.ListVMEvents(ctx, &pb.ListVMEventsRequest{
						VmName: args[0], Limit: limit, Since: since,
					})
					if err != nil {
						return fmt.Errorf("list vm events: %w", err)
					}
					w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
					fmt.Fprintln(w, "TIMESTAMP\tTYPE\tRESULT\tHOST\tDETAIL")
					for _, e := range resp.Events {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
							e.Ts, e.Type, e.Result, e.HostName, e.Detail)
					}
					return w.Flush()
				})
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.StreamEvents(ctx, &pb.StreamEventsRequest{
					EventTypes: types,
				})
				if err != nil {
					return err
				}

				fmt.Printf("%-25s  %-20s  %-20s  %s\n", "TIME", "ACTION", "TARGET", "DETAIL")
				fmt.Println(strings.Repeat("─", 80))

				for {
					ev, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						return err
					}

					ts := ""
					if ev.Timestamp != nil {
						ts = ev.Timestamp.AsTime().Local().Format("2006-01-02 15:04:05")
					}
					fmt.Printf("%-25s  %-20s  %-20s  %s\n", ts, ev.Action, ev.Target, ev.Detail)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringSliceVar(&types, "type", nil, "Filter live stream by event type (comma-separated, e.g. vm.created,vm.deleted)")
	cmd.Flags().Int32Var(&limit, "limit", 50, "History mode: max events to return")
	cmd.Flags().StringVar(&since, "since", "", "History mode: only events at/after this RFC3339 timestamp")
	return cmd
}
