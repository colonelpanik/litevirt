package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newNotifyCmd manages operator notification targets + routes (#5).
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "notify", Short: "Manage operator notifications (webhook/Slack)"}
	cmd.AddCommand(newNotifyTargetCmd(), newNotifyRouteCmd(), newNotifyTestCmd())
	return cmd
}

func newNotifyTargetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "target", Short: "Manage notification targets"}
	cmd.AddCommand(newNotifyTargetAddCmd(), newNotifyTargetLsCmd(), newNotifyTargetRmCmd())
	return cmd
}

func newNotifyTargetAddCmd() *cobra.Command {
	var name, typ, url string
	var disabled bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a notification target (webhook or slack)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if url == "" {
				return fmt.Errorf("--url is required")
			}
			cfg, _ := json.Marshal(map[string]string{"url": url})
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				t, err := c.CreateNotificationTarget(ctx, &pb.CreateNotificationTargetRequest{
					Name: name, Type: typ, Config: string(cfg), Enabled: !disabled,
				})
				if err != nil {
					return fmt.Errorf("add target: %w", err)
				}
				fmt.Printf("Target %q (%s) created: %s\n", t.Name, t.Type, t.Id)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "target name (required)")
	cmd.Flags().StringVar(&typ, "type", "webhook", "target type: webhook | slack")
	cmd.Flags().StringVar(&url, "url", "", "webhook / Slack incoming-webhook URL (required)")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create disabled")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newNotifyTargetLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List notification targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNotificationTargets(ctx, &pb.ListNotificationTargetsRequest{})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "ID\tNAME\tTYPE\tENABLED\tCONFIG\n")
				for _, t := range resp.Targets {
					fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\n", t.Id, t.Name, t.Type, t.Enabled, t.Config)
				}
				return w.Flush()
			})
		},
	}
}

func newNotifyTargetRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a notification target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteNotificationTarget(ctx, &pb.DeleteNotificationTargetRequest{Id: args[0]}); err != nil {
					return err
				}
				fmt.Printf("Target %s deleted\n", args[0])
				return nil
			})
		},
	}
}

func newNotifyRouteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "route", Short: "Manage notification routes"}
	cmd.AddCommand(newNotifyRouteAddCmd(), newNotifyRouteLsCmd(), newNotifyRouteRmCmd())
	return cmd
}

func newNotifyRouteAddCmd() *cobra.Command {
	var pattern, target, minSeverity string
	var disabled bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Route an event pattern to a target",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				r, err := c.CreateNotificationRoute(ctx, &pb.CreateNotificationRouteRequest{
					EventPattern: pattern, TargetId: target, MinSeverity: minSeverity, Enabled: !disabled,
				})
				if err != nil {
					return fmt.Errorf("add route: %w", err)
				}
				fmt.Printf("Route %s → target %s (%s, ≥%s) created\n", r.EventPattern, r.TargetId, r.Id, r.MinSeverity)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&pattern, "pattern", "*", "event glob: '*', 'backup.*', 'host.fenced'")
	cmd.Flags().StringVar(&target, "target", "", "target ID (required)")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "info", "info | warn | error")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create disabled")
	cmd.MarkFlagRequired("target")
	return cmd
}

func newNotifyRouteLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List notification routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNotificationRoutes(ctx, &pb.ListNotificationRoutesRequest{})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "ID\tPATTERN\tTARGET\tMIN-SEVERITY\tENABLED\n")
				for _, r := range resp.Routes {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\n", r.Id, r.EventPattern, r.TargetId, r.MinSeverity, r.Enabled)
				}
				return w.Flush()
			})
		},
	}
}

func newNotifyRouteRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a notification route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteNotificationRoute(ctx, &pb.DeleteNotificationRouteRequest{Id: args[0]}); err != nil {
					return err
				}
				fmt.Printf("Route %s deleted\n", args[0])
				return nil
			})
		},
	}
}

func newNotifyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <target-id>",
		Short: "Send a test notification to a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.TestNotificationTarget(ctx, &pb.TestNotificationTargetRequest{Id: args[0]}); err != nil {
					return fmt.Errorf("test: %w", err)
				}
				fmt.Println("Test notification sent.")
				return nil
			})
		},
	}
}
