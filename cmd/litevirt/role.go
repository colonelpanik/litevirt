package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newRoleCmd is the operator surface for path-based RBAC role
// bindings. The engine itself lives in `internal/auth/permissions.go`;
// this CLI is a thin wrapper around the GrantRole / RevokeRole /
// ListRoleBindings gRPC RPCs.
//
// Roles are named permission sets seeded by `auth.SeedBuiltinRoles`:
// Admin, Operator, VMOperator, NetworkOperator, StorageOperator,
// Viewer, Auditor. Operators define their own custom roles via the
// `roles` table; this CLI doesn't yet wrap that — set custom roles
// by direct config or future CLI extension.
func newRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage path-based RBAC role bindings",
	}
	cmd.AddCommand(
		newRoleGrantCmd(),
		newRoleRevokeCmd(),
		newRoleListCmd(),
		newRoleNormalizeCmd(),
	)
	return cmd
}

func newRoleGrantCmd() *cobra.Command {
	var path string
	var propagate bool
	cmd := &cobra.Command{
		Use:   "grant <role> <principal>",
		Short: "Grant a role to a user or group at a path scope",
		Long: `Grant a role at an RBAC path. Principal forms:

  user:<username>
  group:<group>@<realm>

Examples:
  lv role grant Admin user:alice --path /
  lv role grant Operator group:platform-team@oidc --path /projects/acme --propagate
  lv role grant Viewer user:contractor --path /projects/acme/vms/web-1

--propagate causes the binding to apply to every descendant path scope,
not just the named one. Without --propagate the binding only matches
exact path lookups.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, principal := args[0], args[1]
			if path == "" {
				return fmt.Errorf("--path is required (use / for cluster scope)")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.GrantRole(ctx, &pb.GrantRoleRequest{
					Path:      path,
					Role:      role,
					Principal: principal,
					Propagate: propagate,
				})
				if err != nil {
					return fmt.Errorf("grant role: %w", err)
				}
				fmt.Printf("granted: id=%s path=%s role=%s principal=%s propagate=%v\n",
					resp.Binding.Id, resp.Binding.Path, resp.Binding.Role,
					resp.Binding.Principal, resp.Binding.Propagate)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "RBAC path scope (e.g. / or /projects/acme)")
	cmd.Flags().BoolVar(&propagate, "propagate", false, "Apply binding to all descendant paths")
	return cmd
}

func newRoleRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <binding-id>",
		Short: "Soft-delete a role binding by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RevokeRole(ctx, &pb.RevokeRoleRequest{Id: args[0]}); err != nil {
					return fmt.Errorf("revoke role: %w", err)
				}
				fmt.Printf("revoked: %s\n", args[0])
				return nil
			})
		},
	}
}

func newRoleNormalizeCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "normalize",
		Short: "Rewrite legacy bare user bindings to realm-qualified form",
		Long: `Rewrite legacy bare 'user:<name>' role bindings to the canonical
realm-qualified form ('user:<name>@<realm>') so they enforce. This is a
deliberate, idempotent one-time migration: run it once after enabling
auth.rbac_realm fleet-wide and waiting for the rbac_realm_v1 capability to
latch cluster-wide. A bare binding whose realm can't be resolved (not a known
local user) is left untouched and reported as skipped.

Use --dry-run to preview counts without writing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.NormalizeRoleBindings(ctx, &pb.NormalizeRoleBindingsRequest{DryRun: dryRun})
				if err != nil {
					return fmt.Errorf("normalize role bindings: %w", err)
				}
				verb := "normalized"
				if dryRun {
					verb = "would normalize"
				}
				fmt.Printf("%s %d binding(s); skipped %d (unresolvable realm)\n",
					verb, resp.Normalized, resp.Skipped)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview counts without writing")
	return cmd
}

func newRoleListCmd() *cobra.Command {
	var principal string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List role bindings",
		Long: `List role bindings. Without --principal, admins see all bindings
and non-admins see only their own. With --principal, the daemon
filters server-side; non-admins may only filter to their own
principal.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListRoleBindings(ctx, &pb.ListRoleBindingsRequest{
					Principal: principal,
				})
				if err != nil {
					return fmt.Errorf("list role bindings: %w", err)
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tPATH\tROLE\tPRINCIPAL\tPROPAGATE\tUPDATED")
				for _, b := range resp.Bindings {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\n",
						b.Id, b.Path, b.Role, b.Principal, b.Propagate, b.UpdatedAt)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&principal, "principal", "", "Filter to a single principal (user:foo or group:bar@realm)")
	return cmd
}
