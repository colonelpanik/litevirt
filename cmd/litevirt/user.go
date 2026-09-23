package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/secretfile"
)

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users and API tokens",
	}
	cmd.AddCommand(
		newUserCreateCmd(),
		newUserListCmd(),
		newUserDeleteCmd(),
		newUserPasswdCmd(),
		newTokenCreateCmd(),
		newTokenRevokeCmd(),
		newUserResetAdminCmd(),
	)
	return cmd
}

// newUserPasswdCmd changes a local-realm password: your own (after the current
// one) or, as admin, another user's (a reset, no old password needed).
func newUserPasswdCmd() *cobra.Command {
	var oldPw, newPw string
	cmd := &cobra.Command{
		Use:   "passwd [username]",
		Short: "Change a password (your own, or another user's as admin)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var username string
			if len(args) == 1 {
				username = args[0]
			}
			if newPw == "" {
				var err error
				if newPw, err = cli.ReadPassword("New password: "); err != nil {
					return err
				}
				confirm, err := cli.ReadPassword("Confirm new password: ")
				if err != nil {
					return err
				}
				if confirm != newPw {
					return fmt.Errorf("passwords do not match")
				}
			}
			// Changing your own password requires the current one; an admin
			// resetting another user's password does not.
			if username == "" && oldPw == "" {
				var err error
				if oldPw, err = cli.ReadPassword("Current password: "); err != nil {
					return err
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.ChangePassword(ctx, &pb.ChangePasswordRequest{
					Username: username, OldPassword: oldPw, NewPassword: newPw,
				}); err != nil {
					return err
				}
				fmt.Println("Password changed.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&oldPw, "old-password", "", "current password (prompts if unset; not needed for an admin reset of another user)")
	cmd.Flags().StringVar(&newPw, "new-password", "", "new password (prompts if unset)")
	return cmd
}

func newUserCreateCmd() *cobra.Command {
	var role string
	var password string
	cmd := &cobra.Command{
		Use:   "create <username>",
		Short: "Create a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				var err error
				password, err = cli.ReadPassword("Password: ")
				if err != nil {
					return err
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				u, err := c.CreateUser(ctx, &pb.CreateUserRequest{
					Username: args[0],
					Password: password,
					Role:     role,
				})
				if err != nil {
					return err
				}
				fmt.Printf("Created user %q (role: %s)\n", u.Username, u.Role)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&role, "role", "viewer", "Role: admin, operator, viewer")
	cmd.Flags().StringVar(&password, "password", "", "Password (reads from terminal if not set)")
	return cmd
}

func newUserListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListUsers(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "USERNAME\tROLE\tCREATED")
				for _, u := range resp.Users {
					created := ""
					if u.CreatedAt != nil {
						created = u.CreatedAt.AsTime().Format("2006-01-02")
					}
					fmt.Fprintf(w, "%s\t%s\t%s\n", u.Username, u.Role, created)
				}
				return w.Flush()
			})
		},
	}
}

func newUserDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <username>",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteUser(ctx, &pb.DeleteUserRequest{Username: args[0]})
				if err != nil {
					return err
				}
				fmt.Printf("Deleted user %q\n", args[0])
				return nil
			})
		},
	}
}

func newTokenCreateCmd() *cobra.Command {
	var expires string
	var scopePaths []string
	cmd := &cobra.Command{
		Use:   "token-create <username> <token-name>",
		Short: "Create an API token for a user",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				tok, err := c.CreateToken(ctx, &pb.CreateTokenRequest{
					Username:   args[0],
					Name:       args[1],
					Expires:    expires,
					ScopePaths: scopePaths,
				})
				if err != nil {
					return err
				}
				fmt.Printf("Token ID:  %s\n", tok.Id)
				fmt.Printf("Token:     %s\n", tok.Token)
				if len(scopePaths) > 0 {
					fmt.Printf("Scope:     %v\n", scopePaths)
				}
				fmt.Println("\nSave this token — it will not be shown again.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry time (RFC3339, e.g. 2026-12-31T00:00:00Z)")
	cmd.Flags().StringSliceVar(&scopePaths, "scope-path", nil,
		"Restrict the token to a path subtree (repeatable; e.g. --scope-path /projects/acme)")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "token-revoke <token-id>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.RevokeToken(ctx, &pb.RevokeTokenRequest{Id: args[0]})
				if err != nil {
					return err
				}
				fmt.Printf("Token %q revoked\n", args[0])
				return nil
			})
		},
	}
}

func newUserResetAdminCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset-admin",
		Short: "Reset admin password (must run on a cluster node)",
		Long: `Resets the admin user's password to a new random value.
This command connects directly to the local Corrosion database and
must be run on a node where litevirtd is installed.
The new password is written to /etc/litevirt/admin-password.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := daemon.LoadConfig()
			if err != nil {
				return fmt.Errorf("load config (is this a litevirt node?): %w", err)
			}

			db, err := corrosion.NewLocalClient(cfg.DataDir, cfg.HostName)
			if err != nil {
				return fmt.Errorf("connect to corrosion: %w", err)
			}
			defer db.Close()

			ctx := cmd.Context()

			return resetAdminPassword(ctx, db, adminPasswordPath)
		},
	}
}

// adminPasswordPath is where reset-admin writes the new credential.
const adminPasswordPath = "/etc/litevirt/admin-password"

// resetAdminPassword re-mints the local admin account's password.
//
// It RESETS only. It used to create an admin when GetUser returned nil, and that
// was two bugs at once:
//
//   - GetUser filters `deleted_at IS NULL`, so a deliberately deleted admin read
//     as absent — and InsertUser reactivates a soft-deleted row rather than
//     inserting, so the "create" silently un-deleted a revoked account, gave it a
//     fresh password and replicated it to every peer.
//
//   - On a node that has joined but not yet converged, `users` is legitimately
//     empty. Minting there produces a row with a current updated_at that wins LWW
//     and replaces the cluster's real admin credential — the same failure the
//     daemon's own seed guard exists to prevent, reached through the CLI. It is
//     the path an operator is pushed down, because a joining node deliberately
//     writes no password file and this is the documented recovery command.
//
// Nothing is lost by refusing: founding a cluster mints the admin through
// `lv host init` and the daemon's founder path, and a joined node receives it by
// replication.
func resetAdminPassword(ctx context.Context, db *corrosion.Client, pwPath string) error {
	existing, err := corrosion.GetUser(ctx, db, "admin")
	if err != nil {
		// A read that fails must not read as absence.
		return fmt.Errorf("look up the admin account: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("no live admin account in this node's local database — " +
			"reset-admin resets an existing credential, it does not create one. " +
			"On a node that has joined a cluster the admin credential replicates in; " +
			"wait for this node to converge and try again. On a brand-new cluster the " +
			"founder's `lv host init` mints it. If the admin account was deliberately " +
			"deleted, it stays deleted")
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	password := hex.EncodeToString(b)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		return err
	}
	if err := corrosion.UpdateUserPassword(ctx, db, "admin", string(hash)); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if err := secretfile.Write(pwPath, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("write password file: %w", err)
	}
	fmt.Println("Admin password reset.")
	fmt.Printf("New password written to %s\n", pwPath)
	return nil
}
