package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

func newLoginCmd() *cobra.Command {
	var realm string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to the cluster with username and password",
		RunE: func(cmd *cobra.Command, args []string) error {
			var username string
			fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
			if _, err := fmt.Fscanln(cmd.InOrStdin(), &username); err != nil {
				return fmt.Errorf("read username: %w", err)
			}

			password, err := cli.ReadPassword("Password: ")
			if err != nil {
				return err
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.Login(ctx, &pb.LoginRequest{
					Username: username,
					Password: password,
					Realm:    realm,
				})
				if err != nil {
					return fmt.Errorf("login failed: %w", err)
				}

				// 2FA gate: server returns Requires_2Fa with empty token; prompt
				// for the second factor and re-call Login.
				if resp.Requires_2Fa {
					code, err := cli.ReadPassword("2FA code (or recovery code): ")
					if err != nil {
						return err
					}
					resp, err = c.Login(ctx, &pb.LoginRequest{
						Username: username,
						Password: password,
						Realm:    realm,
						TotpCode: code,
					})
					if err != nil {
						return fmt.Errorf("2fa stage failed: %w", err)
					}
				}

				if err := cli.SaveCredential(cli.CredentialEntry{
					Token:    resp.Token,
					Username: resp.Username,
					Role:     resp.Role,
				}); err != nil {
					return fmt.Errorf("save credential: %w", err)
				}

				fmt.Printf("Logged in as %s (role: %s)\n", resp.Username, resp.Role)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&realm, "realm", "", "Authentication realm (default: local)")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the server-side session and remove stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Best-effort server-side revoke: keep going even if unreachable
			// so a stale credential can always be cleared. This deliberately
			// tolerates a connect failure, so it does NOT use withClient.
			c, closer, err := cli.Connect(cmd.Context())
			if err == nil {
				_, _ = c.Logout(cmd.Context(), &emptypb.Empty{})
				closer()
			}
			if err := cli.DeleteCredential(); err != nil {
				return err
			}
			fmt.Println("Logged out.")
			return nil
		},
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current authenticated identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			cred, err := cli.LoadCredential()
			if err != nil {
				return err
			}
			if cred == nil {
				fmt.Println("Not logged in (using mTLS client certificate)")
				return nil
			}
			fmt.Printf("%s (role: %s)\n", cred.Username, cred.Role)
			return nil
		},
	}
}
