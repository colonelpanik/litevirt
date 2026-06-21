package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage active login sessions",
	}
	cmd.AddCommand(newSessionListCmd(), newSessionRevokeCmd())
	return cmd
}

func newSessionListCmd() *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List active sessions (own by default; --user requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListSessions(ctx, &pb.ListSessionsRequest{Username: username})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tUSER\tREALM\tIP\tLAST USED\tEXPIRES")
				for _, s := range resp.Sessions {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
						shortID(s.Id), s.Username, s.Realm, s.Ip, s.LastUsedAt, s.ExpiresAt)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "List sessions for another user (admin only)")
	return cmd
}

func newSessionRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <session-id>",
		Short: "Revoke an active session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RevokeSession(ctx, &pb.RevokeSessionRequest{Id: args[0]}); err != nil {
					return err
				}
				fmt.Printf("Session %s revoked.\n", args[0])
				return nil
			})
		},
	}
}

func newTwoFactorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "2fa",
		Short: "Manage two-factor authentication",
	}
	cmd.AddCommand(new2FAListCmd(), new2FAEnrollCmd(), new2FADisableCmd())
	return cmd
}

func new2FAListCmd() *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List enrolled second factors",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListTwoFactors(ctx, &pb.ListTwoFactorsRequest{Username: username})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "METHOD\tLABEL\tENROLLED\tLAST USED")
				for _, f := range resp.Factors {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Method, f.Label, f.EnrolledAt, f.LastUsedAt)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "List for another user (admin only)")
	return cmd
}

func new2FAEnrollCmd() *cobra.Command {
	var username, label string
	cmd := &cobra.Command{
		Use:   "enroll-totp",
		Short: "Enroll a TOTP authenticator (returns provisioning URL + recovery codes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{
					Username: username, Label: label,
				})
				if err != nil {
					return err
				}
				fmt.Printf("Provisioning URL: %s\n", resp.OtpauthUrl)
				fmt.Printf("Manual secret:    %s\n", resp.SecretBase32)
				fmt.Println("\nRecovery codes (each usable once — save them now):")
				for _, code := range resp.RecoveryCodes {
					fmt.Printf("  %s\n", code)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "Enroll for another user (admin only); empty = self")
	cmd.Flags().StringVar(&label, "label", "", "Label for this factor (e.g. phone, yubikey)")
	return cmd
}

func new2FADisableCmd() *cobra.Command {
	var username, method, label string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable an enrolled second factor",
		RunE: func(cmd *cobra.Command, args []string) error {
			if method == "" {
				return fmt.Errorf("--method is required (totp or webauthn)")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DisableTwoFactor(ctx, &pb.DisableTwoFactorRequest{
					Username: username, Method: method, Label: label,
				}); err != nil {
					return err
				}
				fmt.Println("Second factor disabled.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "Disable for another user (admin only); empty = self")
	cmd.Flags().StringVar(&method, "method", "", "totp | webauthn")
	cmd.Flags().StringVar(&label, "label", "", "Specific factor label (matches the enrolment label)")
	return cmd
}

// shortID truncates session IDs for table output. Full id is required to
// revoke, but the short form is enough to recognise.
func shortID(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
