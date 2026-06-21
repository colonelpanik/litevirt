package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// newRegistryCmd manages OCI/Docker registry credentials (v23) used to
// authenticate private image pulls (`lv ct pull`). Credentials are per-user by
// default; --global stores a cluster-wide credential (operator-only).
func newRegistryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Manage registry credentials for private OCI image pulls",
	}
	cmd.AddCommand(newRegistryAddCmd(), newRegistryLsCmd(), newRegistryRmCmd())
	return cmd
}

// readRegistryPassword resolves the password per the documented precedence:
// --password-stdin (read one line, piped) > --password (argv-visible) >
// interactive no-echo prompt.
func readRegistryPassword(password string, fromStdin bool) (string, error) {
	if fromStdin {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if password != "" {
		return password, nil
	}
	return cli.ReadPassword("Registry password: ")
}

func newRegistryAddCmd() *cobra.Command {
	var username, password string
	var passwordStdin, global bool
	cmd := &cobra.Command{
		Use:   "add <registry>",
		Short: "Store a registry credential (default: per-user; --global for cluster-wide)",
		Long: "Store a registry login used to authenticate private OCI image pulls.\n" +
			"The registry is a host such as docker.io, ghcr.io, or registry.example.com:5000.\n" +
			"Prefer --password-stdin (e.g. `echo $TOKEN | lv registry add ghcr.io -u me --password-stdin`)\n" +
			"so the secret never lands in your shell history or the process arg list.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if username == "" {
				return fmt.Errorf("--username is required")
			}
			pw, err := readRegistryPassword(password, passwordStdin)
			if err != nil {
				return err
			}
			if pw == "" {
				return fmt.Errorf("a password/token is required")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				rc, err := c.SetRegistryCredential(ctx, &pb.SetRegistryCredentialRequest{
					Global: global, Registry: args[0], Username: username, Password: pw,
				})
				if err != nil {
					return fmt.Errorf("add registry credential: %w", err)
				}
				fmt.Printf("Stored %s credential for %s (user %q)\n", rc.Scope, rc.Registry, rc.Username)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "registry username (required)")
	cmd.Flags().StringVar(&password, "password", "", "registry password/token (visible in argv/history — prefer --password-stdin)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the password/token from stdin")
	cmd.Flags().BoolVar(&global, "global", false, "store a cluster-wide credential (operator-only)")
	return cmd
}

func newRegistryLsCmd() *cobra.Command {
	var global, all bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List registry credentials (your own + global; --all for every user, --global for global only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListRegistryCredentials(ctx, &pb.ListRegistryCredentialsRequest{All: all, Global: global})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "SCOPE\tOWNER\tREGISTRY\tUSERNAME\tUPDATED\n")
				for _, rc := range resp.Credentials {
					owner := rc.Owner
					if owner == "" {
						owner = "-"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", rc.Scope, owner, rc.Registry, rc.Username, rc.UpdatedAt)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().BoolVar(&global, "global", false, "list global credentials only")
	cmd.Flags().BoolVar(&all, "all", false, "list every user's credentials + global (operator-only)")
	return cmd
}

func newRegistryRmCmd() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "rm <registry>",
		Short: "Remove a registry credential (default: your own; --global for cluster-wide)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteRegistryCredential(ctx, &pb.DeleteRegistryCredentialRequest{
					Global: global, Registry: args[0],
				}); err != nil {
					return err
				}
				fmt.Printf("Removed credential for %s\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&global, "global", false, "remove the cluster-wide credential (operator-only)")
	return cmd
}
