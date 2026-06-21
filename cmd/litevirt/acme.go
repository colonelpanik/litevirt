package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// newACMECmd inspects the TLS cert the web UI is serving (#13). The cert is
// provisioned by the daemon (autocert when acme: is configured, else the
// internal-PKI fallback); this just reports what's actually presented on the
// UI port so an operator can confirm issuance/renewal.
func newACMECmd() *cobra.Command {
	cmd := &cobra.Command{Use: "acme", Short: "Inspect the web UI's TLS certificate (ACME)"}
	cmd.AddCommand(newACMEStatusCmd())
	return cmd
}

func newACMEStatusCmd() *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "status [host]",
		Short: "Show the TLS certificate the UI is serving",
		Long: "Dials the UI's TLS port and prints the served certificate's subject, issuer, " +
			"SANs and expiry. host defaults to $LV_HOST. The UI must be serving TLS " +
			"(acme: configured); a plain-HTTP UI will fail to handshake.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := os.Getenv("LV_HOST")
			if len(args) == 1 {
				host = args[0]
			}
			if host == "" {
				host = "127.0.0.1"
			}
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			dialer := &net.Dialer{Timeout: 8 * time.Second}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspection only
			if err != nil {
				return fmt.Errorf("dial %s: %w (is the UI serving TLS? acme must be configured)", addr, err)
			}
			defer conn.Close()
			st := conn.ConnectionState()
			if len(st.PeerCertificates) == 0 {
				return fmt.Errorf("no certificate presented by %s", addr)
			}
			c := st.PeerCertificates[0]
			fmt.Printf("UI cert at %s\n", addr)
			fmt.Printf("  Subject:   %s\n", c.Subject)
			fmt.Printf("  Issuer:    %s\n", c.Issuer)
			fmt.Printf("  DNS names: %v\n", c.DNSNames)
			fmt.Printf("  Not after: %s (%d days left)\n", c.NotAfter.Format(time.RFC3339), int(time.Until(c.NotAfter).Hours()/24))
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 7445, "UI TLS port")
	return cmd
}
