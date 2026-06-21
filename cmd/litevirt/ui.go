package main

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/cli"
)

func newUICmd() *cobra.Command {
	var open bool

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Show web UI URL and SSH tunnel command",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := cli.LoadClusterConfig()
			if err != nil {
				return err
			}

			sshTarget := cfg.DefaultHost

			uiPort := 7445
			url := fmt.Sprintf("http://127.0.0.1:%d", uiPort)

			fmt.Printf("Web UI: %s\n\n", url)
			fmt.Printf("SSH tunnel command:\n  ssh -L %d:127.0.0.1:%d %s -N\n", uiPort, uiPort, sshTarget)

			if open {
				openBrowser(url)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&open, "open", false, "Attempt to open browser automatically")
	return cmd
}

func openBrowser(url string) {
	var browserCmd string
	switch runtime.GOOS {
	case "linux":
		browserCmd = "xdg-open"
	case "darwin":
		browserCmd = "open"
	default:
		fmt.Printf("Open %s in your browser.\n", url)
		return
	}
	if err := exec.Command(browserCmd, url).Start(); err != nil {
		fmt.Printf("Could not open browser: %v\nOpen %s manually.\n", err, url)
	}
}
