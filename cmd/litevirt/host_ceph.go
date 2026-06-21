package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/cephdeploy"
)

// newHostCephCmd attaches `lv host ceph …` to the existing host group.
// Like the backup-repo and ct commands, these are host-local — they
// operate on the cephadm/ceph binaries on the host you're SSH'd into.
// The UI dashboard at /ui/storage/ceph drives the same package.
func newHostCephCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ceph",
		Short: "Bootstrap and grow a Ceph cluster from this host (cephadm wrapper)",
	}
	cmd.AddCommand(
		newHostCephInitCmd(),
		newHostCephAddMonCmd(),
		newHostCephAddMgrCmd(),
		newHostCephAddOSDCmd(),
		newHostCephStatusCmd(),
		newHostCephOSDTreeCmd(),
	)
	return cmd
}

func newHostCephInitCmd() *cobra.Command {
	var monIP, network, fsid string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Bootstrap the first MON+MGR (must run on the future MON host)",
		RunE: func(cmd *cobra.Command, args []string) error {
			r := cephdeploy.NewCephadmRunner()
			out, err := r.Bootstrap(cmd.Context(), cephdeploy.CephSpec{
				MonIP: monIP, Network: network, FSID: fsid,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Bootstrap complete. FSID: %s\n", out)
			fmt.Println("\nNext steps:")
			fmt.Println("  - lv host ceph add-mon <host>     # add a 2nd / 3rd MON")
			fmt.Println("  - lv host ceph add-osd <h> <dev>  # add an OSD per spinner")
			return nil
		},
	}
	cmd.Flags().StringVar(&monIP, "mon-ip", "", "Storage-net IP this MON binds to (required)")
	cmd.Flags().StringVar(&network, "network", "", "Storage CIDR (e.g. 10.10.0.0/24)")
	cmd.Flags().StringVar(&fsid, "fsid", "", "Pre-generated cluster UUID (optional)")
	cmd.MarkFlagRequired("mon-ip") //nolint:errcheck
	return cmd
}

func newHostCephAddMonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-mon <host>",
		Short: "Add a MON daemon on the named host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cephdeploy.NewCephadmRunner().AddMon(cmd.Context(), args[0])
		},
	}
}

func newHostCephAddMgrCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-mgr <host>",
		Short: "Add a Mgr daemon on the named host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cephdeploy.NewCephadmRunner().AddMgr(cmd.Context(), args[0])
		},
	}
}

func newHostCephAddOSDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-osd <host> <device>",
		Short: "Add an OSD on host using device (e.g. /dev/sdb)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cephdeploy.NewCephadmRunner().AddOSD(cmd.Context(), args[0], args[1])
		},
	}
}

func newHostCephStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show cluster health, MON / OSD / PG counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := cephdeploy.NewCephadmRunner().Status(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Printf("FSID:        %s\n", s.FSID)
			fmt.Printf("Health:      %s\n", s.Health)
			if s.HealthDetail != "" && s.HealthDetail != s.Health {
				fmt.Printf("  detail:    %s\n", s.HealthDetail)
			}
			fmt.Printf("MONs:        %d\n", s.MonsTotal)
			fmt.Printf("OSDs:        %d total / %d up / %d in\n", s.OSDsTotal, s.OSDsUp, s.OSDsIn)
			fmt.Printf("PGs:         %d\n", s.PGsTotal)
			fmt.Printf("Capacity:    %d used / %d available\n", s.BytesUsed, s.BytesAvail)
			return nil
		},
	}
}

func newHostCephOSDTreeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "osd-tree",
		Short: "Render the CRUSH topology (host → osd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			tree, err := cephdeploy.NewCephadmRunner().OSDTree(cmd.Context())
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tTYPE\tSTATUS\tREWEIGHT")
			for _, n := range tree.Nodes {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%.2f\n", n.ID, n.Name, n.Type, n.Status, n.Reweight)
			}
			return w.Flush()
		},
	}
}
