package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Manage VM images",
	}
	cmd.AddCommand(
		newImagePullCmd(),
		newImageLsCmd(),
		newImageImportCmd(),
		newImageRmCmd(),
		newImagePushCmd(),
		newImageBuildCmd(),
	)
	return cmd
}

func newImagePullCmd() *cobra.Command {
	var (
		name     string
		format   string
		checksum string
	)
	cmd := &cobra.Command{
		Use:   "pull <url>",
		Short: "Pull an image from a URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.PullImage(ctx, &pb.PullImageRequest{
					Name:      name,
					SourceUrl: args[0],
					Format:    format,
					Checksum:  checksum,
				})
				if err != nil {
					return fmt.Errorf("pull image: %w", err)
				}

				for {
					progress, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						fmt.Println()
						return err
					}
					fmt.Printf("\r  %s: %.0f%% %s", progress.HostName, progress.ProgressPct, progress.Status)
				}
				fmt.Println()
				fmt.Printf("Image %s pulled successfully\n", name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Image name (required)")
	cmd.Flags().StringVar(&format, "format", "qcow2", "Image format")
	cmd.Flags().StringVar(&checksum, "checksum", "", "Expected checksum (sha256:...)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newImageLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List images",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListImages(ctx, nil)
				if err != nil {
					return fmt.Errorf("list images: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tFORMAT\tSIZE\tHOSTS\n")
				for _, img := range resp.Images {
					fmt.Fprintf(w, "%s\t%s\t%s\t%v\n",
						img.Name, img.Format,
						formatBytes(img.SizeBytes), img.Hosts,
					)
				}
				return w.Flush()
			})
		},
	}
}

func newImageImportCmd() *cobra.Command {
	var (
		name     string
		format   string
		checksum string
	)
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import a local image file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				f, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()

				info, err := f.Stat()
				if err != nil {
					return fmt.Errorf("stat file: %w", err)
				}

				stream, err := c.ImportImage(ctx)
				if err != nil {
					return fmt.Errorf("import: %w", err)
				}

				// Stream in 256 KiB chunks.
				buf := make([]byte, 256*1024)
				var sent int64
				first := true

				for {
					n, readErr := f.Read(buf)
					if n > 0 {
						msg := &pb.ImportImageRequest{Chunk: buf[:n]}
						if first {
							msg.Name = name
							msg.Format = format
							msg.Checksum = checksum
							first = false
						}
						if err := stream.Send(msg); err != nil {
							return fmt.Errorf("send chunk: %w", err)
						}
						sent += int64(n)
						pct := float64(sent) / float64(info.Size()) * 100
						fmt.Printf("\r  importing: %.0f%%", pct)
					}
					if readErr == io.EOF {
						break
					}
					if readErr != nil {
						return fmt.Errorf("read: %w", readErr)
					}
				}

				resp, err := stream.CloseAndRecv()
				if err != nil {
					return fmt.Errorf("import: %w", err)
				}
				fmt.Printf("\nImage %s imported (%s, checksum %s)\n",
					resp.Name, formatBytes(resp.SizeBytes), resp.Checksum)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Image name (required)")
	cmd.Flags().StringVar(&format, "format", "qcow2", "Image format")
	cmd.Flags().StringVar(&checksum, "checksum", "", "Expected checksum (sha256:...)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newImageRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <image>",
		Short: "Delete an image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteImage(ctx, &pb.DeleteImageRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("delete image: %w", err)
				}
				fmt.Printf("Image %s deleted\n", args[0])
				return nil
			})
		},
	}
}

func newImagePushCmd() *cobra.Command {
	var targetHost string
	cmd := &cobra.Command{
		Use:   "push <image>",
		Short: "Push an image to another host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.PushImage(ctx, &pb.PushImageRequest{
					Name:       args[0],
					TargetHost: targetHost,
				})
				if err != nil {
					return fmt.Errorf("push: %w", err)
				}

				for {
					progress, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						fmt.Println()
						return err
					}
					fmt.Printf("\r  %s: %.0f%%", progress.Status, progress.ProgressPct)
				}
				fmt.Println()
				fmt.Printf("Image %s pushed to %s\n", args[0], targetHost)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&targetHost, "to", "", "Target host (required)")
	cmd.MarkFlagRequired("to")
	return cmd
}

func newImageBuildCmd() *cobra.Command {
	var imageName string
	cmd := &cobra.Command{
		Use:   "build <vm>",
		Short: "Build an image from a running VM",
		Long:  "Snapshots the VM's root disk into a flattened golden image.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				fmt.Printf("Building image from VM %s...\n", args[0])
				resp, err := c.BuildImage(ctx, &pb.BuildImageRequest{
					VmName:    args[0],
					ImageName: imageName,
				})
				if err != nil {
					return fmt.Errorf("build: %w", err)
				}
				fmt.Printf("Image %s built (%s)\n", resp.Name, formatBytes(resp.SizeBytes))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&imageName, "name", "", "Image name (required)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
