package main

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// withClient opens a gRPC client to the target litevirtd, runs fn, and always
// closes the connection. It collapses the cli.Connect → error-check →
// defer closer() boilerplate that every subcommand otherwise repeats. The
// connection lifecycle lives in exactly one place, so a future change to how we
// connect (retry, timeout, …) happens here rather than across ~40 commands.
func withClient(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
	c, closer, err := cli.Connect(ctx)
	if err != nil {
		return err
	}
	defer closer()
	return fn(ctx, c)
}
