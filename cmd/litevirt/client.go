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
//
// It is a var, not a func, so a test can substitute a client and drive a whole
// command — flag registration, parsing, and request assembly — instead of
// asserting on a flag's existence and hoping it is plumbed through. A flag that
// parses correctly and is never copied into the request is the failure worth
// catching, and it is invisible to a flags-only test.
var withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
	c, closer, err := cli.Connect(ctx)
	if err != nil {
		return err
	}
	defer closer()
	return fn(ctx, c)
}
