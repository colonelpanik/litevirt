package cli

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// PrintHostInspect prints detailed host info as JSON.
func PrintHostInspect(ctx context.Context, c pb.LiteVirtClient, name string) error {
	host, err := c.InspectHost(ctx, &pb.InspectHostRequest{Name: name})
	if err != nil {
		return fmt.Errorf("inspect host: %w", err)
	}
	return printJSON(host)
}

// PrintVMInspect prints detailed VM info as JSON.
func PrintVMInspect(ctx context.Context, c pb.LiteVirtClient, name string) error {
	vm, err := c.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	if err != nil {
		return fmt.Errorf("inspect VM: %w", err)
	}
	return printJSON(vm)
}

var pjson = protojson.MarshalOptions{
	Multiline:       true,
	Indent:          "  ",
	UseEnumNumbers:  false,
	EmitUnpopulated: false,
}

func printJSON(v proto.Message) error {
	b, err := pjson.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(b, '\n'))
	return err
}

// ReadPassword prompts for a password without echoing input.
func ReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
