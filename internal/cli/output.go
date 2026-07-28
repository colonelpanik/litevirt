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
	if err := printJSON(host); err != nil {
		return err
	}
	// Ops-visibility hint (stderr — leaves the JSON on stdout intact): a host whose
	// fence strategy can't PROVE a power-off (anything but IPMI) gives its shared-disk
	// VMs manual-confirm-only automated failover once shared-storage fencing is
	// enforced — a per-host implication that is otherwise invisible until an incident.
	switch host.GetFenceStrategy() {
	case "ipmi":
	default:
		fmt.Fprintf(os.Stderr,
			"note: fence strategy %q cannot prove a power-off; shared-disk VMs on %q require IPMI or `lv host fence-confirm %s` for automated failover under shared-storage fencing\n",
			fenceStrategyOrDefault(host.GetFenceStrategy()), name, name)
	}
	return nil
}

// fenceStrategyOrDefault renders "" as its effective default for the hint.
func fenceStrategyOrDefault(s string) string {
	if s == "" {
		return "best-effort"
	}
	return s
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
