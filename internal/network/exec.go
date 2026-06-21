package network

import (
	"os/exec"
	"strings"
)

// ExecFunc is the type used for all network commands.
type ExecFunc func(name string, args ...string) ([]byte, error)

var defaultExec ExecFunc = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// execCommand is the active executor; replaced in tests.
var execCommand = defaultExec

// DefaultRouteIface returns the interface used by the default route.
// Exported for use by grpcapi when setting up SNAT.
func DefaultRouteIface() string { return defaultRouteInterface() }

// defaultRouteInterface returns the interface used by the default route
// (e.g. "ens18", "eth0"). Returns "" if it cannot be determined.
func defaultRouteInterface() string {
	out, err := execCommand("ip", "route", "show", "default")
	if err != nil {
		return ""
	}
	// Output: "default via X.X.X.X dev ethN..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
