package grpcapi

import (
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// remoteStreamErr must preserve the remote daemon's status code/message (so
// "VM not running" survives the forward hop) and classify transport failures
// as Unavailable with the host name.
func TestRemoteStreamErr(t *testing.T) {
	if err := remoteStreamErr("b", nil); err != nil {
		t.Errorf("nil err → %v, want nil", err)
	}
	if err := remoteStreamErr("b", io.EOF); err != nil {
		t.Errorf("EOF → %v, want nil", err)
	}

	// Remote FailedPrecondition is preserved verbatim, not flattened to Internal.
	in := status.Error(codes.FailedPrecondition, `VM "x" is not running`)
	got := remoteStreamErr("b", in)
	if status.Code(got) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(got))
	}
	if status.Convert(got).Message() != `VM "x" is not running` {
		t.Errorf("message = %q", status.Convert(got).Message())
	}

	// Transport Unavailable is rewritten to mention the host.
	got = remoteStreamErr("b", status.Error(codes.Unavailable, "connection refused"))
	if status.Code(got) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(got))
	}
	if msg := status.Convert(got).Message(); !strings.Contains(msg, "host b unreachable") {
		t.Errorf("message = %q, want host-b context", msg)
	}

	// Non-status (plain) error → Unavailable with host context.
	got = remoteStreamErr("b", errors.New("dial tcp: timeout"))
	if status.Code(got) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(got))
	}
}
