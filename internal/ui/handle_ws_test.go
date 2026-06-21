package ui

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"nhooyr.io/websocket"
)

func TestWSCloseCodeReason(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   websocket.StatusCode
		wantReason string
	}{
		{"nil", nil, websocket.StatusNormalClosure, ""},
		{"not running", status.Error(codes.FailedPrecondition, `VM "x" is not running`),
			websocket.StatusPolicyViolation, `VM "x" is not running`},
		{"vnc disabled", status.Error(codes.FailedPrecondition, `VNC is not enabled for VM "x"`),
			websocket.StatusPolicyViolation, `VNC is not enabled for VM "x"`},
		{"not found", status.Error(codes.NotFound, `VM "x" not found`),
			websocket.StatusPolicyViolation, `VM "x" not found`},
		{"host unreachable", status.Error(codes.Unavailable, "host b unreachable: connection refused"),
			websocket.StatusTryAgainLater, "host b unreachable: connection refused"},
		{"plain error", errors.New("boom"), websocket.StatusInternalError, "boom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, reason := wsCloseCodeReason(c.err)
			if code != c.wantCode {
				t.Errorf("code = %v, want %v", code, c.wantCode)
			}
			if reason != c.wantReason {
				t.Errorf("reason = %q, want %q", reason, c.wantReason)
			}
		})
	}
}

func TestWSCloseReasonTruncated(t *testing.T) {
	long := strings.Repeat("x", 300)
	_, reason := wsCloseCodeReason(status.Error(codes.Internal, long))
	if len(reason) > 123 {
		t.Errorf("reason length = %d, want <= 123", len(reason))
	}
}
