package ui

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"nhooyr.io/websocket"
)

// wsCloseForGRPC closes a WebSocket with a close code and reason derived from a
// gRPC error, so the browser can show *why* a console/VNC session ended instead
// of a bare "disconnected". A nil error closes normally.
func wsCloseForGRPC(ws *websocket.Conn, err error) {
	code, reason := wsCloseCodeReason(err)
	ws.Close(code, reason)
}

// wsCloseCodeReason maps a gRPC error to a WebSocket close code and human
// reason. Split out from wsCloseForGRPC so the mapping is unit-testable. The
// reason is truncated to the RFC 6455 control-frame payload limit (123 bytes).
func wsCloseCodeReason(err error) (websocket.StatusCode, string) {
	if err == nil {
		return websocket.StatusNormalClosure, ""
	}
	code := websocket.StatusInternalError
	reason := err.Error()
	if st, ok := status.FromError(err); ok {
		reason = st.Message()
		switch st.Code() {
		case codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument,
			codes.PermissionDenied, codes.Unauthenticated:
			code = websocket.StatusPolicyViolation
		case codes.Unavailable, codes.DeadlineExceeded:
			code = websocket.StatusTryAgainLater
		}
	}
	if reason == "" {
		reason = "session ended"
	}
	if len(reason) > 123 {
		reason = reason[:123]
	}
	return code, reason
}
