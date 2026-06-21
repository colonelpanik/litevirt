package ui

import (
	"io"
	"log/slog"
	"net/http"

	"google.golang.org/grpc/metadata"
	"nhooyr.io/websocket"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleVNCPage renders the full-screen VNC viewer page for a VM.
func (s *Server) handleVNCPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderFragment(w, "vnc.html", map[string]any{"VMName": name})
}

// handleVNCModal renders the in-app VNC console modal (parallel to the terminal
// console modal) so VNC opens inline with connecting/retry states instead of a
// bare new tab.
func (s *Server) handleVNCModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderFragment(w, "vnc_modal.html", map[string]any{"VMName": name})
}

// handleVNCWebSocket bridges a browser WebSocket to the gRPC ProxyVNC
// bidirectional stream, allowing noVNC or similar clients to connect.
func (s *Server) handleVNCWebSocket(w http.ResponseWriter, r *http.Request) {
	// Auth check — WebSocket upgrades don't follow redirects, so return 401.
	if c, err := r.Cookie(sessionCookieName); err != nil || c.Value == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Enforce same-origin by default (empty OriginPatterns); an operator-set
	// allowlist covers reverse-proxy setups. Replaces InsecureSkipVerify, which
	// disabled the Origin check entirely and allowed cross-site WS hijack (F5).
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: s.wsOriginPatterns,
	})
	if err != nil {
		slog.Error("vnc websocket accept", "error", err)
		return
	}

	vmName := r.PathValue("name")
	ctx := metadata.NewOutgoingContext(s.uiBearerCtx(r), metadata.Pairs("x-vm-name", vmName))

	stream, err := s.grpc.ProxyVNC(ctx)
	if err != nil {
		slog.Error("vnc open grpc stream", "vm", vmName, "error", err)
		wsCloseForGRPC(ws, err)
		return
	}

	slog.Info("vnc session started", "vm", vmName)

	errCh := make(chan error, 2)

	// WebSocket → gRPC
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
			if err := stream.Send(&pb.VNCData{Data: data}); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// gRPC → WebSocket
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					errCh <- err
				} else {
					errCh <- nil
				}
				return
			}
			if err := ws.Write(ctx, websocket.MessageBinary, msg.Data); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Wait for either direction to finish. The gRPC stream error (if any)
	// carries the daemon's status — surface it as the WS close reason so the
	// viewer can show why instead of a bare "Disconnected".
	err = <-errCh
	slog.Info("vnc session ended", "vm", vmName, "error", err)
	wsCloseForGRPC(ws, err)
}
