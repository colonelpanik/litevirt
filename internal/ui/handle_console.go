package ui

import (
	"io"
	"log/slog"
	"net/http"

	"google.golang.org/grpc/metadata"
	"nhooyr.io/websocket"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleConsoleModal renders the console modal for a VM.
func (s *Server) handleConsoleModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderFragment(w, "console_modal.html", map[string]any{"VMName": name})
}

// handleConsoleWebSocket bridges a browser WebSocket to the gRPC ConsoleVM
// bidirectional stream, enabling xterm.js terminal access from the web UI.
func (s *Server) handleConsoleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Auth check — WebSocket upgrades don't follow redirects, so return 401.
	if c, err := r.Cookie(sessionCookieName); err != nil || c.Value == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Same-origin by default (empty OriginPatterns); allowlist for proxies.
	// Replaces InsecureSkipVerify which disabled cross-site protection (F5).
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  s.wsOriginPatterns,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		slog.Error("console websocket accept", "error", err)
		return
	}

	vmName := r.PathValue("name")
	ctx := metadata.NewOutgoingContext(s.uiBearerCtx(r), metadata.Pairs("x-vm-name", vmName))

	stream, err := s.grpc.ConsoleVM(ctx)
	if err != nil {
		slog.Error("console open grpc stream", "vm", vmName, "error", err)
		wsCloseForGRPC(ws, err)
		return
	}

	slog.Info("console session started", "vm", vmName)

	errCh := make(chan error, 2)
	inputCh := make(chan []byte, 64)

	// WebSocket reader — reads keystrokes into a buffered channel so a slow
	// gRPC send never blocks the next ws.Read and causes missed keystrokes.
	go func() {
		defer close(inputCh)
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
			inputCh <- data
		}
	}()

	// gRPC sender — drains the input channel, coalescing queued keystrokes
	// into a single gRPC message to reduce framing overhead during fast typing.
	go func() {
		for data := range inputCh {
			// Drain any additional queued messages.
			for {
				select {
				case more, ok := <-inputCh:
					if !ok {
						break
					}
					data = append(data, more...)
					continue
				default:
				}
				break
			}
			if err := stream.Send(&pb.ConsoleInput{Data: data}); err != nil {
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

	// Wait for either direction to finish. Surface the gRPC stream error (if
	// any) as the WS close reason so the terminal can show why it ended.
	err = <-errCh
	slog.Info("console session ended", "vm", vmName, "error", err)
	wsCloseForGRPC(ws, err)
}
