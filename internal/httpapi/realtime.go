package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var websocketUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// Native clients do not send browser origins. Browser clients must be explicitly added later.
		return r.Header.Get("Origin") == ""
	},
}

func (s *Server) realtime(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFrom(r.Context())
	if !ok {
		writeDomainError(w, domain.ErrUnauthenticated)
		return
	}
	guard := s.realtimeRevocations().Register(id)
	defer s.realtimeRevocations().Unregister(guard)
	owner, err := s.bus.RegisterSessionOwner(r.Context(), id.UserID, id.SessionID, func(sessionID *uuid.UUID) {
		s.realtimeRevocations().Revoke(id.UserID, sessionID)
	})
	if err != nil {
		guard.Revoke()
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "Realtime delivery is unavailable.")
		return
	}
	defer owner.Close()
	guard.SetLeaseValidator(owner.Valid)
	// This durable check occurs after owner registration. A revocation racing
	// registration therefore either fences us through the barrier or is observed
	// here before the socket can send any application data.
	if !s.realtimeSessionActive(r.Context(), id, guard) {
		writeDomainError(w, domain.ErrUnauthenticated)
		return
	}
	connection, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	observability.WebsocketConnections.Inc()
	defer observability.WebsocketConnections.Dec()
	_ = s.presence.Online(r.Context(), id.UserID, id.DeviceID)
	defer s.presence.Offline(context.Background(), id.UserID, id.DeviceID)

	subscription, err := s.bus.Subscribe(r.Context(), id.UserID)
	if err != nil {
		_ = connection.WriteJSON(errorResponse{Error: errorBody{Code: "unavailable", Message: "Realtime delivery is unavailable."}})
		return
	}
	defer subscription.Close()

	connection.SetReadLimit(16 << 10)
	_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = connection.SetReadDeadline(time.Now().Add(70 * time.Second))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(70 * time.Second))
	})

	hello, _ := json.Marshal(map[string]any{
		"user_id": id.UserID, "device_id": id.DeviceID, "heartbeat_seconds": 25,
	})
	wrote, err := guard.WhileActive(func() error {
		return connection.WriteJSON(domain.RealtimeEvent{
			ID: uuid.NewString(), Type: "session.ready", Payload: hello, OccurredAt: time.Now().UTC(),
		})
	})
	if err != nil || !wrote {
		return
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		var lastTypingEvent time.Time
		for {
			if guard.IsRevoked() {
				return
			}
			var frame struct {
				Type           string     `json:"type"`
				ConversationID *uuid.UUID `json:"conversation_id,omitempty"`
				Active         bool       `json:"active,omitempty"`
			}
			if err := connection.ReadJSON(&frame); err != nil {
				return
			}
			if frame.Type == "ping" {
				_, _ = guard.WhileActive(func() error {
					return connection.WriteControl(websocket.PongMessage, nil, time.Now().Add(5*time.Second))
				})
			} else if frame.Type == "typing" && frame.ConversationID != nil {
				now := time.Now()
				if !typingFrameDue(now, &lastTypingEvent) {
					continue
				}
				// The cheap per-connection gate precedes the durable lookup, bounding
				// an authenticated typing flood to at most one query per interval.
				if !s.realtimeSessionActive(r.Context(), id, guard) {
					return
				}
				published, _ := guard.WhileActive(func() error {
					actionContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
					defer cancel()
					members, memberErr := s.store.ListConversationMembers(
						actionContext, *frame.ConversationID, id.UserID,
					)
					if memberErr != nil {
						return nil
					}
					recipients := make([]uuid.UUID, 0, len(members))
					for _, member := range members {
						if member.UserID != id.UserID {
							recipients = append(recipients, member.UserID)
						}
					}
					payload, _ := json.Marshal(map[string]any{
						"user_id": id.UserID, "device_id": id.DeviceID, "active": frame.Active,
					})
					return s.bus.Publish(actionContext, recipients, domain.RealtimeEvent{
						ID: uuid.NewString(), Type: "typing.changed", ConversationID: frame.ConversationID,
						Payload: payload, OccurredAt: time.Now().UTC(),
					})
				})
				if !published {
					return
				}
			}
		}
	}()

	recheckInterval := s.realtimeSessionRecheck
	if recheckInterval <= 0 {
		recheckInterval = realtimeDurableSessionRecheckInterval
	}
	sessionTicker := time.NewTicker(recheckInterval)
	defer sessionTicker.Stop()
	heartbeatTicker := time.NewTicker(25 * time.Second)
	defer heartbeatTicker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-guard.Revoked():
			s.closeRealtimeSession(connection)
			return
		case <-readDone:
			return
		case <-sessionTicker.C:
			// This fail-closed durable fallback bounds a dropped cross-process
			// revocation signal to five seconds without a query per fanout event.
			if !s.realtimeSessionActive(r.Context(), id, guard) {
				s.closeRealtimeSession(connection)
				return
			}
		case <-heartbeatTicker.C:
			_ = s.presence.Heartbeat(r.Context(), id.UserID, id.DeviceID)
			wrote, err := guard.WhileActive(func() error {
				return connection.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			})
			if err != nil || !wrote {
				return
			}
		case event, open := <-subscription.Events():
			if !open {
				return
			}
			if event.Type == sessionRevokedEventType {
				s.applySessionRevocation(id.UserID, event.Payload)
				continue
			}
			_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
			wrote, err := guard.WhileActive(func() error { return connection.WriteJSON(event) })
			if err != nil || !wrote {
				return
			}
		}
	}
}

func typingFrameDue(now time.Time, last *time.Time) bool {
	if !last.IsZero() && now.Sub(*last) < 300*time.Millisecond {
		return false
	}
	*last = now
	return true
}

func (s *Server) realtimeSessionActive(
	ctx context.Context,
	id identity,
	guard *realtimeSessionGuard,
) bool {
	active, err := s.store.SessionActive(ctx, id.SessionID, id.UserID, id.DeviceID)
	if err != nil {
		s.logger.Error("realtime_session_check_failed", "error", err)
		guard.Revoke()
		return false
	}
	if !active {
		s.realtimeRevocations().Revoke(id.UserID, &id.SessionID)
		return false
	}
	return !guard.IsRevoked()
}

func (s *Server) closeRealtimeSession(connection *websocket.Conn) {
	_ = connection.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "session revoked"),
		time.Now().Add(5*time.Second),
	)
}
